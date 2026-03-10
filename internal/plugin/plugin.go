// Package plugin provides a tiered plugin system for Gatekeeper.
//
// Plugins are classified into three tiers:
//
//   - Passive: read-only diagnostics, extra UI pages, extra diagnostic endpoints.
//   - Managed: Gatekeeper-owned adapters to specific external services
//     (Suricata, Squid, FRR, HAProxy).
//   - Unsafe: disabled by default, explicit warning, no core support guarantees.
//
// V1 plugins support only:
//   - Extra UI pages (serve static/template content)
//   - Extra diagnostic endpoints (read-only HTTP handlers)
//   - Post-commit notifications (webhook hooks)
//
// Plugins may NOT hook into the policy compiler or apply pipeline.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tier classifies a plugin's trust level and capabilities.
type Tier string

const (
	// TierPassive allows read-only diagnostics and extra UI pages.
	TierPassive Tier = "passive"
	// TierManaged allows Gatekeeper-owned adapters to external services.
	TierManaged Tier = "managed"
	// TierUnsafe requires explicit opt-in and carries no core support guarantees.
	TierUnsafe Tier = "unsafe"
)

// scriptTimeout is the maximum duration a diagnostic script may run.
const scriptTimeout = 30 * time.Second

// webhookTimeout is the maximum duration for an outbound webhook request.
const webhookTimeout = 10 * time.Second

// manifestFile is the expected filename for a plugin manifest.
const manifestFile = "manifest.json"

// Manifest describes a plugin's metadata and declared capabilities.
// It is loaded from a manifest.json file in the plugin directory.
type Manifest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author"`
	Tier        string `json:"tier"`                  // "passive", "managed", "unsafe"
	Signature   string `json:"signature,omitempty"`    // future: code signing

	// Capabilities — V1 only supports these three.
	DiagEndpoints []DiagEndpoint `json:"diag_endpoints,omitempty"`
	UIPages       []UIPage       `json:"ui_pages,omitempty"`
	Webhooks      []Webhook      `json:"webhooks,omitempty"`
}

// DiagEndpoint declares a read-only diagnostic HTTP endpoint provided by a
// plugin. The handler is a shell script executed with a timeout and reduced
// privileges when possible.
type DiagEndpoint struct {
	Name        string `json:"name"`
	Path        string `json:"path"`        // URL path, e.g. "/diag/myplugin/status"
	Description string `json:"description"`
	Script      string `json:"script"`      // path relative to the plugin directory
}

// UIPage declares a template-based UI page served by the plugin.
type UIPage struct {
	Name     string `json:"name"`
	Path     string `json:"path"`     // URL path, e.g. "/ui/myplugin/dashboard"
	Template string `json:"template"` // template file relative to the plugin directory
}

// Webhook declares a notification hook that fires on specific events.
type Webhook struct {
	Event   string            `json:"event"`   // e.g. "post-commit", "post-rollback", "service-state-change"
	URL     string            `json:"url"`
	Method  string            `json:"method"`  // HTTP method, defaults to POST
	Headers map[string]string `json:"headers,omitempty"`
}

// PluginInfo is the public view of a loaded plugin's state.
type PluginInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author"`
	Tier        string `json:"tier"`
	Enabled     bool   `json:"enabled"`
	Dir         string `json:"dir"`
}

// plugin is the internal bookkeeping for a loaded plugin.
type plugin struct {
	manifest Manifest
	dir      string
	enabled  bool
}

// Manager loads, validates, and manages the lifecycle of plugins.
type Manager struct {
	mu               sync.Mutex
	plugins          map[string]*plugin // keyed by manifest name
	allowUnsafe      bool
	logger           *slog.Logger
	httpClient       *http.Client
}

// NewManager creates a Manager. Set allowUnsafe to true to permit loading of
// unsafe-tier plugins (requires explicit opt-in via configuration).
func NewManager(logger *slog.Logger, allowUnsafe bool) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		plugins:     make(map[string]*plugin),
		allowUnsafe: allowUnsafe,
		logger:      logger,
		httpClient: &http.Client{
			Timeout: webhookTimeout,
		},
	}
}

// LoadPlugins scans dir for subdirectories containing a manifest.json file,
// validates each manifest, and registers the plugin. Plugins that fail
// validation are logged and skipped rather than aborting the entire load.
func (m *Manager) LoadPlugins(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("plugin: read directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginDir := filepath.Join(dir, entry.Name())
		mfPath := filepath.Join(pluginDir, manifestFile)

		data, err := os.ReadFile(mfPath)
		if err != nil {
			m.logger.Debug("skipping directory without manifest",
				"dir", pluginDir, "error", err)
			continue
		}

		var mf Manifest
		if err := json.Unmarshal(data, &mf); err != nil {
			m.logger.Warn("invalid plugin manifest",
				"path", mfPath, "error", err)
			continue
		}

		if err := m.validateManifest(&mf, pluginDir); err != nil {
			m.logger.Warn("plugin manifest rejected",
				"plugin", mf.Name, "error", err)
			continue
		}

		// Passive and managed plugins start enabled; unsafe starts disabled.
		enabled := Tier(mf.Tier) != TierUnsafe

		m.plugins[mf.Name] = &plugin{
			manifest: mf,
			dir:      pluginDir,
			enabled:  enabled,
		}

		m.logger.Info("plugin loaded",
			"plugin", mf.Name,
			"version", mf.Version,
			"tier", mf.Tier,
			"enabled", enabled)
	}

	return nil
}

// validateManifest checks that a manifest is well-formed and allowed.
func (m *Manager) validateManifest(mf *Manifest, pluginDir string) error {
	if mf.Name == "" {
		return fmt.Errorf("manifest missing required field: name")
	}
	if mf.Version == "" {
		return fmt.Errorf("manifest missing required field: version")
	}

	tier := Tier(mf.Tier)
	switch tier {
	case TierPassive, TierManaged, TierUnsafe:
		// ok
	default:
		return fmt.Errorf("unknown tier %q; must be passive, managed, or unsafe", mf.Tier)
	}

	if tier == TierUnsafe && !m.allowUnsafe {
		return fmt.Errorf("unsafe plugin %q rejected: allow_unsafe_plugins is not enabled", mf.Name)
	}

	if _, exists := m.plugins[mf.Name]; exists {
		return fmt.Errorf("duplicate plugin name %q", mf.Name)
	}

	// Validate diagnostic endpoint paths and scripts.
	for i, ep := range mf.DiagEndpoints {
		if ep.Path == "" {
			return fmt.Errorf("diag_endpoints[%d]: path is required", i)
		}
		if !strings.HasPrefix(ep.Path, "/") {
			return fmt.Errorf("diag_endpoints[%d]: path must start with /", i)
		}
		if ep.Script == "" {
			return fmt.Errorf("diag_endpoints[%d]: script is required", i)
		}
		// Script must exist and reside within the plugin directory.
		scriptPath := filepath.Join(pluginDir, ep.Script)
		resolved, err := filepath.EvalSymlinks(scriptPath)
		if err != nil {
			return fmt.Errorf("diag_endpoints[%d]: script %q: %w", i, ep.Script, err)
		}
		if !strings.HasPrefix(resolved, pluginDir) {
			return fmt.Errorf("diag_endpoints[%d]: script %q escapes plugin directory", i, ep.Script)
		}
	}

	// Validate UI page paths and templates.
	for i, page := range mf.UIPages {
		if page.Path == "" {
			return fmt.Errorf("ui_pages[%d]: path is required", i)
		}
		if !strings.HasPrefix(page.Path, "/") {
			return fmt.Errorf("ui_pages[%d]: path must start with /", i)
		}
		if page.Template == "" {
			return fmt.Errorf("ui_pages[%d]: template is required", i)
		}
		tmplPath := filepath.Join(pluginDir, page.Template)
		resolved, err := filepath.EvalSymlinks(tmplPath)
		if err != nil {
			return fmt.Errorf("ui_pages[%d]: template %q: %w", i, page.Template, err)
		}
		if !strings.HasPrefix(resolved, pluginDir) {
			return fmt.Errorf("ui_pages[%d]: template %q escapes plugin directory", i, page.Template)
		}
	}

	// Validate webhook declarations.
	for i, wh := range mf.Webhooks {
		if wh.Event == "" {
			return fmt.Errorf("webhooks[%d]: event is required", i)
		}
		if wh.URL == "" {
			return fmt.Errorf("webhooks[%d]: url is required", i)
		}
		method := strings.ToUpper(wh.Method)
		if method == "" {
			method = http.MethodPost
		}
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			// ok
		default:
			return fmt.Errorf("webhooks[%d]: unsupported method %q", i, wh.Method)
		}
	}

	return nil
}

// EnablePlugin enables a previously loaded plugin by name.
func (m *Manager) EnablePlugin(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.plugins[name]
	if !ok {
		return fmt.Errorf("plugin: %q not found", name)
	}
	if Tier(p.manifest.Tier) == TierUnsafe && !m.allowUnsafe {
		return fmt.Errorf("plugin: cannot enable unsafe plugin %q without allow_unsafe_plugins", name)
	}
	if p.enabled {
		return nil
	}
	p.enabled = true
	m.logger.Info("plugin enabled", "plugin", name)
	return nil
}

// DisablePlugin disables a loaded plugin by name. Disabled plugins do not
// serve routes or fire webhooks.
func (m *Manager) DisablePlugin(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.plugins[name]
	if !ok {
		return fmt.Errorf("plugin: %q not found", name)
	}
	if !p.enabled {
		return nil
	}
	p.enabled = false
	m.logger.Info("plugin disabled", "plugin", name)
	return nil
}

// ListPlugins returns information about all loaded plugins.
func (m *Manager) ListPlugins() []PluginInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	infos := make([]PluginInfo, 0, len(m.plugins))
	for _, p := range m.plugins {
		infos = append(infos, PluginInfo{
			Name:        p.manifest.Name,
			Version:     p.manifest.Version,
			Description: p.manifest.Description,
			Author:      p.manifest.Author,
			Tier:        p.manifest.Tier,
			Enabled:     p.enabled,
			Dir:         p.dir,
		})
	}
	return infos
}

// GetRoutes returns a map of URL path to http.Handler for all enabled plugins'
// diagnostic endpoints and UI pages.
func (m *Manager) GetRoutes() map[string]http.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()

	routes := make(map[string]http.Handler)

	for _, p := range m.plugins {
		if !p.enabled {
			continue
		}

		for _, ep := range p.manifest.DiagEndpoints {
			scriptAbs := filepath.Join(p.dir, ep.Script)
			pluginName := p.manifest.Name
			epName := ep.Name
			routes[ep.Path] = m.diagHandler(pluginName, epName, scriptAbs)
		}

		for _, page := range p.manifest.UIPages {
			tmplAbs := filepath.Join(p.dir, page.Template)
			pluginName := p.manifest.Name
			pageName := page.Name
			routes[page.Path] = m.uiHandler(pluginName, pageName, tmplAbs)
		}
	}

	return routes
}

// diagHandler returns an http.Handler that executes a diagnostic script and
// writes its stdout as the response body. The script is run with a timeout.
func (m *Manager) diagHandler(pluginName, epName, scriptPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "diagnostic endpoints are read-only", http.StatusMethodNotAllowed)
			return
		}

		m.logger.Info("executing diagnostic endpoint",
			"plugin", pluginName,
			"endpoint", epName,
			"script", scriptPath)

		ctx, cancel := context.WithTimeout(r.Context(), scriptTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", scriptPath)
		cmd.Dir = filepath.Dir(scriptPath)

		// Minimal environment to reduce information leakage.
		cmd.Env = []string{
			"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
			"HOME=/tmp",
			"LANG=C.UTF-8",
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			m.logger.Warn("diagnostic script timed out",
				"plugin", pluginName,
				"endpoint", epName)
			http.Error(w, "diagnostic script timed out", http.StatusGatewayTimeout)
			return
		}
		if err != nil {
			m.logger.Warn("diagnostic script failed",
				"plugin", pluginName,
				"endpoint", epName,
				"error", err,
				"stderr", stderr.String())
			http.Error(w, "diagnostic script error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, &stdout)
	})
}

// uiHandler returns an http.Handler that serves a static template file.
func (m *Manager) uiHandler(pluginName, pageName, tmplPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "UI pages are read-only", http.StatusMethodNotAllowed)
			return
		}

		m.logger.Info("serving UI page",
			"plugin", pluginName,
			"page", pageName,
			"template", tmplPath)

		data, err := os.ReadFile(tmplPath)
		if err != nil {
			m.logger.Warn("failed to read UI template",
				"plugin", pluginName,
				"page", pageName,
				"error", err)
			http.Error(w, "template not found", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

// NotifyEvent fires webhooks for all enabled plugins that have registered for
// the given event. Webhooks are dispatched concurrently; failures are logged
// but do not block the caller.
func (m *Manager) NotifyEvent(event string, payload any) {
	m.mu.Lock()

	type target struct {
		pluginName string
		webhook    Webhook
	}
	var targets []target

	for _, p := range m.plugins {
		if !p.enabled {
			continue
		}
		for _, wh := range p.manifest.Webhooks {
			if wh.Event == event {
				targets = append(targets, target{
					pluginName: p.manifest.Name,
					webhook:    wh,
				})
			}
		}
	}

	m.mu.Unlock()

	if len(targets) == 0 {
		return
	}

	body, err := json.Marshal(map[string]any{
		"event":     event,
		"payload":   payload,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		m.logger.Error("failed to marshal webhook payload",
			"event", event, "error", err)
		return
	}

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			m.fireWebhook(t.pluginName, t.webhook, body)
		}(t)
	}
	wg.Wait()
}

// fireWebhook sends a single webhook request and logs the outcome.
func (m *Manager) fireWebhook(pluginName string, wh Webhook, body []byte) {
	method := strings.ToUpper(wh.Method)
	if method == "" {
		method = http.MethodPost
	}

	m.logger.Info("firing webhook",
		"plugin", pluginName,
		"event", wh.Event,
		"url", wh.URL,
		"method", method)

	req, err := http.NewRequest(method, wh.URL, bytes.NewReader(body))
	if err != nil {
		m.logger.Error("failed to create webhook request",
			"plugin", pluginName,
			"event", wh.Event,
			"error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Gatekeeper-Plugin/1.0")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.logger.Warn("webhook request failed",
			"plugin", pluginName,
			"event", wh.Event,
			"url", wh.URL,
			"error", err)
		return
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		m.logger.Warn("webhook returned error status",
			"plugin", pluginName,
			"event", wh.Event,
			"url", wh.URL,
			"status", resp.StatusCode)
		return
	}

	m.logger.Info("webhook delivered",
		"plugin", pluginName,
		"event", wh.Event,
		"url", wh.URL,
		"status", resp.StatusCode)
}
