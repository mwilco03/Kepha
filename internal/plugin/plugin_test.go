package plugin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestLogger returns a silent logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// writeManifest creates a plugin subdirectory with a manifest.json inside dir.
// It returns the path to the plugin subdirectory.
func writeManifest(t *testing.T, dir, subdir string, mf Manifest) string {
	t.Helper()
	pluginDir := filepath.Join(dir, subdir)
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return pluginDir
}

func TestNewManager(t *testing.T) {
	m := NewManager(newTestLogger(), false)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.plugins == nil {
		t.Fatal("plugins map is nil")
	}
	if m.allowUnsafe {
		t.Fatal("allowUnsafe should be false")
	}
}

func TestNewManagerNilLogger(t *testing.T) {
	m := NewManager(nil, true)
	if m == nil {
		t.Fatal("NewManager returned nil with nil logger")
	}
	if m.logger == nil {
		t.Fatal("logger should default when nil is passed")
	}
	if !m.allowUnsafe {
		t.Fatal("allowUnsafe should be true")
	}
}

func TestLoadPluginsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins on empty dir: %v", err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(m.ListPlugins()))
	}
}

func TestLoadPluginsNonexistentDir(t *testing.T) {
	m := NewManager(newTestLogger(), false)
	err := m.LoadPlugins("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestLoadPluginsValidManifest(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "myplugin", Manifest{
		Name:    "myplugin",
		Version: "1.0.0",
		Author:  "tester",
		Tier:    "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	plugins := m.ListPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Name != "myplugin" {
		t.Errorf("expected name myplugin, got %s", plugins[0].Name)
	}
	if plugins[0].Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", plugins[0].Version)
	}
	if plugins[0].Tier != "passive" {
		t.Errorf("expected tier passive, got %s", plugins[0].Tier)
	}
	if !plugins[0].Enabled {
		t.Error("passive plugin should start enabled")
	}
}

func TestLoadPluginsManagedStartsEnabled(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "managed-plug", Manifest{
		Name:    "managed-plug",
		Version: "2.0.0",
		Tier:    "managed",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	plugins := m.ListPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if !plugins[0].Enabled {
		t.Error("managed plugin should start enabled")
	}
}

func TestLoadPluginsUnsafeStartsDisabled(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "unsafe-plug", Manifest{
		Name:    "unsafe-plug",
		Version: "0.1.0",
		Tier:    "unsafe",
	})

	m := NewManager(newTestLogger(), true) // allowUnsafe = true
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	plugins := m.ListPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Enabled {
		t.Error("unsafe plugin should start disabled")
	}
}

func TestLoadPluginsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "badplugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins should not fail on invalid JSON, got: %v", err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("invalid manifest should not produce a loaded plugin")
	}
}

func TestLoadPluginsUnsafeRejectedWhenNotAllowed(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "dangerous", Manifest{
		Name:    "dangerous",
		Version: "1.0.0",
		Tier:    "unsafe",
	})

	m := NewManager(newTestLogger(), false) // allowUnsafe = false
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins should not return error, got: %v", err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("unsafe plugin should be rejected when allowUnsafe is false")
	}
}

func TestLoadPluginsMissingName(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "noname", Manifest{
		Version: "1.0.0",
		Tier:    "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins should not fail: %v", err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("plugin with empty name should be rejected")
	}
}

func TestLoadPluginsMissingVersion(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "noversion", Manifest{
		Name: "noversion",
		Tier: "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins should not fail: %v", err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("plugin with empty version should be rejected")
	}
}

func TestLoadPluginsUnknownTier(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "badtier", Manifest{
		Name:    "badtier",
		Version: "1.0.0",
		Tier:    "superadmin",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins should not fail: %v", err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("plugin with unknown tier should be rejected")
	}
}

func TestLoadPluginsSkipsFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file (not a directory) in the plugins dir.
	if err := os.WriteFile(filepath.Join(dir, "notadir.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also add a valid plugin to confirm it still loads.
	writeManifest(t, dir, "real", Manifest{
		Name:    "real",
		Version: "1.0.0",
		Tier:    "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	if len(m.ListPlugins()) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(m.ListPlugins()))
	}
}

func TestLoadPluginsMultiple(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "alpha", Manifest{
		Name:    "alpha",
		Version: "1.0.0",
		Tier:    "passive",
	})
	writeManifest(t, dir, "beta", Manifest{
		Name:    "beta",
		Version: "2.0.0",
		Tier:    "managed",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	if len(m.ListPlugins()) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(m.ListPlugins()))
	}
}

func TestEnablePluginKnown(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "plug", Manifest{
		Name:    "plug",
		Version: "1.0.0",
		Tier:    "unsafe",
	})

	m := NewManager(newTestLogger(), true)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	// Unsafe starts disabled.
	plugins := m.ListPlugins()
	if plugins[0].Enabled {
		t.Fatal("unsafe should start disabled")
	}

	if err := m.EnablePlugin("plug"); err != nil {
		t.Fatalf("EnablePlugin: %v", err)
	}

	plugins = m.ListPlugins()
	if !plugins[0].Enabled {
		t.Fatal("plugin should be enabled after EnablePlugin")
	}
}

func TestEnablePluginAlreadyEnabled(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "plug", Manifest{
		Name:    "plug",
		Version: "1.0.0",
		Tier:    "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	// Passive starts enabled; enabling again should be a no-op.
	if err := m.EnablePlugin("plug"); err != nil {
		t.Fatalf("EnablePlugin on already-enabled plugin: %v", err)
	}
}

func TestEnablePluginUnknown(t *testing.T) {
	m := NewManager(newTestLogger(), false)
	err := m.EnablePlugin("nonexistent")
	if err == nil {
		t.Fatal("expected error when enabling unknown plugin")
	}
}

func TestEnableUnsafePluginWhenNotAllowed(t *testing.T) {
	// Manually register an unsafe plugin that was loaded when allowUnsafe was
	// true, then change the manager to disallow unsafe.
	dir := t.TempDir()
	writeManifest(t, dir, "risky", Manifest{
		Name:    "risky",
		Version: "1.0.0",
		Tier:    "unsafe",
	})

	m := NewManager(newTestLogger(), true)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	// Now flip the flag.
	m.allowUnsafe = false

	err := m.EnablePlugin("risky")
	if err == nil {
		t.Fatal("expected error enabling unsafe plugin when allowUnsafe is false")
	}
}

func TestDisablePluginKnown(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "plug", Manifest{
		Name:    "plug",
		Version: "1.0.0",
		Tier:    "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	if err := m.DisablePlugin("plug"); err != nil {
		t.Fatalf("DisablePlugin: %v", err)
	}

	plugins := m.ListPlugins()
	if plugins[0].Enabled {
		t.Fatal("plugin should be disabled after DisablePlugin")
	}
}

func TestDisablePluginAlreadyDisabled(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "plug", Manifest{
		Name:    "plug",
		Version: "1.0.0",
		Tier:    "unsafe",
	})

	m := NewManager(newTestLogger(), true)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	// Unsafe starts disabled; disabling again is a no-op.
	if err := m.DisablePlugin("plug"); err != nil {
		t.Fatalf("DisablePlugin on already-disabled plugin: %v", err)
	}
}

func TestDisablePluginUnknown(t *testing.T) {
	m := NewManager(newTestLogger(), false)
	err := m.DisablePlugin("nonexistent")
	if err == nil {
		t.Fatal("expected error when disabling unknown plugin")
	}
}

func TestListPluginsEmpty(t *testing.T) {
	m := NewManager(newTestLogger(), false)
	plugins := m.ListPlugins()
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(plugins))
	}
}

func TestListPluginsFieldValues(t *testing.T) {
	dir := t.TempDir()
	pluginDir := writeManifest(t, dir, "detailed", Manifest{
		Name:        "detailed",
		Version:     "3.2.1",
		Description: "A test plugin",
		Author:      "tester",
		Tier:        "passive",
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	plugins := m.ListPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	p := plugins[0]
	if p.Name != "detailed" {
		t.Errorf("Name = %q, want %q", p.Name, "detailed")
	}
	if p.Version != "3.2.1" {
		t.Errorf("Version = %q, want %q", p.Version, "3.2.1")
	}
	if p.Description != "A test plugin" {
		t.Errorf("Description = %q, want %q", p.Description, "A test plugin")
	}
	if p.Author != "tester" {
		t.Errorf("Author = %q, want %q", p.Author, "tester")
	}
	if p.Tier != "passive" {
		t.Errorf("Tier = %q, want %q", p.Tier, "passive")
	}
	if !p.Enabled {
		t.Error("Enabled should be true for passive")
	}
	if p.Dir != pluginDir {
		t.Errorf("Dir = %q, want %q", p.Dir, pluginDir)
	}
}

func TestGetRoutesEmpty(t *testing.T) {
	m := NewManager(newTestLogger(), false)
	routes := m.GetRoutes()
	if len(routes) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(routes))
	}
}

func TestGetRoutesWithDiagEndpoints(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "diagplug")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create the script file so that validation passes.
	scriptPath := filepath.Join(pluginDir, "status.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "diagplug",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{
				Name:   "status",
				Path:   "/diag/diagplug/status",
				Script: "status.sh",
			},
		},
	}
	data, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	routes := m.GetRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	handler, ok := routes["/diag/diagplug/status"]
	if !ok {
		t.Fatal("expected route /diag/diagplug/status")
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
}

func TestGetRoutesDisabledPluginExcluded(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "diagplug")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(pluginDir, "check.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "diagplug",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{
				Name:   "check",
				Path:   "/diag/diagplug/check",
				Script: "check.sh",
			},
		},
	}
	data, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	// Disable the plugin.
	if err := m.DisablePlugin("diagplug"); err != nil {
		t.Fatal(err)
	}

	routes := m.GetRoutes()
	if len(routes) != 0 {
		t.Fatalf("expected 0 routes for disabled plugin, got %d", len(routes))
	}
}

func TestGetRoutesWithUIPages(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "uiplug")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tmplPath := filepath.Join(pluginDir, "dash.html")
	if err := os.WriteFile(tmplPath, []byte("<h1>Dashboard</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "uiplug",
		Version: "1.0.0",
		Tier:    "passive",
		UIPages: []UIPage{
			{
				Name:     "dashboard",
				Path:     "/ui/uiplug/dashboard",
				Template: "dash.html",
			},
		},
	}
	data, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	routes := m.GetRoutes()
	if _, ok := routes["/ui/uiplug/dashboard"]; !ok {
		t.Fatal("expected route /ui/uiplug/dashboard")
	}
}

func TestDiagHandlerReturnsOutput(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "diagplug")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(pluginDir, "hello.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho hello-from-diag"), 0o755); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "diagplug",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{Name: "hello", Path: "/diag/hello", Script: "hello.sh"},
		},
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	routes := m.GetRoutes()
	handler := routes["/diag/hello"]
	if handler == nil {
		t.Fatal("handler not found")
	}

	req := httptest.NewRequest(http.MethodGet, "/diag/hello", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Script execution is disabled for security — expect 403.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (script execution disabled), got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "disabled") {
		t.Errorf("expected disabled message, got %q", body)
	}
}

func TestDiagHandlerRejectsNonGet(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "diagplug")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(pluginDir, "test.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "diagplug",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{Name: "test", Path: "/diag/test", Script: "test.sh"},
		},
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	handler := m.GetRoutes()["/diag/test"]
	req := httptest.NewRequest(http.MethodPost, "/diag/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestUIHandlerServesTemplate(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "uiplug")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "<html><body>Test Page</body></html>"
	if err := os.WriteFile(filepath.Join(pluginDir, "page.html"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "uiplug",
		Version: "1.0.0",
		Tier:    "passive",
		UIPages: []UIPage{
			{Name: "page", Path: "/ui/page", Template: "page.html"},
		},
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	handler := m.GetRoutes()["/ui/page"]
	req := httptest.NewRequest(http.MethodGet, "/ui/page", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != content {
		t.Errorf("body = %q, want %q", rec.Body.String(), content)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
}

func TestNotifyEventFiresWebhook(t *testing.T) {
	var receivedBody []byte
	var receivedMethod string
	var receivedContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedContentType = r.Header.Get("Content-Type")
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeManifest(t, dir, "hookplug", Manifest{
		Name:    "hookplug",
		Version: "1.0.0",
		Tier:    "passive",
		Webhooks: []Webhook{
			{
				Event:  "post-commit",
				URL:    srv.URL,
				Method: "POST",
			},
		},
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	m.NotifyEvent("post-commit", map[string]string{"commit": "abc123"})

	if receivedMethod != "POST" {
		t.Errorf("expected POST, got %s", receivedMethod)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected application/json, got %s", receivedContentType)
	}
	if len(receivedBody) == 0 {
		t.Error("expected non-empty body")
	}

	// Verify the body contains our event.
	var payload map[string]any
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal webhook body: %v", err)
	}
	if payload["event"] != "post-commit" {
		t.Errorf("event = %v, want post-commit", payload["event"])
	}
}

func TestNotifyEventSkipsDisabledPlugin(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeManifest(t, dir, "hookplug", Manifest{
		Name:    "hookplug",
		Version: "1.0.0",
		Tier:    "passive",
		Webhooks: []Webhook{
			{Event: "post-commit", URL: srv.URL, Method: "POST"},
		},
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}
	if err := m.DisablePlugin("hookplug"); err != nil {
		t.Fatal(err)
	}

	m.NotifyEvent("post-commit", nil)

	if called {
		t.Error("webhook should not fire for disabled plugin")
	}
}

func TestNotifyEventSkipsUnmatchedEvent(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeManifest(t, dir, "hookplug", Manifest{
		Name:    "hookplug",
		Version: "1.0.0",
		Tier:    "passive",
		Webhooks: []Webhook{
			{Event: "post-commit", URL: srv.URL, Method: "POST"},
		},
	})

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	m.NotifyEvent("post-rollback", nil)

	if called {
		t.Error("webhook should not fire for unmatched event")
	}
}

func TestLoadPluginsDiagEndpointMissingScript(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "baddiag")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Manifest references a script that does not exist.
	mf := Manifest{
		Name:    "baddiag",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{Name: "missing", Path: "/diag/missing", Script: "nonexistent.sh"},
		},
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("plugin with missing script should be rejected")
	}
}

func TestLoadPluginsDiagEndpointMissingPath(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "nopath")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(pluginDir, "ok.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "nopath",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{Name: "nopath", Path: "", Script: "ok.sh"},
		},
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}
	if len(m.ListPlugins()) != 0 {
		t.Fatal("diag endpoint with empty path should be rejected")
	}
}

func TestGetRoutesCombinesDiagAndUI(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "combo")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "run.sh"), []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "index.html"), []byte("<h1>Hi</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{
		Name:    "combo",
		Version: "1.0.0",
		Tier:    "passive",
		DiagEndpoints: []DiagEndpoint{
			{Name: "run", Path: "/diag/combo/run", Script: "run.sh"},
		},
		UIPages: []UIPage{
			{Name: "index", Path: "/ui/combo/index", Template: "index.html"},
		},
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(newTestLogger(), false)
	if err := m.LoadPlugins(dir); err != nil {
		t.Fatal(err)
	}

	routes := m.GetRoutes()
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if _, ok := routes["/diag/combo/run"]; !ok {
		t.Error("missing diag route")
	}
	if _, ok := routes["/ui/combo/index"]; !ok {
		t.Error("missing UI route")
	}
}
