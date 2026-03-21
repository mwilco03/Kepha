// Package service provides a pluggable service manager for Gatekeeper.
//
// Services are network daemons or system capabilities (DNS filtering, Avahi,
// SMB, bridging, DDNS, etc.) that can be enabled/disabled at runtime. Each
// service implements the Service interface and is registered with the Manager.
//
// The Manager persists service state (enabled, config) in SQLite and
// coordinates lifecycle operations (start, stop, reload, status).
package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// State represents the runtime state of a service.
type State string

const (
	StateStopped  State = "stopped"
	StateRunning  State = "running"
	StateError    State = "error"
	StateStarting State = "starting"
	StateStopping State = "stopping"
)

// ServiceInfo describes a registered service's metadata and current state.
type ServiceInfo struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	State       State             `json:"state"`
	Error       string            `json:"error,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Deps        []string          `json:"deps,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Service is the interface that all pluggable services must implement.
type Service interface {
	// Name returns the unique service identifier (e.g. "dns-filter", "avahi").
	Name() string
	// DisplayName returns the human-readable name.
	DisplayName() string
	// Description returns a short description of what the service does.
	Description() string
	// Category groups services (e.g. "dns", "discovery", "sharing", "network").
	Category() string
	// Dependencies returns names of services that must be running first.
	Dependencies() []string

	// Start launches the service with the given config.
	Start(cfg map[string]string) error
	// Stop gracefully stops the service.
	Stop() error
	// Reload applies configuration changes without a full restart.
	Reload(cfg map[string]string) error
	// Status returns the current runtime state.
	Status() State
	// Validate checks if the config is valid before applying.
	Validate(cfg map[string]string) error
	// DefaultConfig returns the default configuration for the service.
	DefaultConfig() map[string]string
	// ConfigSchema returns a description of each config key.
	ConfigSchema() map[string]ConfigField
}

// ConfigField describes a single configuration parameter.
type ConfigField struct {
	Description string `json:"description"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Type        string `json:"type"` // "string", "bool", "int", "cidr", "path"
}

// Manager coordinates service lifecycle and persists state.
type Manager struct {
	mu       sync.RWMutex
	db       *sql.DB
	registry map[string]Service
	states   map[string]State
	errors   map[string]string
}

// NewManager creates a service manager backed by the given database.
func NewManager(db *sql.DB) (*Manager, error) {
	m := &Manager{
		db:       db,
		registry: make(map[string]Service),
		states:   make(map[string]State),
		errors:   make(map[string]string),
	}
	if err := m.migrate(); err != nil {
		return nil, fmt.Errorf("service manager migration: %w", err)
	}
	return m, nil
}

// Register adds a service to the manager. Does not start it.
func (m *Manager) Register(svc Service) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry[svc.Name()] = svc
	m.states[svc.Name()] = StateStopped
}

// Enable marks a service as enabled and starts it.
func (m *Manager) Enable(name string) error {
	m.mu.Lock()
	svc, ok := m.registry[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown service: %s", name)
	}

	cfg, err := m.loadConfig(name)
	if err != nil {
		return err
	}
	if len(cfg) == 0 {
		cfg = svc.DefaultConfig()
	}

	// Check dependencies.
	for _, dep := range svc.Dependencies() {
		m.mu.RLock()
		depState := m.states[dep]
		m.mu.RUnlock()
		if depState != StateRunning {
			return fmt.Errorf("dependency %q is not running (state: %s)", dep, depState)
		}
	}

	if err := m.setEnabled(name, true); err != nil {
		return err
	}

	return m.startService(svc, cfg)
}

// Disable stops a service and marks it as disabled.
func (m *Manager) Disable(name string) error {
	m.mu.Lock()
	svc, ok := m.registry[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown service: %s", name)
	}

	if err := m.setEnabled(name, false); err != nil {
		return err
	}

	return m.stopService(svc)
}

// Configure updates a service's configuration and reloads if running.
func (m *Manager) Configure(name string, cfg map[string]string) error {
	m.mu.RLock()
	svc, ok := m.registry[name]
	state := m.states[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown service: %s", name)
	}

	if err := svc.Validate(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if err := m.saveConfig(name, cfg); err != nil {
		return err
	}

	if state == StateRunning {
		return svc.Reload(cfg)
	}
	return nil
}

// List returns info for all registered services.
// Snapshots the registry under the lock, then queries DB lock-free
// to avoid holding RLock during SQLite I/O (M-BA4).
func (m *Manager) List() []ServiceInfo {
	// Snapshot under lock.
	m.mu.RLock()
	type snapshot struct {
		svc   Service
		state State
		err   string
	}
	snaps := make([]snapshot, 0, len(m.registry))
	for _, svc := range m.registry {
		snaps = append(snaps, snapshot{
			svc:   svc,
			state: m.states[svc.Name()],
			err:   m.errors[svc.Name()],
		})
	}
	m.mu.RUnlock()

	// Build result without holding the lock (DB queries happen here).
	result := make([]ServiceInfo, 0, len(snaps))
	for _, s := range snaps {
		name := s.svc.Name()
		enabled, _ := m.isEnabled(name)
		cfg, _ := m.loadConfig(name)
		if len(cfg) == 0 {
			cfg = s.svc.DefaultConfig()
		}
		result = append(result, ServiceInfo{
			Name:        name,
			DisplayName: s.svc.DisplayName(),
			Description: s.svc.Description(),
			Category:    s.svc.Category(),
			Enabled:     enabled,
			State:       s.state,
			Error:       s.err,
			Config:      cfg,
			Deps:        s.svc.Dependencies(),
		})
	}
	return result
}

// Get returns info for a single service.
func (m *Manager) Get(name string) (ServiceInfo, error) {
	m.mu.RLock()
	svc, ok := m.registry[name]
	m.mu.RUnlock()
	if !ok {
		return ServiceInfo{}, fmt.Errorf("unknown service: %s", name)
	}

	enabled, _ := m.isEnabled(name)
	cfg, _ := m.loadConfig(name)
	if len(cfg) == 0 {
		cfg = svc.DefaultConfig()
	}

	m.mu.RLock()
	info := ServiceInfo{
		Name:        name,
		DisplayName: svc.DisplayName(),
		Description: svc.Description(),
		Category:    svc.Category(),
		Enabled:     enabled,
		State:       m.states[name],
		Error:       m.errors[name],
		Config:      cfg,
		Deps:        svc.Dependencies(),
	}
	m.mu.RUnlock()
	return info, nil
}

// Schema returns the config schema for a service.
func (m *Manager) Schema(name string) (map[string]ConfigField, error) {
	m.mu.RLock()
	svc, ok := m.registry[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown service: %s", name)
	}
	return svc.ConfigSchema(), nil
}

// StartEnabled starts all services that are marked enabled in the DB.
// Called at daemon boot.
func (m *Manager) StartEnabled() {
	m.mu.RLock()
	services := make([]Service, 0, len(m.registry))
	for _, svc := range m.registry {
		services = append(services, svc)
	}
	m.mu.RUnlock()

	// Start services respecting dependency order (simple: deps first pass).
	started := make(map[string]bool)
	maxPasses := 5
	for pass := 0; pass < maxPasses; pass++ {
		progress := false
		for _, svc := range services {
			name := svc.Name()
			if started[name] {
				continue
			}
			enabled, _ := m.isEnabled(name)
			if !enabled {
				started[name] = true
				continue
			}

			// Check deps.
			depsOK := true
			for _, dep := range svc.Dependencies() {
				if !started[dep] {
					depsOK = false
					break
				}
			}
			if !depsOK {
				continue
			}

			cfg, _ := m.loadConfig(name)
			if len(cfg) == 0 {
				cfg = svc.DefaultConfig()
			}

			if err := m.startService(svc, cfg); err != nil {
				slog.Error("failed to start service", "service", name, "error", err)
			}
			started[name] = true
			progress = true
		}
		if !progress {
			break
		}
	}
}

// StopAll stops all running services in reverse order.
func (m *Manager) StopAll() {
	m.mu.RLock()
	services := make([]Service, 0, len(m.registry))
	for _, svc := range m.registry {
		services = append(services, svc)
	}
	m.mu.RUnlock()

	for i := len(services) - 1; i >= 0; i-- {
		svc := services[i]
		m.mu.RLock()
		state := m.states[svc.Name()]
		m.mu.RUnlock()
		if state == StateRunning {
			if err := m.stopService(svc); err != nil {
				slog.Error("failed to stop service", "service", svc.Name(), "error", err)
			}
		}
	}
}

func (m *Manager) startService(svc Service, cfg map[string]string) error {
	name := svc.Name()
	m.mu.Lock()
	m.states[name] = StateStarting
	m.errors[name] = ""
	m.mu.Unlock()

	slog.Info("starting service", "service", name)
	if err := svc.Start(cfg); err != nil {
		m.mu.Lock()
		m.states[name] = StateError
		m.errors[name] = err.Error()
		m.mu.Unlock()
		return fmt.Errorf("start %s: %w", name, err)
	}

	m.mu.Lock()
	m.states[name] = StateRunning
	m.mu.Unlock()
	slog.Info("service started", "service", name)
	return nil
}

func (m *Manager) stopService(svc Service) error {
	name := svc.Name()
	m.mu.Lock()
	m.states[name] = StateStopping
	m.mu.Unlock()

	slog.Info("stopping service", "service", name)
	if err := svc.Stop(); err != nil {
		m.mu.Lock()
		m.states[name] = StateError
		m.errors[name] = err.Error()
		m.mu.Unlock()
		return fmt.Errorf("stop %s: %w", name, err)
	}

	m.mu.Lock()
	m.states[name] = StateStopped
	m.errors[name] = ""
	m.mu.Unlock()
	slog.Info("service stopped", "service", name)
	return nil
}

// DB operations.

func (m *Manager) migrate() error {
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS services (
			name       TEXT PRIMARY KEY,
			enabled    INTEGER NOT NULL DEFAULT 0,
			config     TEXT NOT NULL DEFAULT '{}',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func (m *Manager) isEnabled(name string) (bool, error) {
	var enabled int
	err := m.db.QueryRow("SELECT enabled FROM services WHERE name = ?", name).Scan(&enabled)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return enabled == 1, err
}

func (m *Manager) setEnabled(name string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	_, err := m.db.Exec(`
		INSERT INTO services (name, enabled, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled, updated_at = CURRENT_TIMESTAMP
	`, name, val)
	return err
}

func (m *Manager) loadConfig(name string) (map[string]string, error) {
	var raw string
	err := m.db.QueryRow("SELECT config FROM services WHERE name = ?", name).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg map[string]string
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (m *Manager) saveConfig(name string, cfg map[string]string) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = m.db.Exec(`
		INSERT INTO services (name, config, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET config = excluded.config, updated_at = CURRENT_TIMESTAMP
	`, name, string(data))
	return err
}
