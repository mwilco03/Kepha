package service

import (
	"fmt"
	"log/slog"

	"github.com/mwilco03/kepha/internal/backend"
)

// Package-level dependencies for service DI. These are write-once globals:
// set by the daemon in main() BEFORE svcMgr.StartEnabled(), and read-only
// thereafter. This ordering guarantee means no mutex is needed — all writes
// happen-before any concurrent read (M-BA3).
//
// Callers MUST NOT call Set*() after services have started.
var (
	Proc backend.ProcessManager = &noopProcessManager{}
	HTTP backend.HTTPClient     = backend.NewHTTPClient()
	Net  backend.NetworkManager = backend.NewLinuxNetworkManager()
)

// SetProcessManager sets the package-level process manager.
// MUST be called before svcMgr.StartEnabled().
func SetProcessManager(pm backend.ProcessManager) {
	if pm == nil {
		return
	}
	Proc = pm
}

// SetHTTPClient sets the package-level HTTP client.
// MUST be called before svcMgr.StartEnabled().
func SetHTTPClient(c backend.HTTPClient) {
	if c == nil {
		return
	}
	HTTP = c
}

// SetNetworkManager sets the package-level network manager.
// MUST be called before svcMgr.StartEnabled().
func SetNetworkManager(nm backend.NetworkManager) {
	if nm == nil {
		return
	}
	Net = nm
}

// noopProcessManager logs operations but does not execute them.
// Used when no real ProcessManager is configured (tests, etc.).
type noopProcessManager struct{}

func (n *noopProcessManager) Start(service string) error {
	slog.Warn("process manager not configured, skipping start", "service", service)
	return fmt.Errorf("process manager not configured")
}

func (n *noopProcessManager) Stop(service string) error {
	slog.Warn("process manager not configured, skipping stop", "service", service)
	return nil
}

func (n *noopProcessManager) Restart(service string) error {
	slog.Warn("process manager not configured, skipping restart", "service", service)
	return fmt.Errorf("process manager not configured")
}

func (n *noopProcessManager) Reload(service string) error {
	slog.Warn("process manager not configured, skipping reload", "service", service)
	return fmt.Errorf("process manager not configured")
}

func (n *noopProcessManager) Status(service string) (backend.ProcessStatus, error) {
	return backend.ProcessStatus{}, fmt.Errorf("process manager not configured")
}

func (n *noopProcessManager) Signal(pid int, sig backend.ProcessSignal) error {
	return fmt.Errorf("process manager not configured")
}

func (n *noopProcessManager) FindProcess(name string) (int, error) {
	return 0, fmt.Errorf("process manager not configured")
}

func (n *noopProcessManager) IsRunning(pid int) bool {
	return false
}
