package service

import (
	"fmt"
	"log/slog"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
)

// Proc is the package-level ProcessManager used by all services that need to
// start/stop/reload system daemons. Set by the daemon at startup via SetProcessManager.
// Falls back to a logging no-op if not set (safe for tests / standalone usage).
var Proc backend.ProcessManager = &noopProcessManager{}

// HTTP is the package-level HTTPClient used by services that need to fetch
// URLs (DDNS updates, blocklist downloads, etc.). Set by the daemon at startup.
// Falls back to a real Go HTTP client by default (safe without explicit init).
var HTTP backend.HTTPClient = backend.NewHTTPClient()

// Net is the package-level NetworkManager used by services that need
// ping, conntrack, connections, etc. Falls back to LinuxNetworkManager.
var Net backend.NetworkManager = backend.NewLinuxNetworkManager()

// SetProcessManager sets the package-level process manager.
// Call this from the daemon before starting any services.
func SetProcessManager(pm backend.ProcessManager) {
	Proc = pm
}

// SetHTTPClient sets the package-level HTTP client.
func SetHTTPClient(c backend.HTTPClient) {
	HTTP = c
}

// SetNetworkManager sets the package-level network manager.
func SetNetworkManager(nm backend.NetworkManager) {
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
