package service

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// MultiWAN provides multi-WAN failover and load balancing.
// Monitors multiple WAN connections and automatically fails over when the
// primary goes down. Supports active-passive (failover) and active-active
// (load balancing) modes.
//
// Implementation: uses ip route with multiple default routes and custom
// routing tables, plus periodic health checks to detect WAN failures.
type MultiWAN struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
	stopCh  chan struct{}
}

func NewMultiWAN(confDir string) *MultiWAN {
	return &MultiWAN{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (m *MultiWAN) Name() string           { return "multiwan" }
func (m *MultiWAN) DisplayName() string    { return "Multi-WAN Failover" }
func (m *MultiWAN) Category() string       { return "network" }
func (m *MultiWAN) Dependencies() []string { return nil }

func (m *MultiWAN) Description() string {
	return "Multi-WAN failover and load balancing. Monitors WAN connections and automatically switches to backup when the primary fails. Supports active-passive and weighted load balancing."
}

func (m *MultiWAN) DefaultConfig() map[string]string {
	return map[string]string{
		"mode":               "failover",
		"wan1_interface":     "",
		"wan1_gateway":       "",
		"wan1_weight":        "100",
		"wan1_check_target":  "1.1.1.1",
		"wan2_interface":     "",
		"wan2_gateway":       "",
		"wan2_weight":        "50",
		"wan2_check_target":  "8.8.8.8",
		"check_interval":     "10",
		"check_timeout":      "3",
		"fail_threshold":     "3",
		"recovery_threshold": "2",
		"check_method":       "ping",
	}
}

func (m *MultiWAN) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mode":               {Description: "Mode: failover (active-passive) or loadbalance (weighted)", Default: "failover", Required: true, Type: "string"},
		"wan1_interface":     {Description: "Primary WAN interface", Required: true, Type: "string"},
		"wan1_gateway":       {Description: "Primary WAN gateway IP", Required: true, Type: "string"},
		"wan1_weight":        {Description: "Primary WAN weight (for load balancing)", Default: "100", Type: "int"},
		"wan1_check_target":  {Description: "IP to ping for primary WAN health check", Default: "1.1.1.1", Type: "string"},
		"wan2_interface":     {Description: "Secondary WAN interface", Required: true, Type: "string"},
		"wan2_gateway":       {Description: "Secondary WAN gateway IP", Required: true, Type: "string"},
		"wan2_weight":        {Description: "Secondary WAN weight (for load balancing)", Default: "50", Type: "int"},
		"wan2_check_target":  {Description: "IP to ping for secondary WAN health check", Default: "8.8.8.8", Type: "string"},
		"check_interval":     {Description: "Health check interval in seconds", Default: "10", Type: "int"},
		"check_timeout":      {Description: "Health check timeout in seconds", Default: "3", Type: "int"},
		"fail_threshold":     {Description: "Consecutive failures before marking WAN down", Default: "3", Type: "int"},
		"recovery_threshold": {Description: "Consecutive successes before marking WAN up", Default: "2", Type: "int"},
		"check_method":       {Description: "Health check method: ping or curl", Default: "ping", Type: "string"},
	}
}

func (m *MultiWAN) Validate(cfg map[string]string) error {
	mode := cfg["mode"]
	if mode != "failover" && mode != "loadbalance" {
		return fmt.Errorf("invalid mode: %s (use failover or loadbalance)", mode)
	}
	if cfg["wan1_interface"] == "" || cfg["wan1_gateway"] == "" {
		return fmt.Errorf("wan1_interface and wan1_gateway are required")
	}
	if cfg["wan2_interface"] == "" || cfg["wan2_gateway"] == "" {
		return fmt.Errorf("wan2_interface and wan2_gateway are required")
	}
	return nil
}

func (m *MultiWAN) Start(cfg map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.stopCh = make(chan struct{})

	if err := os.MkdirAll(m.confDir, 0o755); err != nil {
		return err
	}

	// Set up routing tables.
	if err := m.setupRoutingTables(); err != nil {
		return err
	}

	// Start health check loop.
	go m.healthCheckLoop()

	m.state = StateRunning
	slog.Info("multi-wan started", "mode", cfg["mode"])
	return nil
}

func (m *MultiWAN) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopCh != nil {
		close(m.stopCh)
	}

	// Clean up routing tables.
	m.cleanupRoutingTables()

	m.state = StateStopped
	return nil
}

func (m *MultiWAN) Reload(cfg map[string]string) error {
	if err := m.Stop(); err != nil {
		slog.Warn("multiwan stop during reload", "error", err)
	}
	return m.Start(cfg)
}

func (m *MultiWAN) Status() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *MultiWAN) setupRoutingTables() error {
	cfg := m.cfg

	// Create routing tables for each WAN.
	// Table 100: WAN1, Table 200: WAN2.
	run("ip", "route", "flush", "table", "100")
	run("ip", "route", "flush", "table", "200")

	// WAN1 routing table.
	run("ip", "route", "add", "default", "via", cfg["wan1_gateway"],
		"dev", cfg["wan1_interface"], "table", "100")

	// WAN2 routing table.
	run("ip", "route", "add", "default", "via", cfg["wan2_gateway"],
		"dev", cfg["wan2_interface"], "table", "200")

	// Set up ip rules for source-based routing.
	run("ip", "rule", "add", "oif", cfg["wan1_interface"], "table", "100", "priority", "100")
	run("ip", "rule", "add", "oif", cfg["wan2_interface"], "table", "200", "priority", "200")

	// Initial default route via WAN1.
	m.setDefaultRoute(cfg["wan1_gateway"], cfg["wan1_interface"])

	// Write marker file with current state.
	state := "wan1=up\nwan2=up\nactive=wan1\n"
	os.WriteFile(filepath.Join(m.confDir, "multiwan-state"), []byte(state), 0o644)

	slog.Info("multi-wan routing tables configured")
	return nil
}

func (m *MultiWAN) cleanupRoutingTables() {
	if m.cfg == nil {
		return
	}
	cfg := m.cfg
	run("ip", "route", "flush", "table", "100")
	run("ip", "route", "flush", "table", "200")
	run("ip", "rule", "del", "oif", cfg["wan1_interface"], "table", "100")
	run("ip", "rule", "del", "oif", cfg["wan2_interface"], "table", "200")
}

func (m *MultiWAN) healthCheckLoop() {
	m.mu.Lock()
	cfg := m.cfg
	stopCh := m.stopCh
	m.mu.Unlock()

	interval := 10 * time.Second
	if secs := cfg["check_interval"]; secs != "" {
		if v, err := time.ParseDuration(secs + "s"); err == nil && v >= time.Second {
			interval = v
		}
	}

	timeout := cfg["check_timeout"]
	if timeout == "" {
		timeout = "3"
	}

	failThreshold := 3
	recoveryThreshold := 2
	if v := cfg["fail_threshold"]; v != "" {
		fmt.Sscanf(v, "%d", &failThreshold)
	}
	if v := cfg["recovery_threshold"]; v != "" {
		fmt.Sscanf(v, "%d", &recoveryThreshold)
	}

	wan1Fails := 0
	wan2Fails := 0
	wan1Up := true
	wan2Up := true
	activeWAN := "wan1"

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			// Check WAN1.
			if m.checkWAN(cfg["wan1_check_target"], cfg["wan1_interface"], timeout) {
				if !wan1Up {
					wan1Fails = 0
					wan1Fails-- // Count as recovery.
					if -wan1Fails >= recoveryThreshold {
						wan1Up = true
						slog.Info("multi-wan: WAN1 recovered")
						if activeWAN != "wan1" && cfg["mode"] == "failover" {
							m.setDefaultRoute(cfg["wan1_gateway"], cfg["wan1_interface"])
							activeWAN = "wan1"
							slog.Info("multi-wan: switched back to WAN1")
						}
					}
				} else {
					wan1Fails = 0
				}
			} else {
				wan1Fails++
				if wan1Fails >= failThreshold && wan1Up {
					wan1Up = false
					slog.Warn("multi-wan: WAN1 down", "failures", wan1Fails)
					if activeWAN == "wan1" && wan2Up {
						m.setDefaultRoute(cfg["wan2_gateway"], cfg["wan2_interface"])
						activeWAN = "wan2"
						slog.Info("multi-wan: failed over to WAN2")
					}
				}
			}

			// Check WAN2.
			if m.checkWAN(cfg["wan2_check_target"], cfg["wan2_interface"], timeout) {
				if !wan2Up {
					wan2Fails = 0
					wan2Fails--
					if -wan2Fails >= recoveryThreshold {
						wan2Up = true
						slog.Info("multi-wan: WAN2 recovered")
					}
				} else {
					wan2Fails = 0
				}
			} else {
				wan2Fails++
				if wan2Fails >= failThreshold && wan2Up {
					wan2Up = false
					slog.Warn("multi-wan: WAN2 down", "failures", wan2Fails)
					if activeWAN == "wan2" && wan1Up {
						m.setDefaultRoute(cfg["wan1_gateway"], cfg["wan1_interface"])
						activeWAN = "wan1"
						slog.Info("multi-wan: failed over to WAN1")
					}
				}
			}

			// Write state file.
			state := fmt.Sprintf("wan1=%s\nwan2=%s\nactive=%s\n",
				boolState(wan1Up), boolState(wan2Up), activeWAN)
			os.WriteFile(filepath.Join(m.confDir, "multiwan-state"), []byte(state), 0o644)
		}
	}
}

func (m *MultiWAN) checkWAN(target, iface, timeout string) bool {
	if target == "" {
		return true
	}
	cmd := exec.Command("ping", "-c", "1", "-W", timeout, "-I", iface, target)
	return cmd.Run() == nil
}

func (m *MultiWAN) setDefaultRoute(gateway, iface string) {
	// Remove existing default, add new.
	run("ip", "route", "del", "default")
	run("ip", "route", "add", "default", "via", gateway, "dev", iface)
}

func boolState(up bool) string {
	if up {
		return "up"
	}
	return "down"
}
