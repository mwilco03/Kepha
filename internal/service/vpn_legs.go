package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// VPNLeg defines a single site-to-site WireGuard tunnel to a remote site.
type VPNLeg struct {
	// Name is the unique identifier for this leg (also used as wg interface suffix).
	Name string `json:"name"`
	// RemoteEndpoint is the WireGuard peer endpoint (host:port).
	RemoteEndpoint string `json:"remote_endpoint"`
	// RemotePublicKey is the WireGuard public key of the remote peer.
	RemotePublicKey string `json:"remote_public_key"`
	// PSK is the optional pre-shared key for additional security.
	PSK string `json:"psk,omitempty"`
	// RemoteSubnets are the CIDRs reachable through this leg.
	RemoteSubnets []string `json:"remote_subnets"`
	// Priority determines route metric (lower = preferred).
	Priority int `json:"priority"`
	// HealthTarget is the IP address to ping for health monitoring.
	HealthTarget string `json:"health_target"`
}

// legState tracks the runtime state of an active leg.
type legState struct {
	def       VPNLeg
	iface     string
	healthy   bool
	routesUp  bool
	cancelCh  chan struct{}
}

// VPNLegs manages site-to-site WireGuard tunnel legs with automatic
// health-based route injection and failover. Multiple legs can serve the same
// remote subnets with different priorities (route metrics); when a leg goes
// down its routes are withdrawn and traffic shifts to the next-best leg.
type VPNLegs struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
	legs    map[string]*legState

	// Health check tunables (parsed from config on Start).
	healthInterval    time.Duration
	healthTimeout     string
	failThreshold     int
	recoveryThreshold int
}

// NewVPNLegs creates a new VPN legs service. confDir is used for WireGuard
// config file generation and state tracking.
func NewVPNLegs(confDir string) *VPNLegs {
	return &VPNLegs{
		confDir: confDir,
		state:   StateStopped,
		legs:    make(map[string]*legState),
	}
}

func (v *VPNLegs) Name() string        { return "vpn-legs" }
func (v *VPNLegs) DisplayName() string  { return "VPN Legs & Route Management" }
func (v *VPNLegs) Category() string     { return "network" }
func (v *VPNLegs) Dependencies() []string { return nil }

func (v *VPNLegs) Description() string {
	return "Site-to-site WireGuard tunnel management with health-based route injection. " +
		"Each leg is a named tunnel to a remote site carrying associated subnets. " +
		"Routes are automatically injected when a leg is healthy and withdrawn on failure, " +
		"with priority-based failover between legs serving the same subnets."
}

func (v *VPNLegs) DefaultConfig() map[string]string {
	return map[string]string{
		"legs":                "[]",
		"local_private_key":   "",
		"local_listen_port":   "51820",
		"health_interval":     "10",
		"health_timeout":      "3",
		"fail_threshold":      "3",
		"recovery_threshold":  "2",
	}
}

func (v *VPNLegs) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"legs": {
			Description: "JSON array of leg definitions. Each object: name, remote_endpoint, remote_public_key, psk (optional), remote_subnets ([]CIDR), priority (int), health_target (IP)",
			Default:     "[]",
			Required:    true,
			Type:        "string",
		},
		"local_private_key": {
			Description: "WireGuard private key for this host",
			Required:    true,
			Type:        "string",
		},
		"local_listen_port": {
			Description: "WireGuard listen port (base; each leg gets base+N if multiple legs share a port)",
			Default:     "51820",
			Type:        "int",
		},
		"health_interval": {
			Description: "Health check interval in seconds",
			Default:     "10",
			Type:        "int",
		},
		"health_timeout": {
			Description: "Health check ping timeout in seconds",
			Default:     "3",
			Type:        "int",
		},
		"fail_threshold": {
			Description: "Consecutive health check failures before marking a leg down",
			Default:     "3",
			Type:        "int",
		},
		"recovery_threshold": {
			Description: "Consecutive health check successes before marking a leg up",
			Default:     "2",
			Type:        "int",
		},
	}
}

func (v *VPNLegs) Validate(cfg map[string]string) error {
	if cfg["local_private_key"] == "" {
		return fmt.Errorf("local_private_key is required")
	}

	port := cfg["local_listen_port"]
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("local_listen_port must be 1-65535")
		}
	}

	legsJSON := cfg["legs"]
	if legsJSON == "" {
		legsJSON = "[]"
	}

	var legs []VPNLeg
	if err := json.Unmarshal([]byte(legsJSON), &legs); err != nil {
		return fmt.Errorf("invalid legs JSON: %w", err)
	}

	names := make(map[string]bool)
	for i, leg := range legs {
		if leg.Name == "" {
			return fmt.Errorf("leg[%d]: name is required", i)
		}
		if strings.ContainsAny(leg.Name, " \t\n/\\") {
			return fmt.Errorf("leg[%d]: invalid name %q", i, leg.Name)
		}
		if names[leg.Name] {
			return fmt.Errorf("leg[%d]: duplicate name %q", i, leg.Name)
		}
		names[leg.Name] = true

		if leg.RemoteEndpoint == "" {
			return fmt.Errorf("leg[%d] %q: remote_endpoint is required", i, leg.Name)
		}
		if leg.RemotePublicKey == "" {
			return fmt.Errorf("leg[%d] %q: remote_public_key is required", i, leg.Name)
		}
		if len(leg.RemoteSubnets) == 0 {
			return fmt.Errorf("leg[%d] %q: at least one remote_subnet is required", i, leg.Name)
		}
		for _, cidr := range leg.RemoteSubnets {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("leg[%d] %q: invalid CIDR %q: %w", i, leg.Name, cidr, err)
			}
		}
		if leg.Priority < 0 {
			return fmt.Errorf("leg[%d] %q: priority must be >= 0", i, leg.Name)
		}
		if leg.HealthTarget != "" {
			if ip := net.ParseIP(leg.HealthTarget); ip == nil {
				return fmt.Errorf("leg[%d] %q: invalid health_target IP %q", i, leg.Name, leg.HealthTarget)
			}
		}
	}

	for _, key := range []string{"health_interval", "health_timeout", "fail_threshold", "recovery_threshold"} {
		if val := cfg[key]; val != "" {
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return fmt.Errorf("%s must be a positive integer", key)
			}
		}
	}

	return nil
}

func (v *VPNLegs) Start(cfg map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.cfg = cfg

	if err := os.MkdirAll(v.confDir, 0o755); err != nil {
		return fmt.Errorf("create confdir: %w", err)
	}

	// Parse tunables.
	v.healthInterval = parseDurationSecs(cfg["health_interval"], 10*time.Second)
	v.healthTimeout = cfg["health_timeout"]
	if v.healthTimeout == "" {
		v.healthTimeout = "3"
	}
	v.failThreshold = parseIntDefault(cfg["fail_threshold"], 3)
	v.recoveryThreshold = parseIntDefault(cfg["recovery_threshold"], 2)

	legs, err := parseLegs(cfg["legs"])
	if err != nil {
		return fmt.Errorf("parse legs: %w", err)
	}

	basePort := parseIntDefault(cfg["local_listen_port"], 51820)
	privateKey := cfg["local_private_key"]

	for i, leg := range legs {
		listenPort := basePort + i
		ls, err := v.startLeg(leg, privateKey, listenPort)
		if err != nil {
			// Tear down any legs already started.
			slog.Error("failed to start leg, rolling back", "leg", leg.Name, "error", err)
			v.stopAllLegsLocked()
			return fmt.Errorf("start leg %q: %w", leg.Name, err)
		}
		v.legs[leg.Name] = ls
	}

	v.state = StateRunning
	slog.Info("vpn-legs started", "count", len(legs))
	return nil
}

func (v *VPNLegs) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.stopAllLegsLocked()
	v.state = StateStopped
	slog.Info("vpn-legs stopped")
	return nil
}

func (v *VPNLegs) Reload(cfg map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	newLegs, err := parseLegs(cfg["legs"])
	if err != nil {
		return fmt.Errorf("parse legs: %w", err)
	}

	newSet := make(map[string]VPNLeg)
	for _, leg := range newLegs {
		newSet[leg.Name] = leg
	}

	// Remove legs that are no longer in config.
	for name, ls := range v.legs {
		if _, exists := newSet[name]; !exists {
			slog.Info("vpn-legs reload: removing leg", "leg", name)
			v.stopLeg(ls)
			delete(v.legs, name)
		}
	}

	// Update config for parsing tunables.
	v.cfg = cfg
	v.healthInterval = parseDurationSecs(cfg["health_interval"], 10*time.Second)
	v.healthTimeout = cfg["health_timeout"]
	if v.healthTimeout == "" {
		v.healthTimeout = "3"
	}
	v.failThreshold = parseIntDefault(cfg["fail_threshold"], 3)
	v.recoveryThreshold = parseIntDefault(cfg["recovery_threshold"], 2)

	basePort := parseIntDefault(cfg["local_listen_port"], 51820)
	privateKey := cfg["local_private_key"]

	// Add new legs or update existing ones.
	for i, leg := range newLegs {
		existing, exists := v.legs[leg.Name]
		if exists {
			// Check if the definition changed.
			if legEqual(existing.def, leg) {
				continue
			}
			// Definition changed: tear down and recreate.
			slog.Info("vpn-legs reload: updating leg", "leg", leg.Name)
			v.stopLeg(existing)
			delete(v.legs, leg.Name)
		}

		slog.Info("vpn-legs reload: adding leg", "leg", leg.Name)
		listenPort := basePort + i
		ls, err := v.startLeg(leg, privateKey, listenPort)
		if err != nil {
			slog.Error("vpn-legs reload: failed to start leg", "leg", leg.Name, "error", err)
			continue
		}
		v.legs[leg.Name] = ls
	}

	slog.Info("vpn-legs reloaded", "legs", len(v.legs))
	return nil
}

func (v *VPNLegs) Status() State {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state
}

// startLeg creates the WireGuard interface, configures the peer, injects
// routes, and starts the health monitor goroutine. Caller must hold v.mu.
func (v *VPNLegs) startLeg(leg VPNLeg, privateKey string, listenPort int) (*legState, error) {
	iface := "wg-" + leg.Name

	ls := &legState{
		def:      leg,
		iface:    iface,
		healthy:  true,
		routesUp: false,
		cancelCh: make(chan struct{}),
	}

	// Create WireGuard interface.
	if err := run("ip", "link", "add", iface, "type", "wireguard"); err != nil {
		return nil, fmt.Errorf("create interface %s: %w", iface, err)
	}

	// Write WireGuard config file.
	confPath := filepath.Join(v.confDir, iface+".conf")
	if err := v.writeWGConfig(confPath, leg, privateKey, listenPort); err != nil {
		// Clean up the interface on failure.
		run("ip", "link", "del", iface)
		return nil, fmt.Errorf("write wg config: %w", err)
	}

	// Apply WireGuard config.
	if err := run("wg", "setconf", iface, confPath); err != nil {
		run("ip", "link", "del", iface)
		return nil, fmt.Errorf("apply wg config on %s: %w", iface, err)
	}

	// Bring interface up.
	if err := run("ip", "link", "set", iface, "up"); err != nil {
		run("ip", "link", "del", iface)
		return nil, fmt.Errorf("bring up %s: %w", iface, err)
	}

	// Inject routes.
	if err := v.injectRoutes(ls); err != nil {
		slog.Warn("initial route injection failed (will retry on health check)", "leg", leg.Name, "error", err)
	}

	slog.Info("vpn leg started", "leg", leg.Name, "interface", iface, "endpoint", leg.RemoteEndpoint)

	// Start health monitor.
	go v.healthMonitor(ls)

	return ls, nil
}

// stopLeg tears down a single leg: stops health monitor, withdraws routes,
// removes the WireGuard interface.
func (v *VPNLegs) stopLeg(ls *legState) {
	close(ls.cancelCh)

	if ls.routesUp {
		v.withdrawRoutes(ls)
	}

	run("ip", "link", "set", ls.iface, "down")
	run("ip", "link", "del", ls.iface)

	// Remove config file.
	confPath := filepath.Join(v.confDir, ls.iface+".conf")
	os.Remove(confPath)

	slog.Info("vpn leg stopped", "leg", ls.def.Name, "interface", ls.iface)
}

// stopAllLegsLocked stops every active leg. Caller must hold v.mu.
func (v *VPNLegs) stopAllLegsLocked() {
	for name, ls := range v.legs {
		v.stopLeg(ls)
		delete(v.legs, name)
	}
}

// writeWGConfig writes a WireGuard configuration file for a leg.
func (v *VPNLegs) writeWGConfig(path string, leg VPNLeg, privateKey string, listenPort int) error {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", listenPort))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))
	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", leg.RemotePublicKey))
	if leg.PSK != "" {
		b.WriteString(fmt.Sprintf("PresharedKey = %s\n", leg.PSK))
	}
	b.WriteString(fmt.Sprintf("Endpoint = %s\n", leg.RemoteEndpoint))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(leg.RemoteSubnets, ", ")))
	b.WriteString("PersistentKeepalive = 25\n")

	// Write with restricted permissions since it contains keys.
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// injectRoutes adds routes for the leg's remote subnets via its WireGuard
// interface with the configured metric (priority).
func (v *VPNLegs) injectRoutes(ls *legState) error {
	metric := strconv.Itoa(ls.def.Priority)
	var firstErr error
	for _, subnet := range ls.def.RemoteSubnets {
		if err := run("ip", "route", "add", subnet, "dev", ls.iface, "metric", metric); err != nil {
			slog.Warn("route inject failed", "leg", ls.def.Name, "subnet", subnet, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	ls.routesUp = true
	slog.Info("routes injected", "leg", ls.def.Name, "subnets", ls.def.RemoteSubnets, "metric", metric)
	return firstErr
}

// withdrawRoutes removes routes for the leg's remote subnets.
func (v *VPNLegs) withdrawRoutes(ls *legState) {
	for _, subnet := range ls.def.RemoteSubnets {
		if err := run("ip", "route", "del", subnet, "dev", ls.iface); err != nil {
			slog.Warn("route withdrawal failed", "leg", ls.def.Name, "subnet", subnet, "error", err)
		}
	}
	ls.routesUp = false
	slog.Info("routes withdrawn", "leg", ls.def.Name, "subnets", ls.def.RemoteSubnets)
}

// healthMonitor periodically pings the leg's health target and injects or
// withdraws routes based on reachability. It runs until the leg's cancelCh is
// closed.
func (v *VPNLegs) healthMonitor(ls *legState) {
	if ls.def.HealthTarget == "" {
		slog.Info("no health target configured, leg always considered healthy", "leg", ls.def.Name)
		return
	}

	v.mu.Lock()
	interval := v.healthInterval
	timeout := v.healthTimeout
	failThresh := v.failThreshold
	recoveryThresh := v.recoveryThreshold
	v.mu.Unlock()

	consecutiveFails := 0
	consecutiveSuccesses := 0

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ls.cancelCh:
			return
		case <-ticker.C:
			ok := v.pingHealth(ls.def.HealthTarget, ls.iface, timeout)

			v.mu.Lock()
			if ok {
				consecutiveFails = 0
				consecutiveSuccesses++

				if !ls.healthy && consecutiveSuccesses >= recoveryThresh {
					ls.healthy = true
					slog.Info("vpn leg recovered", "leg", ls.def.Name)
					if !ls.routesUp {
						if err := v.injectRoutes(ls); err != nil {
							slog.Error("route re-injection failed on recovery", "leg", ls.def.Name, "error", err)
						}
					}
				}
			} else {
				consecutiveSuccesses = 0
				consecutiveFails++

				if ls.healthy && consecutiveFails >= failThresh {
					ls.healthy = false
					slog.Warn("vpn leg down", "leg", ls.def.Name, "failures", consecutiveFails)
					if ls.routesUp {
						v.withdrawRoutes(ls)
					}
				}
			}
			v.mu.Unlock()
		}
	}
}

// pingHealth sends a single ICMP ping to the target via the specified
// interface and returns true if the host is reachable.
func (v *VPNLegs) pingHealth(target, iface, timeout string) bool {
	timeoutSec := 3
	if v2, err := strconv.Atoi(timeout); err == nil && v2 > 0 {
		timeoutSec = v2
	}
	result, err := Net.Ping(target, 1, timeoutSec, iface)
	return err == nil && result.Received > 0
}

// parseLegs deserializes the JSON legs config string.
func parseLegs(legsJSON string) ([]VPNLeg, error) {
	if legsJSON == "" || legsJSON == "[]" {
		return nil, nil
	}
	var legs []VPNLeg
	if err := json.Unmarshal([]byte(legsJSON), &legs); err != nil {
		return nil, fmt.Errorf("unmarshal legs: %w", err)
	}
	return legs, nil
}

// legEqual returns true if two leg definitions are functionally identical.
func legEqual(a, b VPNLeg) bool {
	if a.Name != b.Name || a.RemoteEndpoint != b.RemoteEndpoint ||
		a.RemotePublicKey != b.RemotePublicKey || a.PSK != b.PSK ||
		a.Priority != b.Priority || a.HealthTarget != b.HealthTarget {
		return false
	}
	if len(a.RemoteSubnets) != len(b.RemoteSubnets) {
		return false
	}
	for i := range a.RemoteSubnets {
		if a.RemoteSubnets[i] != b.RemoteSubnets[i] {
			return false
		}
	}
	return true
}

// parseDurationSecs parses a string as integer seconds and returns a
// time.Duration. Falls back to defVal on error.
func parseDurationSecs(s string, defVal time.Duration) time.Duration {
	if s == "" {
		return defVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return defVal
	}
	return time.Duration(n) * time.Second
}

// parseIntDefault parses a string as an integer, returning defVal on error.
func parseIntDefault(s string, defVal int) int {
	if s == "" {
		return defVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return defVal
	}
	return n
}
