// Package ha provides High Availability infrastructure hooks for Gatekeeper.
//
// This package implements the groundwork for multi-node HA deployments
// including keepalived/VRRP integration, leader election interfaces,
// state replication stubs, and health check endpoints. The HA service
// supports three modes:
//
//   - standalone: single node, no HA (default)
//   - active-passive: VRRP failover with a single active node
//   - active-active: multiple active nodes with shared virtual IP
//
// Future work will integrate etcd for distributed consensus, conntrack-tools
// for connection state synchronization, and full leader election.
package ha

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mwilco03/kepha/internal/backend"
)

// Proc is the package-level ProcessManager for HA process management.
// Set via SetProcessManager from the daemon.
var Proc backend.ProcessManager

// SetProcessManager sets the process manager for this package.
func SetProcessManager(pm backend.ProcessManager) {
	Proc = pm
}

// State represents the runtime state of a service.
// State and ConfigField are duplicated across ha, ipv6, and service packages.
// Consolidation into a shared package would require breaking the import cycle
// (service → ha → service). For now, kept in sync by convention (M-SA1).
// TODO: move to internal/model when the ha_wrapper.go coupling is resolved.
type State string

const (
	StateStopped  State = "stopped"
	StateRunning  State = "running"
	StateError    State = "error"
	StateStarting State = "starting"
	StateStopping State = "stopping"
)

type ConfigField struct {
	Description string `json:"description"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`
}

// NodeRole indicates the current role of a node in the HA cluster.
type NodeRole string

const (
	RoleStandalone NodeRole = "standalone"
	RoleMaster     NodeRole = "master"
	RoleBackup     NodeRole = "backup"
)

// HAConfig holds the high availability cluster configuration.
type HAConfig struct {
	Mode              string   `json:"mode"`
	NodeID            string   `json:"node_id"`
	ClusterName       string   `json:"cluster_name"`
	VirtualIP         string   `json:"virtual_ip"`
	VRRPInterface     string   `json:"vrrp_interface"`
	VRRPPriority      int      `json:"vrrp_priority"`
	VRRPAuthPass      string   `json:"vrrp_auth_pass"`
	PeerNodes         []string `json:"peer_nodes"`
	HeartbeatInterval int      `json:"heartbeat_interval"`
	KeepalivedConfDir string   `json:"keepalived_conf_dir"`
	EtcdEndpoints     []string `json:"etcd_endpoints,omitempty"`
}

// LeaderElector defines the interface for leader election in a cluster.
// The default implementation is a no-op stub; a production deployment
// would use etcd or a similar consensus system.
type LeaderElector interface {
	// Campaign attempts to become the leader. Blocks until elected or ctx done.
	Campaign(nodeID string) error
	// Resign gives up leadership.
	Resign() error
	// Leader returns the current leader's node ID.
	Leader() (string, error)
	// IsLeader returns true if this node is the current leader.
	IsLeader() bool
}

// StateReplicator defines the interface for synchronizing state between nodes.
// Implementations would handle conntrack state, firewall rules, and service
// configuration replication.
type StateReplicator interface {
	// PushState sends local state to peer nodes.
	PushState(key string, data []byte) error
	// PullState retrieves state from the cluster.
	PullState(key string) ([]byte, error)
	// WatchState registers a callback for state changes.
	WatchState(key string, callback func(data []byte)) error
}

// ConntrackSyncer defines the interface for connection tracking synchronization.
// A production implementation would use conntrack-tools (conntrackd) to
// synchronize the kernel conntrack table between nodes.
type ConntrackSyncer interface {
	// Enable starts conntrack synchronization.
	Enable(peerAddr string) error
	// Disable stops conntrack synchronization.
	Disable() error
	// Status returns the current sync state.
	Status() string
}

// HealthCheck represents a registered health check endpoint.
type HealthCheck struct {
	Name     string        `json:"name"`
	Endpoint string        `json:"endpoint"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	CheckFn  func() error  `json:"-"`
}

// HealthStatus holds the result of a health check run.
type HealthStatus struct {
	Name    string    `json:"name"`
	Healthy bool      `json:"healthy"`
	Error   string    `json:"error,omitempty"`
	CheckAt time.Time `json:"checked_at"`
}

// ---------------------------------------------------------------------------
// Stub implementations
// ---------------------------------------------------------------------------

// stubElector is a no-op leader elector for standalone mode.
type stubElector struct {
	mu       sync.Mutex
	nodeID   string
	isLeader bool
}

func newStubElector() *stubElector {
	return &stubElector{}
}

func (s *stubElector) Campaign(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeID = nodeID
	s.isLeader = true
	return nil
}

func (s *stubElector) Resign() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isLeader = false
	return nil
}

func (s *stubElector) Leader() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isLeader {
		return s.nodeID, nil
	}
	return "", fmt.Errorf("no leader elected")
}

func (s *stubElector) IsLeader() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isLeader
}

// stubReplicator is a no-op state replicator for standalone mode.
type stubReplicator struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newStubReplicator() *stubReplicator {
	return &stubReplicator{data: make(map[string][]byte)}
}

func (s *stubReplicator) PushState(key string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = data
	return nil
}

func (s *stubReplicator) PullState(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.data[key]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("key %q not found", key)
}

func (s *stubReplicator) WatchState(_ string, _ func(data []byte)) error {
	return nil // No-op in standalone mode.
}

// stubConntrackSyncer is a no-op conntrack syncer for standalone mode.
type stubConntrackSyncer struct {
	mu      sync.Mutex
	enabled bool
}

func newStubConntrackSyncer() *stubConntrackSyncer {
	return &stubConntrackSyncer{}
}

func (s *stubConntrackSyncer) Enable(peerAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	slog.Info("ha: conntrack sync enabled (stub)", "peer", peerAddr)
	s.enabled = true
	return nil
}

func (s *stubConntrackSyncer) Disable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	return nil
}

func (s *stubConntrackSyncer) Status() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled {
		return "active-stub"
	}
	return "disabled"
}

// ---------------------------------------------------------------------------
// HAManager service
// ---------------------------------------------------------------------------

// HAManager provides high availability infrastructure for Gatekeeper.
// It implements the Service interface from the service package and
// coordinates VRRP/keepalived, health checks, leader election, and
// state replication.
type HAManager struct {
	mu    sync.Mutex
	state State
	cfg   map[string]string

	haCfg    HAConfig
	role     NodeRole
	stopCh   chan struct{}
	healthMu sync.RWMutex
	checks   []HealthCheck
	statuses map[string]HealthStatus

	elector    LeaderElector
	replicator StateReplicator
	conntrack  ConntrackSyncer

	healthSrv *http.Server
}

// NewHAManager creates a new HA manager.
func NewHAManager() *HAManager {
	return &HAManager{
		state:    StateStopped,
		role:     RoleStandalone,
		statuses: make(map[string]HealthStatus),
	}
}

func (h *HAManager) Name() string        { return "ha" }
func (h *HAManager) DisplayName() string { return "High Availability" }
func (h *HAManager) Category() string    { return "cluster" }
func (h *HAManager) Dependencies() []string {
	return nil
}

func (h *HAManager) Description() string {
	return "High Availability infrastructure with VRRP/keepalived integration, health checks, leader election hooks, and state replication interfaces for multi-node deployments."
}

func (h *HAManager) DefaultConfig() map[string]string {
	return map[string]string{
		"mode":               "standalone",
		"node_id":            "",
		"cluster_name":       "gatekeeper",
		"virtual_ip":         "",
		"vrrp_interface":     "",
		"vrrp_priority":      "100",
		"vrrp_auth_pass":     "",
		"peer_nodes":         "[]",
		"heartbeat_interval": "1",
		"keepalived_conf_dir": "/etc/keepalived",
	}
}

func (h *HAManager) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mode":               {Description: "HA mode: standalone, active-passive, or active-active", Default: "standalone", Required: true, Type: "string"},
		"node_id":            {Description: "Unique identifier for this node in the cluster", Type: "string"},
		"cluster_name":       {Description: "Name of the HA cluster", Default: "gatekeeper", Type: "string"},
		"virtual_ip":         {Description: "Virtual IP address managed by VRRP", Type: "string"},
		"vrrp_interface":     {Description: "Network interface for VRRP communication", Type: "string"},
		"vrrp_priority":      {Description: "VRRP priority (higher value = preferred master, range 1-254)", Default: "100", Type: "int"},
		"vrrp_auth_pass":     {Description: "VRRP authentication password (max 8 characters)", Type: "string"},
		"peer_nodes":         {Description: "JSON array of peer node addresses", Default: "[]", Type: "string"},
		"heartbeat_interval": {Description: "Heartbeat interval in seconds", Default: "1", Type: "int"},
		"keepalived_conf_dir": {Description: "Directory for keepalived configuration files", Default: "/etc/keepalived", Type: "path"},
	}
}

func (h *HAManager) Validate(cfg map[string]string) error {
	mode := cfg["mode"]
	switch mode {
	case "standalone":
		// No further validation needed.
		return nil
	case "active-passive", "active-active":
		// These modes require additional config.
	default:
		return fmt.Errorf("invalid mode: %s (use standalone, active-passive, or active-active)", mode)
	}

	if cfg["node_id"] == "" {
		return fmt.Errorf("node_id is required for %s mode", mode)
	}
	if cfg["virtual_ip"] == "" {
		return fmt.Errorf("virtual_ip is required for %s mode", mode)
	}
	if ip := net.ParseIP(cfg["virtual_ip"]); ip == nil {
		return fmt.Errorf("invalid virtual_ip: %s", cfg["virtual_ip"])
	}
	if cfg["vrrp_interface"] == "" {
		return fmt.Errorf("vrrp_interface is required for %s mode", mode)
	}

	if v := cfg["vrrp_priority"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 254 {
			return fmt.Errorf("vrrp_priority must be between 1 and 254")
		}
	}

	if pass := cfg["vrrp_auth_pass"]; pass != "" && len(pass) > 8 {
		return fmt.Errorf("vrrp_auth_pass must be at most 8 characters")
	}

	if v := cfg["heartbeat_interval"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 60 {
			return fmt.Errorf("heartbeat_interval must be between 1 and 60 seconds")
		}
	}

	if v := cfg["peer_nodes"]; v != "" {
		var peers []string
		if err := json.Unmarshal([]byte(v), &peers); err != nil {
			return fmt.Errorf("peer_nodes must be a valid JSON array of strings: %w", err)
		}
	}

	return nil
}

func (h *HAManager) Start(cfg map[string]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cfg = cfg
	h.stopCh = make(chan struct{})

	// Parse HA configuration.
	if err := h.parseConfig(cfg); err != nil {
		return fmt.Errorf("parse HA config: %w", err)
	}

	// Initialize stub interfaces (replaced by real implementations in future).
	h.elector = newStubElector()
	h.replicator = newStubReplicator()
	h.conntrack = newStubConntrackSyncer()

	switch h.haCfg.Mode {
	case "standalone":
		h.role = RoleStandalone
		slog.Info("ha: starting in standalone mode")

	case "active-passive", "active-active":
		// SECURITY: warn that stub elector is in use — both nodes will claim master.
		// A real elector (etcd) should be configured for production HA.
		slog.Warn("ha: using stub leader elector in cluster mode — both nodes will become master; configure etcd for production",
			"mode", h.haCfg.Mode)
		// Generate and apply keepalived config.
		if err := h.generateKeepalivedConfig(); err != nil {
			return fmt.Errorf("generate keepalived config: %w", err)
		}
		if err := h.startKeepalived(); err != nil {
			return fmt.Errorf("start keepalived: %w", err)
		}

		// Elect self as leader in standalone elector (stub).
		if err := h.elector.Campaign(h.haCfg.NodeID); err != nil {
			slog.Warn("ha: leader election failed", "error", err)
		}
		if h.elector.IsLeader() {
			h.role = RoleMaster
		} else {
			h.role = RoleBackup
		}

		slog.Info("ha: starting in cluster mode",
			"mode", h.haCfg.Mode,
			"node_id", h.haCfg.NodeID,
			"role", h.role,
			"virtual_ip", h.haCfg.VirtualIP,
		)
	}

	// Start health check HTTP endpoint.
	if err := h.startHealthEndpoint(); err != nil {
		slog.Warn("ha: failed to start health endpoint", "error", err)
	}

	// Start heartbeat goroutine.
	go h.heartbeatLoop()

	h.state = StateRunning
	slog.Info("ha: started", "mode", h.haCfg.Mode, "role", h.role)
	return nil
}

func (h *HAManager) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.stopCh != nil {
		close(h.stopCh)
		h.stopCh = nil
	}

	// Stop health endpoint.
	if h.healthSrv != nil {
		h.healthSrv.Close()
		h.healthSrv = nil
	}

	// Resign leadership.
	if h.elector != nil {
		h.elector.Resign()
	}

	// Stop conntrack sync.
	if h.conntrack != nil {
		h.conntrack.Disable()
	}

	// Stop keepalived if running in cluster mode.
	if h.haCfg.Mode != "standalone" {
		if err := h.stopKeepalived(); err != nil {
			slog.Warn("ha: failed to stop keepalived", "error", err)
		}
	}

	h.role = RoleStandalone
	h.state = StateStopped
	slog.Info("ha: stopped")
	return nil
}

func (h *HAManager) Reload(cfg map[string]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cfg = cfg
	if err := h.parseConfig(cfg); err != nil {
		return fmt.Errorf("parse HA config: %w", err)
	}

	if h.haCfg.Mode != "standalone" {
		if err := h.generateKeepalivedConfig(); err != nil {
			return fmt.Errorf("regenerate keepalived config: %w", err)
		}
		if err := h.reloadKeepalived(); err != nil {
			return fmt.Errorf("reload keepalived: %w", err)
		}
	}

	slog.Info("ha: reloaded", "mode", h.haCfg.Mode)
	return nil
}

func (h *HAManager) Status() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// ---------------------------------------------------------------------------
// Configuration parsing
// ---------------------------------------------------------------------------

func (h *HAManager) parseConfig(cfg map[string]string) error {
	h.haCfg = HAConfig{
		Mode:              cfg["mode"],
		NodeID:            cfg["node_id"],
		ClusterName:       cfg["cluster_name"],
		VirtualIP:         cfg["virtual_ip"],
		VRRPInterface:     cfg["vrrp_interface"],
		VRRPAuthPass:      cfg["vrrp_auth_pass"],
		KeepalivedConfDir: cfg["keepalived_conf_dir"],
	}

	if h.haCfg.Mode == "" {
		h.haCfg.Mode = "standalone"
	}
	if h.haCfg.ClusterName == "" {
		h.haCfg.ClusterName = "gatekeeper"
	}
	if h.haCfg.KeepalivedConfDir == "" {
		h.haCfg.KeepalivedConfDir = "/etc/keepalived"
	}

	if v := cfg["vrrp_priority"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid vrrp_priority: %w", err)
		}
		h.haCfg.VRRPPriority = n
	} else {
		h.haCfg.VRRPPriority = 100
	}

	if v := cfg["heartbeat_interval"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid heartbeat_interval: %w", err)
		}
		h.haCfg.HeartbeatInterval = n
	} else {
		h.haCfg.HeartbeatInterval = 1
	}

	if v := cfg["peer_nodes"]; v != "" {
		var peers []string
		if err := json.Unmarshal([]byte(v), &peers); err != nil {
			return fmt.Errorf("parse peer_nodes: %w", err)
		}
		h.haCfg.PeerNodes = peers
	}

	return nil
}

// ---------------------------------------------------------------------------
// Keepalived management
// ---------------------------------------------------------------------------

// generateKeepalivedConfig writes a keepalived.conf for VRRP failover.
// keepalivedSafe returns true if s contains only safe characters for keepalived config values.
// Prevents config injection via newlines, braces, or special characters.
func keepalivedSafe(s string) bool {
	for _, c := range s {
		if c == '\n' || c == '\r' || c == '{' || c == '}' || c == ';' || c == '#' || c == '"' || c == '\'' {
			return false
		}
	}
	return true
}

func (h *HAManager) generateKeepalivedConfig() error {
	if err := os.MkdirAll(h.haCfg.KeepalivedConfDir, 0o755); err != nil {
		return fmt.Errorf("create keepalived conf dir: %w", err)
	}

	vip := h.haCfg.VirtualIP
	iface := h.haCfg.VRRPInterface
	priority := h.haCfg.VRRPPriority

	// Validate config values to prevent keepalived config injection.
	if !keepalivedSafe(h.haCfg.NodeID) || !keepalivedSafe(iface) || !keepalivedSafe(vip) {
		return fmt.Errorf("keepalived config contains unsafe characters in node_id, interface, or vip")
	}
	if h.haCfg.VRRPAuthPass != "" && !keepalivedSafe(h.haCfg.VRRPAuthPass) {
		return fmt.Errorf("keepalived auth_pass contains unsafe characters")
	}
	for _, peer := range h.haCfg.PeerNodes {
		if !keepalivedSafe(peer) {
			return fmt.Errorf("keepalived peer node address contains unsafe characters: %q", peer)
		}
	}

	// Determine VRRP state: higher priority starts as MASTER.
	vrrpState := "BACKUP"
	if priority >= 200 {
		vrrpState = "MASTER"
	}

	// Generate a VRRP router ID from the cluster name (1-255).
	routerID := 51 // Default.
	for _, c := range h.haCfg.ClusterName {
		routerID = (routerID*31 + int(c)) % 255
	}
	if routerID == 0 {
		routerID = 1
	}

	var b strings.Builder
	b.WriteString("# Gatekeeper HA — keepalived configuration\n")
	b.WriteString("# Auto-generated by gatekeeperd — DO NOT EDIT\n\n")

	b.WriteString("global_defs {\n")
	b.WriteString(fmt.Sprintf("    router_id gatekeeper_%s\n", h.haCfg.NodeID))
	b.WriteString("    script_user root\n")
	b.WriteString("    enable_script_security\n")
	b.WriteString("}\n\n")

	// Health check script.
	b.WriteString("vrrp_script chk_gatekeeper {\n")
	b.WriteString("    script \"/usr/bin/curl -sf http://127.0.0.1:9191/health\"\n")
	b.WriteString("    interval 2\n")
	b.WriteString("    weight -20\n")
	b.WriteString("    fall 3\n")
	b.WriteString("    rise 2\n")
	b.WriteString("}\n\n")

	b.WriteString(fmt.Sprintf("vrrp_instance GK_%s {\n", strings.ToUpper(h.haCfg.ClusterName)))
	b.WriteString(fmt.Sprintf("    state %s\n", vrrpState))
	b.WriteString(fmt.Sprintf("    interface %s\n", iface))
	b.WriteString(fmt.Sprintf("    virtual_router_id %d\n", routerID))
	b.WriteString(fmt.Sprintf("    priority %d\n", priority))
	b.WriteString(fmt.Sprintf("    advert_int %d\n", h.haCfg.HeartbeatInterval))
	b.WriteString("    nopreempt\n")

	if h.haCfg.VRRPAuthPass != "" {
		b.WriteString("    authentication {\n")
		b.WriteString("        auth_type PASS\n")
		b.WriteString(fmt.Sprintf("        auth_pass %s\n", h.haCfg.VRRPAuthPass))
		b.WriteString("    }\n")
	}

	// Determine subnet mask from the virtual IP or default to /32.
	vipCIDR := vip
	if !strings.Contains(vipCIDR, "/") {
		vipCIDR += "/32"
	}

	b.WriteString("    virtual_ipaddress {\n")
	b.WriteString(fmt.Sprintf("        %s dev %s\n", vipCIDR, iface))
	b.WriteString("    }\n")

	b.WriteString("    track_script {\n")
	b.WriteString("        chk_gatekeeper\n")
	b.WriteString("    }\n")

	// Unicast peers for environments where multicast is unavailable.
	if len(h.haCfg.PeerNodes) > 0 {
		b.WriteString("    unicast_peer {\n")
		for _, peer := range h.haCfg.PeerNodes {
			b.WriteString(fmt.Sprintf("        %s\n", strings.TrimSpace(peer)))
		}
		b.WriteString("    }\n")
	}

	b.WriteString("}\n")

	confPath := filepath.Join(h.haCfg.KeepalivedConfDir, "keepalived.conf")
	// Restrict to owner-only: config contains VRRP auth password.
	if err := os.WriteFile(confPath, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write keepalived.conf: %w", err)
	}

	slog.Info("ha: keepalived config generated",
		"path", confPath,
		"vip", vip,
		"interface", iface,
		"priority", priority,
	)
	return nil
}

// startKeepalived launches the keepalived daemon via ProcessManager.
func (h *HAManager) startKeepalived() error {
	// Check if keepalived is already running.
	if _, err := Proc.FindProcess("keepalived"); err == nil {
		// Already running, reload instead.
		return h.reloadKeepalived()
	}

	if err := Proc.Start("keepalived"); err != nil {
		return fmt.Errorf("start keepalived: %w", err)
	}

	slog.Info("ha: keepalived started")
	return nil
}

// stopKeepalived terminates the keepalived daemon via ProcessManager.
func (h *HAManager) stopKeepalived() error {
	if err := Proc.Stop("keepalived"); err != nil {
		return fmt.Errorf("stop keepalived: %w", err)
	}
	slog.Info("ha: keepalived stopped")
	return nil
}

// reloadKeepalived sends SIGHUP to keepalived to reload config via ProcessManager.
func (h *HAManager) reloadKeepalived() error {
	if err := Proc.Reload("keepalived"); err != nil {
		return fmt.Errorf("reload keepalived: %w", err)
	}
	slog.Info("ha: keepalived reloaded")
	return nil
}

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

// RegisterHealthCheck adds a health check to the HA manager.
func (h *HAManager) RegisterHealthCheck(check HealthCheck) {
	h.healthMu.Lock()
	defer h.healthMu.Unlock()
	h.checks = append(h.checks, check)
	slog.Info("ha: health check registered", "name", check.Name)
}

// HealthStatuses returns the most recent results of all health checks.
func (h *HAManager) HealthStatuses() map[string]HealthStatus {
	h.healthMu.RLock()
	defer h.healthMu.RUnlock()

	result := make(map[string]HealthStatus, len(h.statuses))
	for k, v := range h.statuses {
		result[k] = v
	}
	return result
}

// startHealthEndpoint starts an HTTP server for health check queries.
func (h *HAManager) startHealthEndpoint() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/health/detail", h.handleHealthDetail)

	h.healthSrv = &http.Server{
		Addr:         "127.0.0.1:9191",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", h.healthSrv.Addr)
	if err != nil {
		return fmt.Errorf("listen health endpoint: %w", err)
	}

	go func() {
		if err := h.healthSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("ha: health endpoint error", "error", err)
		}
	}()

	slog.Info("ha: health endpoint started", "addr", h.healthSrv.Addr)
	return nil
}

// handleHealth returns 200 if all checks pass, 503 otherwise.
func (h *HAManager) handleHealth(w http.ResponseWriter, r *http.Request) {
	h.healthMu.RLock()
	defer h.healthMu.RUnlock()

	for _, status := range h.statuses {
		if !status.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "UNHEALTHY: %s: %s\n", status.Name, status.Error)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}

// handleHealthDetail returns a JSON object with all health check statuses.
func (h *HAManager) handleHealthDetail(w http.ResponseWriter, r *http.Request) {
	h.healthMu.RLock()
	defer h.healthMu.RUnlock()

	detail := struct {
		NodeID   string                  `json:"node_id"`
		Role     NodeRole                `json:"role"`
		Mode     string                  `json:"mode"`
		Checks   map[string]HealthStatus `json:"checks"`
		Healthy  bool                    `json:"healthy"`
	}{
		NodeID:  h.haCfg.NodeID,
		Role:    h.role,
		Mode:    h.haCfg.Mode,
		Checks:  make(map[string]HealthStatus, len(h.statuses)),
		Healthy: true,
	}

	for k, v := range h.statuses {
		detail.Checks[k] = v
		if !v.Healthy {
			detail.Healthy = false
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

// ---------------------------------------------------------------------------
// Heartbeat loop
// ---------------------------------------------------------------------------

// heartbeatLoop runs periodic health checks and peer heartbeats.
func (h *HAManager) heartbeatLoop() {
	interval := time.Duration(h.haCfg.HeartbeatInterval) * time.Second
	if interval < 1*time.Second {
		interval = 1 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.runHealthChecks()
		}
	}
}

// runHealthChecks executes all registered health checks and updates statuses.
func (h *HAManager) runHealthChecks() {
	h.healthMu.RLock()
	checks := make([]HealthCheck, len(h.checks))
	copy(checks, h.checks)
	h.healthMu.RUnlock()

	for _, check := range checks {
		status := HealthStatus{
			Name:    check.Name,
			Healthy: true,
			CheckAt: time.Now(),
		}

		if check.CheckFn != nil {
			if err := check.CheckFn(); err != nil {
				status.Healthy = false
				status.Error = err.Error()
				slog.Warn("ha: health check failed", "check", check.Name, "error", err)
			}
		}

		h.healthMu.Lock()
		h.statuses[check.Name] = status
		h.healthMu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Public accessors
// ---------------------------------------------------------------------------

// Role returns the current HA role of this node.
func (h *HAManager) Role() NodeRole {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.role
}

// Config returns a copy of the current HA configuration.
func (h *HAManager) Config() HAConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.haCfg
}

// Elector returns the leader elector interface.
func (h *HAManager) Elector() LeaderElector {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.elector
}

// Replicator returns the state replicator interface.
func (h *HAManager) Replicator() StateReplicator {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.replicator
}

// Conntrack returns the conntrack syncer interface.
func (h *HAManager) Conntrack() ConntrackSyncer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conntrack
}
