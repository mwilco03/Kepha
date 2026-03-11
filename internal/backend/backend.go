// Package backend defines the core interfaces for Gatekeeper's system
// integration layer. All interaction with the host OS (firewall, VPN,
// process management, networking) goes through these interfaces.
//
// The goal: zero exec.Command in the codebase. Native API calls only.
// Same control plane, different packet engine. A FreeBSD/pf backend
// becomes possible by implementing FirewallBackend with pf rules.
package backend

import (
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

// FirewallBackend abstracts the packet filtering engine.
// Implementations: NftablesBackend (Linux), PfBackend (FreeBSD, future).
type FirewallBackend interface {
	// Compile transforms the policy model into a backend-specific artifact.
	// The artifact is opaque to callers — it may be nftables netlink messages,
	// a pf.conf string, or eBPF bytecode.
	Compile(input *compiler.Input) (*Artifact, error)

	// Apply atomically installs the compiled artifact into the kernel.
	// On failure, the previous ruleset remains active.
	Apply(artifact *Artifact) error

	// Verify checks that the running kernel state matches the expected artifact.
	// Returns any drift detected (missing tables, extra rules, wrong counters).
	Verify(artifact *Artifact) (bool, []Drift, error)

	// Rollback reverts to a previously-compiled artifact.
	Rollback(previous *Artifact) error

	// DryRun returns a human-readable representation of what Apply would do.
	DryRun(input *compiler.Input) (string, error)

	// Capabilities reports what this backend supports.
	Capabilities() BackendCaps

	// AddToSet adds a member to a named set (e.g., an alias) without full recompile.
	AddToSet(setName string, member string) error

	// RemoveFromSet removes a member from a named set.
	RemoveFromSet(setName string, member string) error

	// FlushSet removes all members from a named set.
	FlushSet(setName string) error
}

// Artifact is the compiled output of a FirewallBackend.
// It is opaque to the rest of the system — only the backend that created it
// knows how to Apply or Rollback it.
type Artifact struct {
	// Text is the human-readable representation (for DryRun, logging, web UI).
	Text string

	// Data is the backend-specific compiled form (netlink messages, pf tokens, etc.).
	// Nil for backends that work from Text alone.
	Data any

	// Checksum is a content hash for change detection and drift verification.
	Checksum string

	// CreatedAt records when this artifact was compiled.
	CreatedAt time.Time
}

// Drift describes a single discrepancy between expected and actual state.
type Drift struct {
	Type     DriftType // What kind of drift.
	Resource string    // What resource drifted (table name, chain name, set name).
	Expected string    // What we expected.
	Actual   string    // What we found (empty if missing).
}

// DriftType classifies a drift finding.
type DriftType int

const (
	DriftMissing  DriftType = iota // Expected resource not found.
	DriftExtra                     // Unexpected resource found.
	DriftModified                  // Resource exists but differs.
)

// BackendCaps reports feature support for a firewall backend.
type BackendCaps struct {
	Name             string // "nftables", "pf", "iptables"
	Version          string // Backend version (e.g., nftables kernel version)
	Sets             bool   // Supports named sets (nftables sets, pf tables).
	IncrementalSets  bool   // Supports add/remove without full recompile.
	Flowtables       bool   // Supports hardware flow offload.
	AtomicReplace    bool   // Supports atomic full-ruleset replacement.
	NAT              bool   // Supports NAT/masquerade.
	IPv6             bool   // Supports IPv6 filtering.
	Conntrack        bool   // Supports connection tracking.
	HardwareOffload  bool   // Supports NIC hardware offload.
}

// VPNBackend abstracts VPN tunnel management.
// Implementations: WireGuardBackend (wgctrl), OpenVPNBackend (future).
type VPNBackend interface {
	// Init initializes the VPN subsystem (generate keys, create interface).
	Init() error

	// AddPeer adds a VPN peer.
	AddPeer(peer VPNPeer) error

	// RemovePeer removes a VPN peer by public key.
	RemovePeer(publicKey string) error

	// ListPeers returns all configured peers with their current status.
	ListPeers() ([]VPNPeer, error)

	// PeerStatus returns handshake timestamps and transfer stats.
	PeerStatus() ([]PeerStats, error)

	// PruneStalePeers removes peers with no handshake within maxAge.
	PruneStalePeers(maxAge time.Duration) ([]string, error)

	// GenerateKeyPair creates a new private/public key pair.
	GenerateKeyPair() (privateKey, publicKey string, err error)

	// GenerateClientConfig builds a client config for the given peer.
	GenerateClientConfig(clientPrivateKey, serverEndpoint string, peer VPNPeer) string

	// PublicKey returns the server's public key.
	PublicKey() string

	// Apply writes config and brings up the VPN interface.
	Apply() error
}

// VPNPeer is a VPN peer (backend-agnostic).
type VPNPeer struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint,omitempty"`
	Name       string `json:"name,omitempty"`
}

// PeerStats holds runtime statistics for a VPN peer.
type PeerStats struct {
	PublicKey         string    `json:"public_key"`
	LastHandshake     time.Time `json:"last_handshake"`
	TransferRx        int64     `json:"transfer_rx"`
	TransferTx        int64     `json:"transfer_tx"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

// DHCPBackend abstracts DHCP/DNS server management.
// Implementations: DnsmasqBackend, KeeaDHCPBackend (future).
type DHCPBackend interface {
	// GenerateConfig writes DHCP/DNS config from zones and devices.
	GenerateConfig(zones []model.Zone, devices []model.DeviceAssignment) error

	// Validate checks config syntax without applying.
	Validate() error

	// Reload signals the DHCP/DNS daemon to re-read config.
	Reload() error

	// Apply generates, validates, and reloads in one step.
	Apply(zones []model.Zone, devices []model.DeviceAssignment) error

	// Leases returns current DHCP leases.
	Leases() ([]DHCPLease, error)
}

// DHCPLease represents a DHCP lease (backend-agnostic).
type DHCPLease struct {
	Expiry   string `json:"expiry"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// ProcessManager abstracts process lifecycle operations.
// Replaces: kill, pidof, pkill, systemctl, rc-service.
// Implementations: OpenRCManager (Alpine), SystemdManager (Debian).
type ProcessManager interface {
	// Start starts a system service by name.
	Start(service string) error

	// Stop stops a system service by name.
	Stop(service string) error

	// Restart stops and starts a system service.
	Restart(service string) error

	// Reload sends a reload signal (SIGHUP) to a running service.
	Reload(service string) error

	// Status returns whether a service is running.
	Status(service string) (ProcessStatus, error)

	// Signal sends a signal to a process by PID.
	Signal(pid int, sig ProcessSignal) error

	// FindProcess finds a running process by name, returns its PID.
	// Uses /proc parsing, not pidof/pgrep.
	FindProcess(name string) (int, error)

	// IsRunning checks if a process with the given PID is alive.
	IsRunning(pid int) bool
}

// ProcessStatus describes the state of a managed process.
type ProcessStatus struct {
	Running bool
	PID     int
	Uptime  time.Duration
}

// ProcessSignal is a portable signal type.
type ProcessSignal int

const (
	SigHUP  ProcessSignal = 1
	SigINT  ProcessSignal = 2
	SigKILL ProcessSignal = 9
	SigTERM ProcessSignal = 15
	SigUSR1 ProcessSignal = 10
	SigUSR2 ProcessSignal = 12
)

// NetworkManager abstracts network interface operations.
// Replaces: ip link, ip addr, ip route, ip rule, bridge, sysctl.
type NetworkManager interface {
	// SysctlSet writes a sysctl value via /proc/sys.
	SysctlSet(key string, value string) error

	// SysctlGet reads a sysctl value from /proc/sys.
	SysctlGet(key string) (string, error)

	// LinkAdd creates a network interface.
	LinkAdd(name string, kind string) error

	// LinkDel deletes a network interface.
	LinkDel(name string) error

	// LinkSetUp brings an interface up.
	LinkSetUp(name string) error

	// LinkSetDown brings an interface down.
	LinkSetDown(name string) error

	// LinkSetMaster sets an interface's master (e.g., bridge port).
	LinkSetMaster(name string, master string) error

	// AddrAdd adds an IP address to an interface.
	AddrAdd(name string, cidr string) error

	// AddrFlush removes all addresses from an interface.
	AddrFlush(name string) error

	// RouteAdd adds a route.
	RouteAdd(dst string, via string, dev string) error

	// RouteDel removes a route.
	RouteDel(dst string, via string, dev string) error

	// BridgeVlanAdd adds a VLAN to a bridge.
	BridgeVlanAdd(bridge string, vid int) error

	// Ping sends ICMP echo requests and returns results.
	Ping(target string, count int, timeoutSec int) (PingResult, error)

	// Connections returns active network connections (replaces ss/netstat).
	Connections() ([]Connection, error)

	// ConntrackList returns connection tracking entries.
	ConntrackList(proto string) ([]ConntrackEntry, error)
}

// PingResult holds the result of a ping operation.
type PingResult struct {
	Sent     int
	Received int
	AvgRTT   time.Duration
	Output   string // Raw output for display.
}

// Connection represents an active network connection.
type Connection struct {
	Protocol  string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	PeerAddr  string `json:"peer_addr"`
	State     string `json:"state"`
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
}

// ConntrackEntry represents a conntrack table entry.
type ConntrackEntry struct {
	Protocol string `json:"protocol"`
	SrcAddr  string `json:"src_addr"`
	DstAddr  string `json:"dst_addr"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	State    string `json:"state"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
}

// HTTPClient abstracts HTTP operations.
// Replaces: curl shell-outs in DDNS, DNS filter, IP checks.
type HTTPClient interface {
	// Get performs an HTTP GET and returns the response body.
	Get(url string, headers map[string]string, timeoutSec int) ([]byte, int, error)

	// Put performs an HTTP PUT and returns the response body.
	Put(url string, body []byte, headers map[string]string, timeoutSec int) ([]byte, int, error)

	// Post performs an HTTP POST and returns the response body.
	Post(url string, body []byte, headers map[string]string, timeoutSec int) ([]byte, int, error)
}
