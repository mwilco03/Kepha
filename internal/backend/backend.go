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
)

// Firewall is the consumer-facing interface used by the API, web UI, MCP,
// and daemon. It matches the methods that code actually calls today:
// Apply, SafeApply, DryRun, Confirm, ApplyWithConfirm.
//
// This is separate from FirewallBackend (which is the low-level compile/apply
// abstraction) because consumers don't deal with Artifacts directly.
type Firewall interface {
	// Apply compiles the current config from the store and applies it.
	Apply() error
	// SafeApply is like Apply but logs errors instead of failing hard (boot-time).
	SafeApply() error
	// DryRun compiles and returns the ruleset text without applying.
	DryRun() (string, error)
	// ApplyWithConfirm applies with auto-rollback timer.
	ApplyWithConfirm(prevRev int) error
	// Confirm stops the auto-rollback timer.
	Confirm()
}

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


// WGManager abstracts WireGuard VPN operations (H24).
// The interface uses driver.WGPeer directly to avoid import cycles.
// Implementations: driver.WireGuard.
//
// Consumers that only need peer listing and management should accept
// WGManager instead of *driver.WireGuard. This allows testing with
// mock implementations and decouples the ops layer from the driver.
//
// Note: the interface is defined here but uses types from driver/.
// This is a stepping-stone — long-term, WGPeer should move to model/.
// For now, consumers continue using *driver.WireGuard; the interface
// documents the contract for future migration.

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

// --- Network sub-interfaces (M-SA4) ---
// Split from the monolithic 31-method NetworkManager into focused interfaces.
// Consumers should depend on the narrowest interface they need.

// SysctlManager abstracts /proc/sys read/write operations.
type SysctlManager interface {
	SysctlSet(key string, value string) error
	SysctlGet(key string) (string, error)
}

// LinkManager abstracts network interface (link + address) operations.
type LinkManager interface {
	LinkList() ([]LinkInfo, error)
	LinkAdd(name string, kind string) error
	LinkDel(name string) error
	LinkSetMTU(name string, mtu int) error
	LinkGetMTU(name string) (int, error)
	LinkSetUp(name string) error
	LinkSetDown(name string) error
	LinkSetMaster(name string, master string) error
	AddrAdd(name string, cidr string) error
	AddrFlush(name string) error
}

// RouteManager abstracts routing table and policy rule operations.
type RouteManager interface {
	RouteAdd(dst string, via string, dev string) error
	RouteDel(dst string, via string, dev string) error
	RouteAddTable(dst string, via string, dev string, table int) error
	RouteFlushTable(table int) error
	RouteAddMetric(dst string, dev string, metric int) error
	RouteReplace(via string, dev string) error
	RuleAdd(oif string, table int, priority int) error
	RuleAddSrc(src string, table int, priority int) error
	RuleAddFwmark(mark uint32, table int, priority int) error
	RuleDel(table int) error
}

// BridgeManager abstracts bridge-specific operations (VLAN, STP).
type BridgeManager interface {
	BridgeVlanAdd(bridge string, vid int) error
	BridgeSetSTP(name string, enabled bool) error
	BridgeSetForwardDelay(name string, delay int) error
	BridgeSetVlanFiltering(name string, enabled bool) error
}

// DiagManager abstracts diagnostic operations (ping, connections, NIC info).
type DiagManager interface {
	Ping(target string, count int, timeoutSec int, iface string) (PingResult, error)
	Connections() ([]Connection, error)
	ConntrackList(proto string) ([]ConntrackEntry, error)
	NICInfo(iface string) (*NICInfo, error)
	SetIRQAffinity(irq int, cpuList string) error
	NICSetOffload(iface string, feature string, enabled bool) error
}

// NetworkManager is the composite interface embedding all sub-interfaces.
// Existing code can continue using NetworkManager; new code should depend
// on the narrowest sub-interface needed (e.g., SysctlManager for sysctl-only).
type NetworkManager interface {
	SysctlManager
	LinkManager
	RouteManager
	BridgeManager
	DiagManager
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

// LinkInfo holds basic attributes for a network interface as returned by LinkList.
type LinkInfo struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`        // "device", "bridge", "veth", "vlan", "loopback", etc.
	State      string   `json:"state"`        // "up", "down", "unknown"
	MTU        int      `json:"mtu"`
	MACAddress string   `json:"mac_address"`
	Addresses  []string `json:"addresses"`    // CIDRs assigned to this interface
	Master     string   `json:"master"`       // parent bridge/bond name, if any
	HasCarrier bool     `json:"has_carrier"`  // cable plugged in / link detected
}

// NICInfo holds hardware and offload details for a network interface.
type NICInfo struct {
	Name       string          `json:"name"`
	Driver     string          `json:"driver"`
	SpeedMbps  int             `json:"speed_mbps"`  // -1 = unknown
	Duplex     string          `json:"duplex"`
	MTU        int             `json:"mtu"`
	TxQueueLen int             `json:"tx_queue_len"`
	RxQueues   int             `json:"rx_queues"`
	TxQueues   int             `json:"tx_queues"`
	Offloads   map[string]bool `json:"offloads"` // tso, gro, gso, rx_checksum, tx_checksum
	IRQs       []int           `json:"irqs"`
	Stats      NICStats        `json:"stats"`
}

// NICStats holds interface-level traffic counters from sysfs.
type NICStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
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
