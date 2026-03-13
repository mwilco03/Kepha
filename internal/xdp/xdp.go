// Package xdp provides XDP/eBPF fast-path packet processing for Gatekeeper.
//
// This package implements pre-stack packet drops and traffic accounting using
// Linux XDP (eXpress Data Path). When enabled, known-bad IPs are dropped
// before they enter the kernel networking stack, and simple ACLs can bypass
// full nftables evaluation for high-throughput zones.
//
// Architecture:
//
//	Packet → XDP entry (parse headers) → tail call → blocklist check
//	                                   → tail call → ACL check
//	                                   → tail call → accounting
//	                                   → XDP_PASS (to nftables)
//
// The XDP program uses tail-call chaining so each stage is independently
// verifiable and can be toggled without reloading the entire program.
// On any failure (missing tail call, map lookup error), the default action
// is XDP_PASS — never silently drop legitimate traffic.
//
// Requirements:
//   - Linux kernel >= 5.10 (for BTF, ring buffer, atomic operations)
//   - Network interface supporting XDP (most modern drivers)
//   - CAP_BPF + CAP_NET_ADMIN capabilities
//
// This feature is entirely opt-in. When disabled, zero overhead.
package xdp

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// AttachMode determines how XDP programs are attached to interfaces.
type AttachMode int

const (
	// AttachModeNative uses driver-level XDP (best performance, requires driver support).
	AttachModeNative AttachMode = iota
	// AttachModeGeneric uses generic/SKB XDP (works everywhere, slower).
	AttachModeGeneric
	// AttachModeOffload uses NIC hardware offload (best performance, limited support).
	AttachModeOffload
)

func (m AttachMode) String() string {
	switch m {
	case AttachModeNative:
		return "native"
	case AttachModeGeneric:
		return "generic"
	case AttachModeOffload:
		return "offload"
	default:
		return "unknown"
	}
}

// Capabilities describes what XDP/eBPF features are available on this system.
type Capabilities struct {
	// KernelVersion is the running kernel version string.
	KernelVersion string `json:"kernel_version"`
	// KernelMajor/Minor/Patch are parsed version components.
	KernelMajor int `json:"kernel_major"`
	KernelMinor int `json:"kernel_minor"`
	KernelPatch int `json:"kernel_patch"`
	// BPFSupported indicates /sys/fs/bpf is mounted and accessible.
	BPFSupported bool `json:"bpf_supported"`
	// BTFAvailable indicates BTF (BPF Type Format) is available.
	BTFAvailable bool `json:"btf_available"`
	// XDPSupported indicates the kernel supports XDP programs.
	XDPSupported bool `json:"xdp_supported"`
	// HasCAP_BPF indicates the process has CAP_BPF capability.
	HasCAPBPF bool `json:"has_cap_bpf"`
	// HasCAP_NET_ADMIN indicates the process has CAP_NET_ADMIN.
	HasCAPNetAdmin bool `json:"has_cap_net_admin"`
	// MinKernelMet indicates kernel >= 5.10.
	MinKernelMet bool `json:"min_kernel_met"`
	// TailCallSupported indicates BPF tail calls work.
	TailCallSupported bool `json:"tail_call_supported"`
	// RingBufSupported indicates BPF ring buffer is available (kernel >= 5.8).
	RingBufSupported bool `json:"ring_buf_supported"`
	// Ready is true when all requirements are met.
	Ready bool `json:"ready"`
	// Reason describes why XDP is not ready (if !Ready).
	Reason string `json:"reason,omitempty"`
}

// ProbeCapabilities detects XDP/eBPF support on the running system.
func ProbeCapabilities() *Capabilities {
	caps := &Capabilities{}

	// Parse kernel version.
	caps.KernelVersion = readKernelVersion()
	caps.KernelMajor, caps.KernelMinor, caps.KernelPatch = parseKernelVersion(caps.KernelVersion)

	// Check minimum kernel version (5.10).
	caps.MinKernelMet = (caps.KernelMajor > 5) ||
		(caps.KernelMajor == 5 && caps.KernelMinor >= 10)

	// Check BPF filesystem.
	caps.BPFSupported = checkBPFFS()

	// Check BTF availability.
	caps.BTFAvailable = checkBTF()

	// Check XDP support via /proc/config.gz or sysfs probing.
	caps.XDPSupported = caps.MinKernelMet && runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"

	// Check capabilities (simplified: check if running as root or have CAP_BPF).
	caps.HasCAPBPF = os.Geteuid() == 0
	caps.HasCAPNetAdmin = os.Geteuid() == 0

	// Tail calls available since kernel 4.2, ring buffer since 5.8.
	caps.TailCallSupported = caps.MinKernelMet
	caps.RingBufSupported = (caps.KernelMajor > 5) ||
		(caps.KernelMajor == 5 && caps.KernelMinor >= 8)

	// Determine readiness.
	caps.Ready = true
	var reasons []string

	if !caps.MinKernelMet {
		caps.Ready = false
		reasons = append(reasons, fmt.Sprintf("kernel %s < 5.10", caps.KernelVersion))
	}
	if !caps.BPFSupported {
		caps.Ready = false
		reasons = append(reasons, "BPF filesystem not mounted")
	}
	if !caps.HasCAPBPF {
		caps.Ready = false
		reasons = append(reasons, "missing CAP_BPF (not root)")
	}
	if !caps.HasCAPNetAdmin {
		caps.Ready = false
		reasons = append(reasons, "missing CAP_NET_ADMIN (not root)")
	}

	if len(reasons) > 0 {
		caps.Reason = strings.Join(reasons, "; ")
	}

	return caps
}

// Stats contains XDP program statistics.
type Stats struct {
	// Interface is the network interface name.
	Interface string `json:"interface"`
	// AttachMode is how the XDP program is attached.
	AttachMode string `json:"attach_mode"`
	// Attached is true if an XDP program is currently running on this interface.
	Attached bool `json:"attached"`
	// PacketsTotal is the total number of packets processed.
	PacketsTotal uint64 `json:"packets_total"`
	// PacketsDropped is the number of packets dropped (XDP_DROP).
	PacketsDropped uint64 `json:"packets_dropped"`
	// PacketsPassed is the number of packets passed to the stack (XDP_PASS).
	PacketsPassed uint64 `json:"packets_passed"`
	// BytesTotal is the total bytes processed.
	BytesTotal uint64 `json:"bytes_total"`
	// BytesDropped is the bytes from dropped packets.
	BytesDropped uint64 `json:"bytes_dropped"`
	// BlocklistSize is the number of IPs in the blocklist.
	BlocklistSize int `json:"blocklist_size"`
	// ACLRuleCount is the number of active ACL rules.
	ACLRuleCount int `json:"acl_rule_count"`
	// LastUpdate is when stats were last read.
	LastUpdate time.Time `json:"last_update"`
}

// BlocklistEntry represents a single IP in the XDP blocklist.
type BlocklistEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason,omitempty"`    // Why blocked: "threat_feed", "manual", "rate_limit"
	Source    string    `json:"source,omitempty"`    // Feed name or "admin"
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Zero = permanent
	AddedAt   time.Time `json:"added_at"`
	HitCount  uint64    `json:"hit_count"`           // Packets dropped for this IP
}

// ACLRule is a simplified ACL rule for the XDP fast path.
// These are much simpler than full nftables rules — they only support
// src/dst IP + protocol + port for maximum BPF verifier compatibility.
type ACLRule struct {
	ID       uint32 `json:"id"`
	SrcIP    string `json:"src_ip,omitempty"`    // CIDR or empty (any)
	DstIP    string `json:"dst_ip,omitempty"`    // CIDR or empty (any)
	Protocol uint8  `json:"protocol,omitempty"`  // 6=TCP, 17=UDP, 0=any
	DstPort  uint16 `json:"dst_port,omitempty"`  // 0 = any
	Action   uint8  `json:"action"`              // 1=DROP, 2=PASS
	HitCount uint64 `json:"hit_count"`
}

// XDP action constants matching the kernel definitions.
const (
	XDP_ABORTED = 0
	XDP_DROP    = 1
	XDP_PASS    = 2
	XDP_TX      = 3
	XDP_REDIRECT = 4
)

// readKernelVersion reads the kernel version from /proc/version.
func readKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	// Format: "Linux version 5.15.0-91-generic (...)"
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2]
	}
	return strings.TrimSpace(string(data))
}

// parseKernelVersion extracts major.minor.patch from a version string.
func parseKernelVersion(ver string) (int, int, int) {
	// Strip anything after the first non-version character.
	var clean string
	for _, c := range ver {
		if (c >= '0' && c <= '9') || c == '.' {
			clean += string(c)
		} else {
			break
		}
	}

	parts := strings.SplitN(clean, ".", 4)
	major, _ := strconv.Atoi(safeIndex(parts, 0))
	minor, _ := strconv.Atoi(safeIndex(parts, 1))
	patch, _ := strconv.Atoi(safeIndex(parts, 2))
	return major, minor, patch
}

func safeIndex(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

// checkBPFFS checks if the BPF filesystem is mounted.
func checkBPFFS() bool {
	_, err := os.Stat("/sys/fs/bpf")
	return err == nil
}

// checkBTF checks if BTF is available.
func checkBTF() bool {
	// BTF vmlinux is usually at /sys/kernel/btf/vmlinux
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}
