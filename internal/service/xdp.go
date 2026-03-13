package service

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/gatekeeper-firewall/gatekeeper/internal/xdp"
)

// XDPService provides XDP/eBPF fast-path packet processing.
//
// When enabled, it attaches XDP programs to configured interfaces for
// pre-stack IP blocklist drops, simple ACL enforcement, and traffic
// accounting. This runs before the kernel networking stack and nftables,
// providing maximum throughput for known-good/known-bad traffic decisions.
//
// This service is entirely opt-in. When disabled, zero overhead.
type XDPService struct {
	mu      sync.Mutex
	state   State
	cfg     map[string]string
	manager *xdp.Manager
}

// NewXDPService creates a new XDP service.
func NewXDPService() *XDPService {
	return &XDPService{
		state:   StateStopped,
		manager: xdp.NewManager(),
	}
}

func (x *XDPService) Name() string        { return "xdp" }
func (x *XDPService) DisplayName() string  { return "XDP Fast Path" }
func (x *XDPService) Category() string     { return "performance" }
func (x *XDPService) Dependencies() []string { return nil }

func (x *XDPService) Description() string {
	return "XDP/eBPF pre-stack packet processing. IP blocklist drops, simple ACL enforcement, and traffic accounting before packets reach the kernel networking stack."
}

func (x *XDPService) DefaultConfig() map[string]string {
	return map[string]string{
		"interfaces":  "",       // Comma-separated (empty = auto-detect non-loopback)
		"mode":        "auto",   // "auto", "native", "generic", "offload"
		"blocklist":   "",       // Path to IP blocklist file (one IP/CIDR per line)
		"auto_block":  "false",  // Auto-block IPs from fingerprint threat matches
		"max_entries": "1000000", // Max blocklist entries
	}
}

func (x *XDPService) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"interfaces": {
			Description: "Comma-separated list of interfaces for XDP attachment. Empty = all non-loopback.",
			Default:     "",
			Type:        "string",
		},
		"mode": {
			Description: "XDP attach mode: auto (probe native, fallback to generic), native, generic, offload.",
			Default:     "auto",
			Type:        "string",
		},
		"blocklist": {
			Description: "Path to a text file with one IP or CIDR per line to block at XDP level.",
			Default:     "",
			Type:        "path",
		},
		"auto_block": {
			Description: "Automatically add IPs from threat feed matches to the XDP blocklist.",
			Default:     "false",
			Type:        "bool",
		},
		"max_entries": {
			Description: "Maximum number of blocklist entries (controls BPF map size).",
			Default:     "1000000",
			Type:        "int",
		},
	}
}

func (x *XDPService) Validate(cfg map[string]string) error {
	if mode, ok := cfg["mode"]; ok {
		switch mode {
		case "auto", "native", "generic", "offload":
		default:
			return fmt.Errorf("invalid mode: %q (must be auto, native, generic, or offload)", mode)
		}
	}
	if ab, ok := cfg["auto_block"]; ok {
		if ab != "true" && ab != "false" {
			return fmt.Errorf("auto_block must be true or false")
		}
	}
	return nil
}

func (x *XDPService) Start(cfg map[string]string) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.state == StateRunning {
		return nil
	}

	x.cfg = cfg

	// Probe capabilities.
	caps := x.manager.Probe()
	if !caps.Ready {
		slog.Warn("XDP not fully available, running in monitoring-only mode",
			"reason", caps.Reason)
	}

	// Set attach mode.
	mode := cfg["mode"]
	switch mode {
	case "native":
		x.manager.SetMode(xdp.AttachModeNative)
	case "offload":
		x.manager.SetMode(xdp.AttachModeOffload)
	case "generic":
		x.manager.SetMode(xdp.AttachModeGeneric)
	default: // "auto"
		if caps.Ready {
			x.manager.SetMode(xdp.AttachModeNative)
		} else {
			x.manager.SetMode(xdp.AttachModeGeneric)
		}
	}

	// Determine interfaces.
	ifaces := parseInterfaces(cfg["interfaces"])
	if len(ifaces) == 0 {
		ifaces = detectNonLoopback()
	}

	// Register interfaces (actual BPF attach happens when a BPFLoader is provided).
	for _, ifName := range ifaces {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			slog.Warn("interface not found for XDP", "interface", ifName, "error", err)
			continue
		}
		if err := x.manager.AttachInterface(ifName, iface.Index); err != nil {
			slog.Error("failed to register XDP interface", "interface", ifName, "error", err)
		}
	}

	slog.Info("XDP fast path started",
		"interfaces", ifaces,
		"mode", cfg["mode"],
		"capabilities", caps.Ready,
	)

	x.state = StateRunning
	return nil
}

func (x *XDPService) Stop() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.state != StateRunning {
		return nil
	}

	// Detach all interfaces.
	for _, iface := range x.manager.AttachedInterfaces() {
		if err := x.manager.DetachInterface(iface.Name); err != nil {
			slog.Error("failed to detach XDP", "interface", iface.Name, "error", err)
		}
	}

	slog.Info("XDP fast path stopped")
	x.state = StateStopped
	return nil
}

func (x *XDPService) Reload(cfg map[string]string) error {
	if err := x.Stop(); err != nil {
		return err
	}
	return x.Start(cfg)
}

func (x *XDPService) Status() State {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.state
}

// Manager returns the XDP manager for direct access from API/CLI.
func (x *XDPService) Manager() *xdp.Manager {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.manager
}

func parseInterfaces(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name != "" {
			result = append(result, name)
		}
	}
	return result
}

func detectNonLoopback() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		result = append(result, iface.Name)
	}
	return result
}
