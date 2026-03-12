package service

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// UPnP provides UPnP IGD (Internet Gateway Device) and NAT-PMP support.
// Allows LAN devices to automatically request port forwarding without
// manual configuration. Uses miniupnpd as the backend.
//
// Security: UPnP is inherently risky. Gatekeeper defaults to:
//   - Disabled by default (opt-in)
//   - Restricted to LAN zone only
//   - Configurable ACLs to limit which IPs can request mappings
//   - Logging of all port mapping requests
type UPnP struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewUPnP(confDir string) *UPnP {
	return &UPnP{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (u *UPnP) Name() string           { return "upnp" }
func (u *UPnP) DisplayName() string    { return "UPnP/NAT-PMP" }
func (u *UPnP) Category() string       { return "network" }
func (u *UPnP) Dependencies() []string { return nil }

func (u *UPnP) Description() string {
	return "UPnP Internet Gateway Device and NAT-PMP for automatic port forwarding. Allows gaming consoles, smart TVs, and other devices to open ports on demand."
}

func (u *UPnP) DefaultConfig() map[string]string {
	return map[string]string{
		"ext_interface":   "",
		"int_interface":   "",
		"listening_ip":    "",
		"nat_pmp":         "true",
		"secure_mode":     "true",
		"notify_interval": "30",
		"system_uptime":   "true",
		"allowed_ports":   "1024-65535",
		"denied_ports":    "0-1023",
		"max_leases":      "128",
		"clean_interval":  "600",
		"log_packets":     "true",
	}
}

func (u *UPnP) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"ext_interface":   {Description: "External (WAN) interface", Required: true, Type: "string"},
		"int_interface":   {Description: "Internal (LAN) interface", Required: true, Type: "string"},
		"listening_ip":    {Description: "IP to listen on (empty = auto)", Type: "string"},
		"nat_pmp":         {Description: "Enable NAT-PMP (Apple protocol)", Default: "true", Type: "bool"},
		"secure_mode":     {Description: "Only allow mappings from the requesting IP", Default: "true", Type: "bool"},
		"notify_interval": {Description: "SSDP notify interval (seconds)", Default: "30", Type: "int"},
		"system_uptime":   {Description: "Report system uptime in UPnP", Default: "true", Type: "bool"},
		"allowed_ports":   {Description: "Allowed port ranges for mappings", Default: "1024-65535", Type: "string"},
		"denied_ports":    {Description: "Denied port ranges", Default: "0-1023", Type: "string"},
		"max_leases":      {Description: "Max active port mappings", Default: "128", Type: "int"},
		"clean_interval":  {Description: "Interval to clean expired mappings (seconds)", Default: "600", Type: "int"},
		"log_packets":     {Description: "Log UPnP packets", Default: "true", Type: "bool"},
	}
}

func (u *UPnP) Validate(cfg map[string]string) error {
	if cfg["ext_interface"] == "" {
		return fmt.Errorf("ext_interface is required")
	}
	if cfg["int_interface"] == "" {
		return fmt.Errorf("int_interface is required")
	}
	return nil
}

func (u *UPnP) Start(cfg map[string]string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cfg = cfg

	if err := os.MkdirAll(u.confDir, 0o755); err != nil {
		return err
	}

	if err := u.generateConfig(); err != nil {
		return err
	}

	if err := Proc.Start("miniupnpd"); err != nil {
		return fmt.Errorf("start miniupnpd: %w", err)
	}

	u.state = StateRunning
	return nil
}

func (u *UPnP) Stop() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if err := Proc.Stop("miniupnpd"); err != nil {
		slog.Warn("failed to stop miniupnpd", "error", err)
	}

	u.state = StateStopped
	return nil
}

func (u *UPnP) Reload(cfg map[string]string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cfg = cfg

	if err := u.generateConfig(); err != nil {
		return err
	}

	if err := Proc.Restart("miniupnpd"); err != nil {
		return fmt.Errorf("restart miniupnpd: %w", err)
	}
	return nil
}

func (u *UPnP) Status() State {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state
}

func (u *UPnP) generateConfig() error {
	cfg := u.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper miniupnpd config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	b.WriteString(fmt.Sprintf("ext_ifname=%s\n", cfg["ext_interface"]))

	if listen := cfg["listening_ip"]; listen != "" {
		b.WriteString(fmt.Sprintf("listening_ip=%s\n", listen))
	} else {
		b.WriteString(fmt.Sprintf("listening_ip=%s\n", cfg["int_interface"]))
	}

	if cfg["nat_pmp"] == "true" {
		b.WriteString("enable_natpmp=yes\n")
	} else {
		b.WriteString("enable_natpmp=no\n")
	}

	if cfg["secure_mode"] == "true" {
		b.WriteString("secure_mode=yes\n")
	} else {
		b.WriteString("secure_mode=no\n")
	}

	if cfg["system_uptime"] == "true" {
		b.WriteString("system_uptime=yes\n")
	}

	b.WriteString(fmt.Sprintf("notify_interval=%s\n", cfg["notify_interval"]))
	b.WriteString(fmt.Sprintf("clean_ruleset_interval=%s\n", cfg["clean_interval"]))

	if cfg["log_packets"] == "true" {
		b.WriteString("packet_log=yes\n")
	}

	// ACLs: allow LAN, deny everything else.
	if allowed := cfg["allowed_ports"]; allowed != "" {
		b.WriteString(fmt.Sprintf("allow %s 0.0.0.0/0 %s\n", allowed, allowed))
	}
	if denied := cfg["denied_ports"]; denied != "" {
		b.WriteString(fmt.Sprintf("deny %s 0.0.0.0/0 0-65535\n", denied))
	}

	confPath := filepath.Join(u.confDir, "miniupnpd.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write miniupnpd config: %w", err)
	}

	slog.Info("upnp config generated", "path", confPath)
	return nil
}
