package service

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Avahi provides mDNS/DNS-SD (multicast DNS service discovery) on the LAN.
// Enables .local hostname resolution and service advertisement so devices
// can find the gateway and advertised services (SMB shares, printers, etc.)
// without manual DNS configuration.
type Avahi struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewAvahi(confDir string) *Avahi {
	return &Avahi{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (a *Avahi) Name() string           { return "avahi" }
func (a *Avahi) DisplayName() string    { return "Avahi (mDNS/DNS-SD)" }
func (a *Avahi) Category() string       { return "discovery" }
func (a *Avahi) Dependencies() []string { return nil }

func (a *Avahi) Description() string {
	return "Multicast DNS and service discovery. Enables .local hostname resolution and automatic service advertisement on the LAN."
}

func (a *Avahi) DefaultConfig() map[string]string {
	return map[string]string{
		"hostname":            "",
		"domain_name":         "local",
		"browse_domains":      "",
		"use_ipv4":            "true",
		"use_ipv6":            "false",
		"allow_interfaces":    "",
		"deny_interfaces":     "",
		"publish_addresses":   "true",
		"publish_hinfo":       "false",
		"publish_workstation": "false",
		"reflect_mdns":        "false",
	}
}

func (a *Avahi) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"hostname":            {Description: "Hostname to publish (empty = system hostname)", Type: "string"},
		"domain_name":         {Description: "mDNS domain (usually 'local')", Default: "local", Type: "string"},
		"browse_domains":      {Description: "Additional browse domains, comma-separated", Type: "string"},
		"use_ipv4":            {Description: "Enable IPv4 mDNS", Default: "true", Type: "bool"},
		"use_ipv6":            {Description: "Enable IPv6 mDNS", Default: "false", Type: "bool"},
		"allow_interfaces":    {Description: "Interfaces to allow (comma-separated, empty = all LAN)", Type: "string"},
		"deny_interfaces":     {Description: "Interfaces to deny (comma-separated)", Type: "string"},
		"publish_addresses":   {Description: "Publish address records for this host", Default: "true", Type: "bool"},
		"publish_hinfo":       {Description: "Publish host info record", Default: "false", Type: "bool"},
		"publish_workstation": {Description: "Publish workstation service", Default: "false", Type: "bool"},
		"reflect_mdns":        {Description: "Reflect mDNS between interfaces (cross-subnet discovery)", Default: "false", Type: "bool"},
	}
}

func (a *Avahi) Validate(cfg map[string]string) error {
	if domain := cfg["domain_name"]; domain != "" && domain != "local" {
		if strings.Contains(domain, " ") {
			return fmt.Errorf("invalid domain_name: %s", domain)
		}
	}
	return nil
}

func (a *Avahi) Start(cfg map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg

	if err := os.MkdirAll(a.confDir, 0o755); err != nil {
		return err
	}

	if err := a.generateConfig(); err != nil {
		return err
	}

	// Restart avahi-daemon to pick up new config.
	if err := a.restartDaemon(); err != nil {
		return err
	}

	a.state = StateRunning
	return nil
}

func (a *Avahi) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := Proc.Stop("avahi-daemon"); err != nil {
		slog.Warn("failed to stop avahi-daemon", "error", err)
	}

	a.state = StateStopped
	return nil
}

func (a *Avahi) Reload(cfg map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg

	if err := a.generateConfig(); err != nil {
		return err
	}
	return a.restartDaemon()
}

func (a *Avahi) Status() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

func (a *Avahi) generateConfig() error {
	cfg := a.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper Avahi config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	b.WriteString("[server]\n")
	if hostname := cfg["hostname"]; hostname != "" {
		b.WriteString(fmt.Sprintf("host-name=%s\n", hostname))
	}
	domain := cfg["domain_name"]
	if domain == "" {
		domain = "local"
	}
	b.WriteString(fmt.Sprintf("domain-name=%s\n", domain))

	if cfg["use_ipv4"] == "true" {
		b.WriteString("use-ipv4=yes\n")
	} else {
		b.WriteString("use-ipv4=no\n")
	}
	if cfg["use_ipv6"] == "true" {
		b.WriteString("use-ipv6=yes\n")
	} else {
		b.WriteString("use-ipv6=no\n")
	}

	if ifaces := cfg["allow_interfaces"]; ifaces != "" {
		for _, iface := range strings.Split(ifaces, ",") {
			iface = strings.TrimSpace(iface)
			if iface != "" {
				b.WriteString(fmt.Sprintf("allow-interfaces=%s\n", iface))
			}
		}
	}
	if ifaces := cfg["deny_interfaces"]; ifaces != "" {
		for _, iface := range strings.Split(ifaces, ",") {
			iface = strings.TrimSpace(iface)
			if iface != "" {
				b.WriteString(fmt.Sprintf("deny-interfaces=%s\n", iface))
			}
		}
	}

	if browse := cfg["browse_domains"]; browse != "" {
		for _, d := range strings.Split(browse, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				b.WriteString(fmt.Sprintf("browse-domains=%s\n", d))
			}
		}
	}

	b.WriteString("\n[wide-area]\nenable-wide-area=no\n")

	b.WriteString("\n[publish]\n")
	if cfg["publish_addresses"] == "true" {
		b.WriteString("publish-addresses=yes\n")
	} else {
		b.WriteString("publish-addresses=no\n")
	}
	if cfg["publish_hinfo"] == "true" {
		b.WriteString("publish-hinfo=yes\n")
	} else {
		b.WriteString("publish-hinfo=no\n")
	}
	if cfg["publish_workstation"] == "true" {
		b.WriteString("publish-workstation=yes\n")
	} else {
		b.WriteString("publish-workstation=no\n")
	}

	b.WriteString("\n[reflector]\n")
	if cfg["reflect_mdns"] == "true" {
		b.WriteString("enable-reflector=yes\n")
	} else {
		b.WriteString("enable-reflector=no\n")
	}

	b.WriteString("\n[rlimits]\nrlimit-core=0\nrlimit-data=4194304\nrlimit-fsize=0\nrlimit-nofile=768\nrlimit-stack=4194304\nrlimit-nproc=3\n")

	confPath := filepath.Join(a.confDir, "avahi-daemon.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write avahi config: %w", err)
	}

	slog.Info("avahi config generated", "path", confPath)
	return nil
}

func (a *Avahi) restartDaemon() error {
	if err := Proc.Restart("avahi-daemon"); err != nil {
		return fmt.Errorf("restart avahi-daemon: %w", err)
	}
	return nil
}

// PublishService creates a static service file for avahi to advertise.
func (a *Avahi) PublishService(name, svcType string, port int, txtRecords []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	servicesDir := filepath.Join(a.confDir, "services")
	if err := os.MkdirAll(servicesDir, 0o755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" standalone='no'?>\n")
	b.WriteString("<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">\n")
	b.WriteString("<service-group>\n")
	b.WriteString(fmt.Sprintf("  <name replace-wildcards=\"yes\">%s on %%h</name>\n", name))
	b.WriteString("  <service>\n")
	b.WriteString(fmt.Sprintf("    <type>%s</type>\n", svcType))
	b.WriteString(fmt.Sprintf("    <port>%d</port>\n", port))
	for _, txt := range txtRecords {
		b.WriteString(fmt.Sprintf("    <txt-record>%s</txt-record>\n", txt))
	}
	b.WriteString("  </service>\n")
	b.WriteString("</service-group>\n")

	filename := strings.ReplaceAll(name, " ", "-") + ".service"
	path := filepath.Join(servicesDir, filename)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
