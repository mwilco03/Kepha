package service

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// NTP provides a local NTP (Network Time Protocol) server for LAN devices.
// Ensures all devices have accurate time without relying on external NTP
// servers, which is important for TLS certificate validation, logging
// correlation, and scheduled tasks.
type NTP struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewNTP(confDir string) *NTP {
	return &NTP{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (n *NTP) Name() string           { return "ntp" }
func (n *NTP) DisplayName() string    { return "NTP Server" }
func (n *NTP) Category() string       { return "network" }
func (n *NTP) Dependencies() []string { return nil }

func (n *NTP) Description() string {
	return "Local NTP time server for LAN devices. Ensures accurate time across all network devices without external dependencies."
}

func (n *NTP) DefaultConfig() map[string]string {
	return map[string]string{
		"upstream_servers": "0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org",
		"listen_address":   "",
		"allow_networks":   "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		"local_stratum":    "10",
		"rtc_sync":         "true",
	}
}

func (n *NTP) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"upstream_servers": {Description: "Comma-separated upstream NTP servers", Default: "0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org", Type: "string"},
		"listen_address":   {Description: "Address to listen on (empty = all interfaces)", Type: "string"},
		"allow_networks":   {Description: "Networks allowed to query NTP (comma-separated CIDRs)", Default: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", Type: "string"},
		"local_stratum":    {Description: "Local clock stratum when upstream unreachable", Default: "10", Type: "int"},
		"rtc_sync":         {Description: "Sync hardware RTC", Default: "true", Type: "bool"},
	}
}

func (n *NTP) Validate(cfg map[string]string) error {
	return nil
}

func (n *NTP) Start(cfg map[string]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = cfg

	if err := os.MkdirAll(n.confDir, 0o755); err != nil {
		return err
	}

	if err := n.generateConfig(); err != nil {
		return err
	}

	if err := Proc.Restart("chronyd"); err != nil {
		// Try systemd-timesyncd as fallback.
		if err2 := Proc.Restart("systemd-timesyncd"); err2 != nil {
			return fmt.Errorf("start chronyd: %v; start timesyncd: %v", err, err2)
		}
	}

	n.state = StateRunning
	return nil
}

func (n *NTP) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	Proc.Stop("chronyd")

	n.state = StateStopped
	return nil
}

func (n *NTP) Reload(cfg map[string]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = cfg

	if err := n.generateConfig(); err != nil {
		return err
	}

	if err := Proc.Reload("chronyd"); err != nil {
		// Fallback to restart if reload not supported.
		if err2 := Proc.Restart("chronyd"); err2 != nil {
			return fmt.Errorf("reload chronyd: %v", err2)
		}
	}
	return nil
}

func (n *NTP) Status() State {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

func (n *NTP) generateConfig() error {
	cfg := n.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper Chrony NTP config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	// Upstream servers.
	if servers := cfg["upstream_servers"]; servers != "" {
		for _, srv := range strings.Split(servers, ",") {
			srv = strings.TrimSpace(srv)
			if srv != "" {
				b.WriteString(fmt.Sprintf("server %s iburst\n", srv))
			}
		}
	}

	b.WriteString("\n")

	// Allow networks to be NTP clients.
	if nets := cfg["allow_networks"]; nets != "" {
		for _, net := range strings.Split(nets, ",") {
			net = strings.TrimSpace(net)
			if net != "" {
				b.WriteString(fmt.Sprintf("allow %s\n", net))
			}
		}
	}

	// Serve time even when not synchronized.
	if stratum := cfg["local_stratum"]; stratum != "" {
		b.WriteString(fmt.Sprintf("\nlocal stratum %s\n", stratum))
	}

	// Drift file and RTC.
	b.WriteString("\ndriftfile /var/lib/chrony/drift\n")
	b.WriteString("makestep 1.0 3\n")
	if cfg["rtc_sync"] == "true" {
		b.WriteString("rtcsync\n")
	}
	b.WriteString("logdir /var/log/chrony\n")

	// Listen address.
	if addr := cfg["listen_address"]; addr != "" {
		b.WriteString(fmt.Sprintf("bindaddress %s\n", addr))
	}

	confPath := filepath.Join(n.confDir, "chrony.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write chrony config: %w", err)
	}

	slog.Info("ntp config generated", "path", confPath)
	return nil
}
