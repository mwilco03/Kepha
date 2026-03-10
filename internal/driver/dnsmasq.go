package driver

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"strconv"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// Dnsmasq manages dnsmasq configuration for DHCP and DNS.
type Dnsmasq struct {
	mu          sync.Mutex
	store       *config.Store
	confDir     string
	pidFile     string
	UpstreamDNS []string // Configurable upstream DNS servers.
	LocalDomain string   // Local domain for DNS resolution.
}

// NewDnsmasq creates a new dnsmasq driver.
func NewDnsmasq(store *config.Store, confDir string) *Dnsmasq {
	return &Dnsmasq{
		store:       store,
		confDir:     confDir,
		pidFile:     filepath.Join(confDir, "dnsmasq.pid"),
		UpstreamDNS: []string{"1.1.1.1", "8.8.8.8"},
		LocalDomain: "gk.local",
	}
}

// GenerateConfig writes dnsmasq configuration files from the current config.
func (d *Dnsmasq) GenerateConfig() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := os.MkdirAll(d.confDir, 0o750); err != nil {
		return fmt.Errorf("create conf dir: %w", err)
	}

	zones, err := d.store.ListZones()
	if err != nil {
		return fmt.Errorf("list zones: %w", err)
	}

	devices, err := d.store.ListDevices()
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}

	conf := d.buildMainConfig(zones)
	confPath := filepath.Join(d.confDir, "dnsmasq.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o640); err != nil {
		return fmt.Errorf("write dnsmasq.conf: %w", err)
	}

	hostsConf := d.buildStaticLeases(devices)
	hostsPath := filepath.Join(d.confDir, "static-leases.conf")
	if err := os.WriteFile(hostsPath, []byte(hostsConf), 0o640); err != nil {
		return fmt.Errorf("write static-leases.conf: %w", err)
	}

	slog.Info("dnsmasq config generated", "path", confPath)
	return nil
}

// Reload sends SIGHUP to dnsmasq to reload configuration.
func (d *Dnsmasq) Reload() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	pidData, err := os.ReadFile(d.pidFile)
	if err != nil {
		slog.Warn("dnsmasq pid file not found, skipping reload", "error", err)
		return nil
	}

	pid := strings.TrimSpace(string(pidData))
	if _, err := strconv.Atoi(pid); err != nil {
		return fmt.Errorf("invalid PID %q in pid file", pid)
	}
	slog.Info("reloading dnsmasq", "pid", pid)

	cmd := exec.Command("kill", "-HUP", pid)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reload dnsmasq: %s: %w", string(output), err)
	}
	return nil
}

// Apply generates config, validates it, and reloads dnsmasq.
func (d *Dnsmasq) Apply() error {
	if err := d.GenerateConfig(); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return err
	}
	return d.Reload()
}

// Validate checks dnsmasq config syntax before reload.
func (d *Dnsmasq) Validate() error {
	confPath := filepath.Join(d.confDir, "dnsmasq.conf")
	cmd := exec.Command("dnsmasq", "--test", "--conf-file="+confPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dnsmasq config invalid: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// ParseLeaseFile reads the dnsmasq lease file and returns active leases.
func (d *Dnsmasq) ParseLeaseFile(leasePath string) ([]Lease, error) {
	data, err := os.ReadFile(leasePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var leases []Lease
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		leases = append(leases, Lease{
			Expiry:   fields[0],
			MAC:      fields[1],
			IP:       fields[2],
			Hostname: fields[3],
		})
	}
	return leases, nil
}

// Lease represents a DHCP lease.
type Lease struct {
	Expiry   string `json:"expiry"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// SignalReload sends SIGHUP to a running dnsmasq process by PID.
func SignalReload(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGHUP)
}

func (d *Dnsmasq) buildMainConfig(zones []model.Zone) string {
	var b strings.Builder

	b.WriteString("# Gatekeeper auto-generated dnsmasq config\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	b.WriteString("# Global settings\n")
	b.WriteString("bind-dynamic\n")
	b.WriteString("listen-address=127.0.0.1\n")
	b.WriteString("domain-needed\n")
	b.WriteString("bogus-priv\n")
	b.WriteString("no-resolv\n")
	b.WriteString("log-queries\n")
	b.WriteString("log-dhcp\n")
	for _, srv := range d.UpstreamDNS {
		b.WriteString(fmt.Sprintf("server=%s\n", srv))
	}
	b.WriteString(fmt.Sprintf("local=/%s/\n", d.LocalDomain))
	b.WriteString(fmt.Sprintf("domain=%s\n", d.LocalDomain))
	b.WriteString("expand-hosts\n")
	b.WriteString(fmt.Sprintf("pid-file=%s\n", d.pidFile))
	b.WriteString(fmt.Sprintf("conf-file=%s\n", filepath.Join(d.confDir, "static-leases.conf")))
	b.WriteString("\n")

	// Per-zone DHCP ranges (skip WAN).
	for _, z := range zones {
		if z.Name == "wan" || z.NetworkCIDR == "" || z.Interface == "" {
			continue
		}
		// Parse CIDR to generate DHCP range.
		dhcpRange := deriveDHCPRange(z.NetworkCIDR)
		if dhcpRange != "" && validate.Interface(z.Interface) == nil {
			b.WriteString(fmt.Sprintf("# Zone: %s\n", z.Name))
			b.WriteString(fmt.Sprintf("interface=%s\n", z.Interface))
			b.WriteString(fmt.Sprintf("dhcp-range=interface:%s,%s,12h\n", z.Interface, dhcpRange))
			b.WriteString("\n")
		}
	}

	return b.String()
}

func (d *Dnsmasq) buildStaticLeases(devices []model.DeviceAssignment) string {
	var b strings.Builder

	b.WriteString("# Gatekeeper static DHCP leases\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	for _, dev := range devices {
		// Skip entries with invalid fields.
		if validate.IP(dev.IP) != nil {
			continue
		}
		if dev.MAC != "" && validate.MAC(dev.MAC) != nil {
			continue
		}
		if dev.Hostname != "" && validate.Hostname(dev.Hostname) != nil {
			continue
		}

		if dev.MAC != "" && dev.IP != "" {
			hostname := dev.Hostname
			if hostname == "" {
				hostname = strings.ReplaceAll(dev.IP, ".", "-")
			}
			b.WriteString(fmt.Sprintf("dhcp-host=%s,%s,%s\n", dev.MAC, dev.IP, hostname))
		} else if dev.IP != "" && dev.Hostname != "" {
			// DNS-only entry (no MAC for static lease).
			b.WriteString(fmt.Sprintf("address=/%s.%s/%s\n", dev.Hostname, d.LocalDomain, dev.IP))
		}
	}

	return b.String()
}

// deriveDHCPRange generates a DHCP range from a CIDR.
// For x.x.x.0/24, returns "x.x.x.100,x.x.x.250".
func deriveDHCPRange(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return ""
	}
	ip := parts[0]
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return ""
	}
	prefix := strings.Join(octets[:3], ".")
	return fmt.Sprintf("%s.100,%s.250", prefix, prefix)
}
