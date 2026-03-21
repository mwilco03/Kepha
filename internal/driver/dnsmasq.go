package driver

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	PIDFile     string   // PID file location (must match init system).
	UpstreamDNS []string // Configurable upstream DNS servers.
	LocalDomain string   // Local domain for DNS resolution.
	PXEServer   string   // PXE server IP for dhcp-boot (empty = disabled).
}

// NewDnsmasq creates a new dnsmasq driver.
func NewDnsmasq(store *config.Store, confDir string) *Dnsmasq {
	return &Dnsmasq{
		store:       store,
		confDir:     confDir,
		PIDFile:     "/run/dnsmasq.pid",
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

	pidData, err := os.ReadFile(d.PIDFile)
	if err != nil {
		slog.Warn("dnsmasq pid file not found, skipping reload", "error", err)
		return nil
	}

	pidStr := strings.TrimSpace(string(pidData))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid PID %q in pid file", pidStr)
	}
	slog.Info("reloading dnsmasq", "pid", pid)

	// Send SIGHUP directly via native Go syscall (no exec.Command("kill")).
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find dnsmasq process %d: %w", pid, err)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("reload dnsmasq (SIGHUP): %w", err)
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
		// Validate upstream DNS to prevent config injection via newlines or special chars.
		if validate.IP(srv) != nil {
			slog.Warn("skipping invalid upstream DNS", "value", srv)
			continue
		}
		b.WriteString(fmt.Sprintf("server=%s\n", srv))
	}
	// Validate LocalDomain to prevent config injection via newlines or special chars.
	localDomain := d.LocalDomain
	if !isDNSLabel(localDomain) {
		slog.Warn("invalid local domain, falling back to default", "value", localDomain)
		localDomain = "gk.local"
	}
	b.WriteString(fmt.Sprintf("local=/%s/\n", localDomain))
	b.WriteString(fmt.Sprintf("domain=%s\n", localDomain))
	b.WriteString("expand-hosts\n")
	b.WriteString(fmt.Sprintf("conf-file=%s\n", filepath.Join(d.confDir, "static-leases.conf")))
	b.WriteString("\n")

	// PXE boot support — chainload iPXE for BIOS and UEFI clients.
	if d.PXEServer != "" && validate.IP(d.PXEServer) == nil {
		b.WriteString("# PXE boot\n")
		b.WriteString("enable-tftp\n")
		b.WriteString(fmt.Sprintf("dhcp-boot=tag:!ipxe,undionly.kpxe,pxeserver,%s\n", d.PXEServer))
		b.WriteString(fmt.Sprintf("dhcp-match=set:efi-x86_64,option:client-arch,7\n"))
		b.WriteString(fmt.Sprintf("dhcp-match=set:efi-x86_64,option:client-arch,9\n"))
		b.WriteString(fmt.Sprintf("dhcp-boot=tag:efi-x86_64,tag:!ipxe,ipxe.efi,pxeserver,%s\n", d.PXEServer))
		b.WriteString(fmt.Sprintf("dhcp-boot=tag:ipxe,http://%s/boot.ipxe\n", d.PXEServer))
		b.WriteString("dhcp-userclass=set:ipxe,iPXE\n")
		b.WriteString("\n")
	}

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

	// L5: Warn about static leases that fall within DHCP dynamic ranges.
	// dnsmasq handles this gracefully (static wins), but it's a config smell.
	for _, dev := range devices {
		if dev.IP != "" {
			ip := net.ParseIP(dev.IP)
			if ip != nil && d.isInDHCPRange(ip) {
				slog.Warn("static lease IP overlaps with DHCP dynamic range",
					"ip", dev.IP, "mac", dev.MAC, "hostname", dev.Hostname)
			}
		}
	}

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

// dnsLabelRe matches a valid DNS domain name (e.g., "gk.local", "home.lan").
var dnsLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$`)

// isDNSLabel validates a domain name for use in dnsmasq config.
// Rejects newlines, control characters, and other injection vectors.
func isDNSLabel(s string) bool {
	return s != "" && dnsLabelRe.MatchString(s) && !strings.Contains(s, "..")
}

// isInDHCPRange checks if an IP falls within any configured DHCP dynamic range.
func (d *Dnsmasq) isInDHCPRange(ip net.IP) bool {
	zones, err := d.store.ListZones()
	if err != nil {
		return false
	}
	for _, z := range zones {
		if z.NetworkCIDR == "" || z.Interface == "" || z.Name == "wan" {
			continue
		}
		dhcpRange := deriveDHCPRange(z.NetworkCIDR)
		if dhcpRange == "" {
			continue
		}
		parts := strings.Split(dhcpRange, ",")
		if len(parts) != 2 {
			continue
		}
		rangeStart := net.ParseIP(parts[0])
		rangeEnd := net.ParseIP(parts[1])
		if rangeStart == nil || rangeEnd == nil {
			continue
		}
		if bytes.Compare(ip.To4(), rangeStart.To4()) >= 0 && bytes.Compare(ip.To4(), rangeEnd.To4()) <= 0 {
			return true
		}
	}
	return false
}

// deriveDHCPRange generates a DHCP range from a CIDR, respecting prefix length.
// Uses the middle 60% of the usable address space (skips first 20% and last 20%).
func deriveDHCPRange(cidr string) string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return ""
	}

	mask := ipnet.Mask
	ones, bits := mask.Size()
	if bits != 32 || ones > 30 {
		return "" // /31 and /32 have no usable DHCP range.
	}

	// Calculate usable host range.
	networkIP := ipnet.IP.To4()
	hostBits := 32 - ones
	totalHosts := (1 << hostBits) - 2 // Exclude network and broadcast.
	if totalHosts < 4 {
		return "" // Too small for a meaningful DHCP range.
	}

	// Start at 20% into the range, end at 80%.
	startOffset := totalHosts / 5
	if startOffset < 1 {
		startOffset = 1
	}
	endOffset := totalHosts * 4 / 5
	if endOffset > totalHosts {
		endOffset = totalHosts
	}

	startIP := make(net.IP, 4)
	copy(startIP, networkIP)
	addToIP(startIP, startOffset)

	endIP := make(net.IP, 4)
	copy(endIP, networkIP)
	addToIP(endIP, endOffset)

	return fmt.Sprintf("%s,%s", startIP.String(), endIP.String())
}

// addToIP adds n to an IPv4 address in place.
func addToIP(ip net.IP, n int) {
	for i := 3; i >= 0 && n > 0; i-- {
		sum := int(ip[i]) + n
		ip[i] = byte(sum & 0xff)
		n = sum >> 8
	}
}
