// Package ipv6 provides IPv6 dual-stack support utilities for Gatekeeper.
//
// This package adds IPv6 address handling, dual-stack zone configuration,
// Router Advertisement (RA) service management via radvd, NDP proxy helpers,
// IPv6 firewall rule generation, and dual-stack validation. It enables
// Gatekeeper to operate as a full dual-stack firewall/router.
package ipv6

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
)

// Proc is the package-level ProcessManager for IPv6 service management.
// Set via SetProcessManager from the daemon.
var Proc backend.ProcessManager

// SetProcessManager sets the process manager for this package.
func SetProcessManager(pm backend.ProcessManager) {
	Proc = pm
}

// State and ConfigField are duplicated across ha, ipv6, and service packages.
// Consolidation blocked by import cycle (service → ipv6 → service via wrappers).
// Kept in sync by convention (M-SA1).
// TODO: move to internal/model when wrapper coupling is resolved.
type State string

const (
	StateStopped State = "stopped"
	StateRunning State = "running"
	StateError   State = "error"
)

type ConfigField struct {
	Description string `json:"description"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`
}

// Address family constants returned by ParseCIDR.
const (
	FamilyIPv4 = 4
	FamilyIPv6 = 6
)

// IPv6 address modes for dual-stack zones.
const (
	ModeSLAAC  = "slaac"
	ModeDHCPv6 = "dhcpv6"
	ModeStatic = "static"
)

// radvd paths.
const (
	radvdConfPath   = "/etc/radvd.conf"
	radvdServiceNam = "radvd"
)

// ---------------------------------------------------------------------------
// Address handling
// ---------------------------------------------------------------------------

// IsIPv6 reports whether addr is a valid IPv6 address (without port or CIDR).
func IsIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// IsIPv4 reports whether addr is a valid IPv4 address (without port or CIDR).
func IsIPv4(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

// ParseCIDR parses a CIDR string and returns the host IP, network, address
// family (4 or 6), and any error.
func ParseCIDR(cidr string) (ip net.IP, network *net.IPNet, family int, err error) {
	ip, network, err = net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if ip.To4() != nil {
		family = FamilyIPv4
	} else {
		family = FamilyIPv6
	}
	return ip, network, family, nil
}

// NormalizeCIDR returns the canonical form of a CIDR string.
// For IPv6, this collapses zero runs (e.g. "fd00:0000::/64" -> "fd00::/64").
// For IPv4, it returns the standard form. Returns the input unchanged on error.
func NormalizeCIDR(cidr string) string {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	ones, _ := network.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones)
}

// ExpandIPv6 returns the full 39-character representation of an IPv6 address
// with all groups explicitly shown (e.g. "::1" -> "0000:0000:0000:0000:0000:0000:0000:0001").
// Returns the input unchanged if it is not a valid IPv6 address.
func ExpandIPv6(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	// Ensure we work with the 16-byte form.
	ip6 := ip.To16()
	if ip6 == nil {
		return addr
	}
	// If this is actually an IPv4 address, return as-is.
	if ip.To4() != nil {
		return addr
	}
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		groups[i] = fmt.Sprintf("%02x%02x", ip6[i*2], ip6[i*2+1])
	}
	return strings.Join(groups, ":")
}

// ---------------------------------------------------------------------------
// Dual-stack zone support
// ---------------------------------------------------------------------------

// DualStackZone defines a network zone that carries both an IPv4 and IPv6
// prefix. It is the configuration primitive for dual-stack operation.
type DualStackZone struct {
	// Name is the zone identifier (e.g. "lan", "guest").
	Name string `json:"name"`
	// Interface is the network interface bound to this zone.
	Interface string `json:"interface"`
	// IPv4CIDR is the IPv4 prefix assigned to this zone (e.g. "192.168.1.0/24").
	IPv4CIDR string `json:"ipv4_cidr"`
	// IPv6CIDR is the IPv6 prefix assigned to this zone (e.g. "fd00::/64").
	IPv6CIDR string `json:"ipv6_cidr"`
	// IPv6Mode is the address-assignment mode: "slaac", "dhcpv6", or "static".
	IPv6Mode string `json:"ipv6_mode"`
}

// ---------------------------------------------------------------------------
// Router Advertisement service
// ---------------------------------------------------------------------------

// RouterAdvertisement manages the radvd daemon which sends IPv6 Router
// Advertisements on configured interfaces. It implements the service.Service
// interface so it can be registered with the service manager.
type RouterAdvertisement struct {
	mu    sync.Mutex
	state State
	cfg   map[string]string
}

// NewRouterAdvertisement creates a new RA service instance.
func NewRouterAdvertisement() *RouterAdvertisement {
	return &RouterAdvertisement{
		state: StateStopped,
	}
}

func (r *RouterAdvertisement) Name() string        { return "router-advertisement" }
func (r *RouterAdvertisement) DisplayName() string  { return "IPv6 Router Advertisements" }
func (r *RouterAdvertisement) Category() string     { return "network" }
func (r *RouterAdvertisement) Dependencies() []string { return nil }

func (r *RouterAdvertisement) Description() string {
	return "Manages IPv6 Router Advertisement (RA) daemon (radvd) for SLAAC and stateless DHCPv6 autoconfiguration on LAN interfaces."
}

func (r *RouterAdvertisement) DefaultConfig() map[string]string {
	return map[string]string{
		"enabled_interfaces": "",
		"prefix":             "fd00::/64",
		"ra_interval":        "600",
		"managed_flag":       "false",
		"other_config_flag":  "false",
		"rdnss":              "",
		"mtu":                "",
		"default_lifetime":   "1800",
	}
}

func (r *RouterAdvertisement) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"enabled_interfaces": {Description: "Comma-separated interfaces to send RAs on", Required: true, Type: "string"},
		"prefix":             {Description: "IPv6 prefix to advertise (e.g. fd00::/64)", Default: "fd00::/64", Required: true, Type: "cidr"},
		"ra_interval":        {Description: "Router Advertisement interval in seconds", Default: "600", Type: "int"},
		"managed_flag":       {Description: "Set the M (Managed Address) flag for DHCPv6", Default: "false", Type: "bool"},
		"other_config_flag":  {Description: "Set the O (Other Configuration) flag for DHCPv6", Default: "false", Type: "bool"},
		"rdnss":              {Description: "Recursive DNS server address(es), comma-separated", Type: "string"},
		"mtu":                {Description: "Link MTU to advertise (empty = do not advertise)", Type: "int"},
		"default_lifetime":   {Description: "Router lifetime in seconds (0 = not a default router)", Default: "1800", Type: "int"},
	}
}

func (r *RouterAdvertisement) Validate(cfg map[string]string) error {
	ifaces := cfg["enabled_interfaces"]
	if strings.TrimSpace(ifaces) == "" {
		return fmt.Errorf("enabled_interfaces must not be empty")
	}

	prefix := cfg["prefix"]
	if prefix == "" {
		return fmt.Errorf("prefix must not be empty")
	}
	if err := ValidateIPv6Address(strings.SplitN(prefix, "/", 2)[0]); err != nil {
		// Try parsing as CIDR.
		_, _, family, err2 := ParseCIDR(prefix)
		if err2 != nil {
			return fmt.Errorf("invalid prefix %q: %w", prefix, err2)
		}
		if family != FamilyIPv6 {
			return fmt.Errorf("prefix %q is not an IPv6 CIDR", prefix)
		}
	}

	// Validate each interface name is non-empty.
	for _, iface := range strings.Split(ifaces, ",") {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			return fmt.Errorf("enabled_interfaces contains an empty entry")
		}
	}

	// Validate RDNSS addresses if provided.
	if rdnss := cfg["rdnss"]; rdnss != "" {
		for _, addr := range strings.Split(rdnss, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			if err := ValidateIPv6Address(addr); err != nil {
				return fmt.Errorf("invalid rdnss address %q: %w", addr, err)
			}
		}
	}

	return nil
}

func (r *RouterAdvertisement) Start(cfg map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = cfg

	if err := r.generateConfig(); err != nil {
		return fmt.Errorf("generate radvd config: %w", err)
	}

	if err := Proc.Restart(radvdServiceNam); err != nil {
		r.state = StateError
		return fmt.Errorf("start radvd: %w", err)
	}

	r.state = StateRunning
	return nil
}

func (r *RouterAdvertisement) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := Proc.Stop(radvdServiceNam); err != nil {
		return fmt.Errorf("stop radvd: %w", err)
	}

	r.state = StateStopped
	return nil
}

func (r *RouterAdvertisement) Reload(cfg map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = cfg

	if err := r.generateConfig(); err != nil {
		return fmt.Errorf("generate radvd config: %w", err)
	}

	if err := Proc.Reload(radvdServiceNam); err != nil {
		if err2 := Proc.Restart(radvdServiceNam); err2 != nil {
			return fmt.Errorf("reload radvd: %w", err2)
		}
	}
	return nil
}

func (r *RouterAdvertisement) Status() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// generateConfig writes /etc/radvd.conf based on the current configuration.
// Must be called with r.mu held.
func (r *RouterAdvertisement) generateConfig() error {
	cfg := r.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper radvd config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	ifaces := strings.Split(cfg["enabled_interfaces"], ",")
	prefix := cfg["prefix"]
	if prefix == "" {
		prefix = "fd00::/64"
	}

	managedFlag := cfg["managed_flag"] == "true"
	otherConfigFlag := cfg["other_config_flag"] == "true"
	raInterval := cfg["ra_interval"]
	if raInterval == "" {
		raInterval = "600"
	}
	defaultLifetime := cfg["default_lifetime"]
	if defaultLifetime == "" {
		defaultLifetime = "1800"
	}

	for _, iface := range ifaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}

		b.WriteString(fmt.Sprintf("interface %s\n{\n", iface))
		b.WriteString("    AdvSendAdvert on;\n")
		b.WriteString(fmt.Sprintf("    MaxRtrAdvInterval %s;\n", raInterval))

		// MinRtrAdvInterval is typically 1/3 of max per RFC 4861.
		b.WriteString(fmt.Sprintf("    MinRtrAdvInterval %d;\n", max(3, atoi(raInterval)/3)))

		b.WriteString(fmt.Sprintf("    AdvDefaultLifetime %s;\n", defaultLifetime))

		if managedFlag {
			b.WriteString("    AdvManagedFlag on;\n")
		} else {
			b.WriteString("    AdvManagedFlag off;\n")
		}

		if otherConfigFlag {
			b.WriteString("    AdvOtherConfigFlag on;\n")
		} else {
			b.WriteString("    AdvOtherConfigFlag off;\n")
		}

		if mtu := cfg["mtu"]; mtu != "" {
			b.WriteString(fmt.Sprintf("    AdvLinkMTU %s;\n", mtu))
		}

		b.WriteString("\n")

		// Prefix block.
		b.WriteString(fmt.Sprintf("    prefix %s\n    {\n", prefix))
		b.WriteString("        AdvOnLink on;\n")
		b.WriteString("        AdvAutonomous on;\n")
		b.WriteString("    };\n")

		// RDNSS block.
		if rdnss := cfg["rdnss"]; rdnss != "" {
			var addrs []string
			for _, a := range strings.Split(rdnss, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					addrs = append(addrs, a)
				}
			}
			if len(addrs) > 0 {
				b.WriteString(fmt.Sprintf("\n    RDNSS %s\n    {\n", strings.Join(addrs, " ")))
				b.WriteString("        AdvRDNSSLifetime 600;\n")
				b.WriteString("    };\n")
			}
		}

		b.WriteString("};\n\n")
	}

	if err := os.WriteFile(radvdConfPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write radvd config: %w", err)
	}

	slog.Info("radvd config generated", "path", radvdConfPath)
	return nil
}

// atoi is a small helper that converts a string to int, returning 0 on error.
func atoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// ---------------------------------------------------------------------------
// NDP (Neighbor Discovery Protocol) proxy
// ---------------------------------------------------------------------------

// EnableNDPProxy enables the kernel NDP proxy on the given interface by
// writing to /proc/sys (no exec.Command).
func EnableNDPProxy(iface string) error {
	if err := validateIfaceName(iface); err != nil {
		return err
	}
	path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface)
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable NDP proxy on %s: %w", iface, err)
	}
	slog.Info("NDP proxy enabled", "interface", iface)
	return nil
}

// DisableNDPProxy disables the kernel NDP proxy on the given interface by
// writing to /proc/sys (no exec.Command).
func DisableNDPProxy(iface string) error {
	if err := validateIfaceName(iface); err != nil {
		return err
	}
	path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface)
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return fmt.Errorf("disable NDP proxy on %s: %w", iface, err)
	}
	slog.Info("NDP proxy disabled", "interface", iface)
	return nil
}

// validateIfaceName performs basic sanitisation on an interface name to
// prevent injection in sysctl paths.
func validateIfaceName(iface string) error {
	if iface == "" {
		return fmt.Errorf("interface name must not be empty")
	}
	for _, c := range iface {
		if c == '/' || c == '.' || c == ' ' || c == '\'' || c == '"' || c == ';' {
			return fmt.Errorf("interface name %q contains invalid character %q", iface, c)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// IPv6 firewall helpers
// ---------------------------------------------------------------------------

// GenerateICMPv6Rules returns nftables rules that allow essential ICMPv6
// traffic required for IPv6 to function: NDP (neighbor solicitation/
// advertisement, router solicitation/advertisement), echo request/reply,
// and other critical types.
func GenerateICMPv6Rules() string {
	var b strings.Builder
	b.WriteString("# Essential ICMPv6 rules for IPv6 operation\n")
	b.WriteString("# Auto-generated by gatekeeper ipv6 module\n\n")

	// Neighbor Discovery Protocol (NDP) — RFC 4861
	b.WriteString("# NDP Neighbor Solicitation (type 135)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type nd-neighbor-solicit accept\n")

	b.WriteString("# NDP Neighbor Advertisement (type 136)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type nd-neighbor-advert accept\n")

	b.WriteString("# NDP Router Solicitation (type 133)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type nd-router-solicit accept\n")

	b.WriteString("# NDP Router Advertisement (type 134)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type nd-router-advert accept\n")

	b.WriteString("# NDP Redirect (type 137)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type nd-redirect accept\n")

	// MLD — RFC 2710 / RFC 3810
	b.WriteString("# MLD Listener Query (type 130)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type mld-listener-query accept\n")

	b.WriteString("# MLD Listener Report (type 131)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type mld-listener-report accept\n")

	b.WriteString("# MLD Listener Done (type 132)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type mld-listener-done accept\n")

	b.WriteString("# MLDv2 Listener Report (type 143)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type mld2-listener-report accept\n")

	// Echo — RFC 4443
	b.WriteString("# ICMPv6 Echo Request (ping6)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type echo-request accept\n")

	b.WriteString("# ICMPv6 Echo Reply\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type echo-reply accept\n")

	// Error types required for PMTUD and general operation.
	b.WriteString("# ICMPv6 Destination Unreachable\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type destination-unreachable accept\n")

	b.WriteString("# ICMPv6 Packet Too Big (PMTUD)\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type packet-too-big accept\n")

	b.WriteString("# ICMPv6 Time Exceeded\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type time-exceeded accept\n")

	b.WriteString("# ICMPv6 Parameter Problem\n")
	b.WriteString("ip6 nexthdr icmpv6 icmpv6 type parameter-problem accept\n")

	return b.String()
}

// GenerateIPv6ForwardRules returns nftables rules for forwarding IPv6 traffic
// between two zones. The action is typically "accept" or "drop".
func GenerateIPv6ForwardRules(srcZone, dstZone, action string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# IPv6 forward: %s -> %s (%s)\n", srcZone, dstZone, action))
	b.WriteString(fmt.Sprintf("iifname %q oifname %q ip6 saddr != :: ip6 daddr != :: %s\n",
		srcZone, dstZone, action))
	return b.String()
}

// ---------------------------------------------------------------------------
// Dual-stack validation
// ---------------------------------------------------------------------------

// ValidateDualStackZone checks that an IPv4 CIDR and IPv6 CIDR pair are
// both valid and belong to the correct address families.
func ValidateDualStackZone(ipv4CIDR, ipv6CIDR string) error {
	if ipv4CIDR == "" {
		return fmt.Errorf("IPv4 CIDR must not be empty")
	}
	if ipv6CIDR == "" {
		return fmt.Errorf("IPv6 CIDR must not be empty")
	}

	_, _, v4fam, err := ParseCIDR(ipv4CIDR)
	if err != nil {
		return fmt.Errorf("invalid IPv4 CIDR: %w", err)
	}
	if v4fam != FamilyIPv4 {
		return fmt.Errorf("expected IPv4 CIDR but got IPv6: %s", ipv4CIDR)
	}

	_, _, v6fam, err := ParseCIDR(ipv6CIDR)
	if err != nil {
		return fmt.Errorf("invalid IPv6 CIDR: %w", err)
	}
	if v6fam != FamilyIPv6 {
		return fmt.Errorf("expected IPv6 CIDR but got IPv4: %s", ipv6CIDR)
	}

	return nil
}

// ValidateIPv6Address checks that addr is a valid IPv6 address.
func ValidateIPv6Address(addr string) error {
	if addr == "" {
		return fmt.Errorf("IPv6 address must not be empty")
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", addr)
	}
	if ip.To4() != nil {
		return fmt.Errorf("expected IPv6 address but got IPv4: %s", addr)
	}
	return nil
}
