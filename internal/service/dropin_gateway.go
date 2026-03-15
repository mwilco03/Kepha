package service

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Drop-in gateway configuration keys.
const (
	cfgDropinIP          = "ip"
	cfgDropinGateway     = "gateway"
	cfgDropinSubnet      = "subnet"
	cfgDropinDNS         = "dns"
	cfgDropinBridge      = "bridge_name"
	cfgDropinInterceptDNS = "intercept_dns"
	cfgDropinDNSPort     = "local_dns_port"
	cfgDropinInterceptHTTP = "intercept_http"
	cfgDropinMgmtIP      = "management_ip"
	cfgDropinIDS         = "enable_ids"
)

// Default values for drop-in gateway configuration.
const (
	defaultDropinBridge  = "br-dropin"
	defaultDropinDNSPort = "5353"
	defaultDropinMgmtIP  = "169.254.1.1/16"
)

// nftables table names for drop-in gateway.
const (
	dropinNFTTable     = "gk_dropin"
	dropinNFTTableInet = "gk_dropin_inet"
)

// Well-known ports intercepted by drop-in mode.
const (
	portDNS  = 53
	portHTTP = 80
)

// DropInGateway provides transparent network insertion mode.
//
// GL.iNet calls this "Drop-in Gateway Mode": place Gatekeeper between an
// existing router and its clients without changing any existing network
// configuration. You provide four values describing the upstream network —
// IP, gateway, subnet, and DNS — and Gatekeeper handles the rest.
//
// All four values are auto-discoverable from the current network state.
// If any are omitted, Gatekeeper reads them from the WAN interface's
// existing DHCP lease / static config.
//
// Gatekeeper creates a bridge between the WAN and LAN ports, passes all
// traffic transparently, and selectively intercepts protocols (DNS, HTTP)
// for filtering, VPN tunneling, and IDS inspection.
type DropInGateway struct {
	mu    sync.Mutex
	state State
	cfg   map[string]string
}

func NewDropInGateway() *DropInGateway {
	return &DropInGateway{state: StateStopped}
}

func (d *DropInGateway) Name() string           { return "dropin-gateway" }
func (d *DropInGateway) DisplayName() string     { return "Drop-in Gateway" }
func (d *DropInGateway) Category() string        { return "network" }
func (d *DropInGateway) Dependencies() []string  { return nil }

func (d *DropInGateway) Description() string {
	return "Transparent drop-in gateway mode. Provide your upstream network's IP, gateway, subnet, and DNS — or let Gatekeeper auto-detect them. Adds DNS filtering, VPN, and IDS without changing any client configuration."
}

func (d *DropInGateway) DefaultConfig() map[string]string {
	return map[string]string{
		cfgDropinIP:            "", // auto-detect from WAN
		cfgDropinGateway:       "", // auto-detect from default route
		cfgDropinSubnet:        "", // auto-detect from WAN address
		cfgDropinDNS:           "", // auto-detect from /etc/resolv.conf
		cfgDropinBridge:        defaultDropinBridge,
		cfgDropinInterceptDNS:  "true",
		cfgDropinDNSPort:       defaultDropinDNSPort,
		cfgDropinInterceptHTTP: "false",
		cfgDropinMgmtIP:        defaultDropinMgmtIP,
		cfgDropinIDS:           "false",
	}
}

func (d *DropInGateway) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		cfgDropinIP:            {Description: "IP address on the upstream network (auto-detected from WAN interface)", Type: "string"},
		cfgDropinGateway:       {Description: "Upstream router/gateway IP (auto-detected from default route)", Type: "string"},
		cfgDropinSubnet:        {Description: "Upstream network subnet mask, e.g. 255.255.255.0 (auto-detected from WAN)", Type: "string"},
		cfgDropinDNS:           {Description: "Upstream DNS server (auto-detected from resolv.conf)", Type: "string"},
		cfgDropinBridge:        {Description: "Bridge interface name", Default: defaultDropinBridge, Type: "string"},
		cfgDropinInterceptDNS:  {Description: "Redirect DNS queries to local resolver for filtering", Default: "true", Type: "bool"},
		cfgDropinDNSPort:       {Description: "Local DNS resolver port for intercepted queries", Default: defaultDropinDNSPort, Type: "string"},
		cfgDropinInterceptHTTP: {Description: "Intercept HTTP for captive portal / transparent proxy", Default: "false", Type: "bool"},
		cfgDropinMgmtIP:        {Description: "Link-local IP for management access to Gatekeeper", Default: defaultDropinMgmtIP, Type: "string"},
		cfgDropinIDS:           {Description: "Route bridge traffic through IDS/IPS (Suricata)", Default: "false", Type: "bool"},
	}
}

func (d *DropInGateway) Validate(cfg map[string]string) error {
	// Fill any blanks from auto-discovery before validating.
	resolved, err := d.resolveConfig(cfg)
	if err != nil {
		return err
	}

	ip := net.ParseIP(resolved[cfgDropinIP])
	if ip == nil {
		return fmt.Errorf("ip: %q is not a valid IP address", resolved[cfgDropinIP])
	}

	gw := net.ParseIP(resolved[cfgDropinGateway])
	if gw == nil {
		return fmt.Errorf("gateway: %q is not a valid IP address", resolved[cfgDropinGateway])
	}

	subnet := resolved[cfgDropinSubnet]
	if net.ParseIP(subnet) == nil {
		return fmt.Errorf("subnet: %q is not a valid subnet mask", subnet)
	}

	dns := net.ParseIP(resolved[cfgDropinDNS])
	if dns == nil {
		return fmt.Errorf("dns: %q is not a valid IP address", resolved[cfgDropinDNS])
	}

	return nil
}

func (d *DropInGateway) Status() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

func (d *DropInGateway) Start(cfg map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.state = StateStarting

	// Resolve any auto-detectable values.
	resolved, err := d.resolveConfig(cfg)
	if err != nil {
		d.state = StateError
		return err
	}
	d.cfg = resolved

	topo, err := DiscoverTopology()
	if err != nil {
		d.state = StateError
		return fmt.Errorf("interface discovery: %w", err)
	}
	if topo.Suggestion == nil {
		d.state = StateError
		return fmt.Errorf("cannot determine WAN/LAN interfaces; ensure two physical NICs are present")
	}

	wan := topo.Suggestion.WANInterface
	lan := topo.Suggestion.LANInterface
	bridge := resolved[cfgDropinBridge]

	slog.Info("dropin-gateway: resolved config",
		"ip", resolved[cfgDropinIP],
		"gateway", resolved[cfgDropinGateway],
		"subnet", resolved[cfgDropinSubnet],
		"dns", resolved[cfgDropinDNS],
		"wan", wan, "lan", lan, "bridge", bridge)

	// Create bridge.
	if err := Net.LinkAdd(bridge, "bridge"); err != nil {
		slog.Warn("dropin: bridge may already exist", "error", err)
	}
	Net.BridgeSetSTP(bridge, true)
	Net.BridgeSetForwardDelay(bridge, 0)

	// Strip IPs from physical interfaces (bridge handles forwarding).
	Net.AddrFlush(wan)
	Net.AddrFlush(lan)

	// Add interfaces to bridge.
	if err := Net.LinkSetMaster(wan, bridge); err != nil {
		d.state = StateError
		return fmt.Errorf("add %s to bridge: %w", wan, err)
	}
	if err := Net.LinkSetMaster(lan, bridge); err != nil {
		d.state = StateError
		return fmt.Errorf("add %s to bridge: %w", lan, err)
	}

	// Bring everything up.
	Net.LinkSetUp(wan)
	Net.LinkSetUp(lan)
	Net.LinkSetUp(bridge)

	// Assign the upstream IP to the bridge so Gatekeeper stays reachable.
	upstreamCIDR := ipWithMask(resolved[cfgDropinIP], resolved[cfgDropinSubnet])
	if err := Net.AddrAdd(bridge, upstreamCIDR); err != nil {
		slog.Warn("dropin: failed to assign upstream IP to bridge", "cidr", upstreamCIDR, "error", err)
	}

	// Re-add the default route through the bridge (interfaces lost it when enslaved).
	if err := Net.RouteAdd("default", resolved[cfgDropinGateway], bridge); err != nil {
		slog.Warn("dropin: failed to restore default route", "gw", resolved[cfgDropinGateway], "error", err)
	}

	// Assign link-local management IP.
	mgmtIP := resolved[cfgDropinMgmtIP]
	if err := Net.AddrAdd(bridge, mgmtIP); err != nil {
		slog.Warn("dropin: failed to assign management IP", "error", err)
	}

	// Apply interception rules.
	if err := d.applyInterceptionRules(resolved); err != nil {
		slog.Warn("dropin: interception rules failed", "error", err)
	}

	d.state = StateRunning
	slog.Info("dropin-gateway started", "bridge", bridge, "wan", wan, "lan", lan)
	return nil
}

func (d *DropInGateway) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.state = StateStopping

	// Remove nftables interception rules.
	nftDeleteTable(nft.TableFamilyBridge, dropinNFTTable)
	nftDeleteTable(nft.TableFamilyINet, dropinNFTTableInet)

	if d.cfg != nil {
		bridge := d.cfg[cfgDropinBridge]
		Net.LinkSetDown(bridge)
		Net.LinkDel(bridge)
	}

	d.state = StateStopped
	slog.Info("dropin-gateway stopped")
	return nil
}

func (d *DropInGateway) Reload(cfg map[string]string) error {
	if err := d.Stop(); err != nil {
		slog.Warn("dropin stop during reload", "error", err)
	}
	return d.Start(cfg)
}

// resolveConfig fills in any blank upstream network values by reading
// the current network state. All four (ip, gateway, subnet, dns) are
// discoverable from the running system.
func (d *DropInGateway) resolveConfig(cfg map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}

	// Apply defaults for non-upstream fields.
	if out[cfgDropinBridge] == "" {
		out[cfgDropinBridge] = defaultDropinBridge
	}
	if out[cfgDropinDNSPort] == "" {
		out[cfgDropinDNSPort] = defaultDropinDNSPort
	}
	if out[cfgDropinMgmtIP] == "" {
		out[cfgDropinMgmtIP] = defaultDropinMgmtIP
	}

	// If all upstream fields are already set, nothing to discover.
	if out[cfgDropinIP] != "" && out[cfgDropinGateway] != "" &&
		out[cfgDropinSubnet] != "" && out[cfgDropinDNS] != "" {
		return out, nil
	}

	// Discover what we can.
	topo, err := DiscoverTopology()
	if err != nil {
		return nil, fmt.Errorf("auto-discovery failed: %w", err)
	}

	if out[cfgDropinGateway] == "" && topo.DefaultGateway != "" {
		out[cfgDropinGateway] = topo.DefaultGateway
	}

	// IP and subnet come from the WAN interface's address.
	if topo.WAN != nil && len(topo.WAN.Addresses) > 0 {
		wanIP, wanMask := parseCIDRComponents(topo.WAN.Addresses[0])
		if out[cfgDropinIP] == "" && wanIP != "" {
			out[cfgDropinIP] = wanIP
		}
		if out[cfgDropinSubnet] == "" && wanMask != "" {
			out[cfgDropinSubnet] = wanMask
		}
	}

	// DNS from resolv.conf.
	if out[cfgDropinDNS] == "" {
		if dns := readFirstNameserver(); dns != "" {
			out[cfgDropinDNS] = dns
		}
	}

	return out, nil
}

// applyInterceptionRules sets up selective traffic interception on the bridge.
func (d *DropInGateway) applyInterceptionRules(cfg map[string]string) error {
	var rules [][]expr.Any

	if cfg[cfgDropinInterceptDNS] == "true" {
		dnsPort := uint16(portDNS)
		if p := cfg[cfgDropinDNSPort]; p != "" {
			fmt.Sscanf(p, "%d", &dnsPort)
		}

		// Redirect both UDP and TCP port 53 to local DNS resolver.
		rules = append(rules,
			nftRule(nftMatchUDPDport(portDNS), nftRedirectToPort(dnsPort)),
			nftRule(nftMatchTCPDport(portDNS), nftRedirectToPort(dnsPort)),
		)
	}

	if cfg[cfgDropinIDS] == "true" {
		// Queue all bridge traffic to NFQUEUE 0 for Suricata inspection.
		rules = append(rules, nftRule(nftExpr(nftQueue(0))))
	}

	if len(rules) == 0 {
		return nil
	}

	// inet family prerouting for redirect (bridge family doesn't support DNAT).
	hook := nft.ChainHookPrerouting
	prio := nft.ChainPriorityNATDest
	policy := nft.ChainPolicyAccept

	return nftApplyRules(nft.TableFamilyINet, dropinNFTTableInet, []nftChainSpec{{
		Name:     "dns_intercept",
		Type:     nft.ChainTypeNAT,
		Hook:     &hook,
		Priority: &prio,
		Policy:   &policy,
		Rules:    rules,
	}})
}

// ipWithMask combines an IP and dotted subnet mask into CIDR notation.
// E.g. ipWithMask("192.168.1.10", "255.255.255.0") → "192.168.1.10/24".
func ipWithMask(ip, mask string) string {
	m := net.IPMask(net.ParseIP(mask).To4())
	ones, _ := m.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}

// parseCIDRComponents splits "192.168.1.10/24" into IP and dotted mask.
func parseCIDRComponents(cidr string) (ip, mask string) {
	ipAddr, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", ""
	}
	return ipAddr.String(), net.IP(ipNet.Mask).String()
}
