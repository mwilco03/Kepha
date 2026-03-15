package service

import (
	"fmt"
	"log/slog"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// DropInGateway provides transparent network insertion mode.
//
// This is the feature GL.iNet calls "Drop-in Gateway Mode" — place Gatekeeper
// between an existing router and its clients without changing any existing
// network configuration. Gatekeeper creates a bridge between WAN and LAN
// interfaces, then selectively intercepts traffic for:
//   - DNS filtering (redirect DNS to local resolver)
//   - VPN tunneling (mark and route selected traffic through VPN)
//   - IDS/IPS inspection (via NFQUEUE to Suricata)
//   - Ad blocking (via DNS filter)
//
// The key insight: the bridge passes all traffic transparently, but nftables
// rules on the bridge intercept specific protocols (DNS, HTTP) for filtering.
// To existing devices on the network, Gatekeeper is invisible — they keep
// their existing IPs, gateways, and DNS settings from the upstream router.
type DropInGateway struct {
	mu       sync.Mutex
	state    State
	cfg      map[string]string
	nftTable string
}

func NewDropInGateway() *DropInGateway {
	return &DropInGateway{
		state:    StateStopped,
		nftTable: "gk_dropin",
	}
}

func (d *DropInGateway) Name() string        { return "dropin-gateway" }
func (d *DropInGateway) DisplayName() string { return "Drop-in Gateway" }
func (d *DropInGateway) Category() string    { return "network" }
func (d *DropInGateway) Dependencies() []string { return nil }

func (d *DropInGateway) Description() string {
	return "Transparent drop-in gateway mode. Insert Gatekeeper between an existing router and its clients without changing any network configuration. Adds DNS filtering, VPN, and IDS transparently."
}

func (d *DropInGateway) DefaultConfig() map[string]string {
	return map[string]string{
		"wan_interface":    "",
		"lan_interface":    "",
		"bridge_name":      "br-dropin",
		"intercept_dns":    "true",
		"local_dns_port":   "5353",
		"intercept_http":   "false",
		"management_ip":    "169.254.1.1/16",
		"enable_ids":       "false",
	}
}

func (d *DropInGateway) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"wan_interface":   {Description: "WAN-facing interface (connects to upstream router). Leave blank for auto-detection via default route.", Required: false, Type: "string"},
		"lan_interface":   {Description: "LAN-facing interface (connects to client devices). Leave blank for auto-detection.", Required: false, Type: "string"},
		"bridge_name":     {Description: "Bridge interface name", Default: "br-dropin", Type: "string"},
		"intercept_dns":   {Description: "Intercept and filter DNS queries", Default: "true", Type: "bool"},
		"local_dns_port":  {Description: "Local DNS resolver port to redirect intercepted DNS to", Default: "5353", Type: "string"},
		"intercept_http":  {Description: "Intercept HTTP for captive portal / transparent proxy", Default: "false", Type: "bool"},
		"management_ip":   {Description: "Link-local IP for management access to Gatekeeper", Default: "169.254.1.1/16", Type: "string"},
		"enable_ids":      {Description: "Send bridge traffic through IDS/IPS (Suricata)", Default: "false", Type: "bool"},
	}
}

func (d *DropInGateway) Validate(cfg map[string]string) error {
	wan := cfg["wan_interface"]
	lan := cfg["lan_interface"]

	// Auto-discover if not specified.
	if wan == "" || lan == "" {
		topo, err := DiscoverTopology()
		if err != nil {
			return fmt.Errorf("auto-discovery failed: %w (set wan_interface and lan_interface manually)")
		}
		if topo.Suggestion == nil {
			return fmt.Errorf("auto-discovery could not determine WAN/LAN interfaces; set wan_interface and lan_interface manually")
		}
		if wan == "" {
			wan = topo.Suggestion.WANInterface
		}
		if lan == "" {
			lan = topo.Suggestion.LANInterface
		}
	}

	if wan == "" {
		return fmt.Errorf("wan_interface is required (auto-discovery found no default route)")
	}
	if lan == "" {
		return fmt.Errorf("lan_interface is required (auto-discovery found no LAN candidates)")
	}
	if wan == lan {
		return fmt.Errorf("wan_interface and lan_interface must be different")
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

	bridge := cfg["bridge_name"]
	if bridge == "" {
		bridge = "br-dropin"
	}

	wan := cfg["wan_interface"]
	lan := cfg["lan_interface"]

	// Auto-discover interfaces if not explicitly configured.
	if wan == "" || lan == "" {
		topo, err := DiscoverTopology()
		if err != nil {
			d.state = StateError
			return fmt.Errorf("auto-discovery failed: %w", err)
		}
		if topo.Suggestion == nil {
			d.state = StateError
			return fmt.Errorf("auto-discovery could not determine WAN/LAN; set wan_interface and lan_interface manually")
		}
		if wan == "" {
			wan = topo.Suggestion.WANInterface
			cfg["wan_interface"] = wan
		}
		if lan == "" {
			lan = topo.Suggestion.LANInterface
			cfg["lan_interface"] = lan
		}
		slog.Info("dropin-gateway: auto-discovered interfaces",
			"wan", wan, "lan", lan, "reason", topo.Suggestion.Reason)
	}

	d.cfg = cfg

	// Step 1: Create bridge.
	if err := Net.LinkAdd(bridge, "bridge"); err != nil {
		slog.Warn("dropin: bridge may already exist", "error", err)
	}

	// Enable STP and set fast forward delay for quick convergence.
	Net.BridgeSetSTP(bridge, true)
	Net.BridgeSetForwardDelay(bridge, 0)

	// Step 2: Strip IPs from WAN and LAN interfaces (bridge handles forwarding).
	Net.AddrFlush(wan)
	Net.AddrFlush(lan)

	// Step 3: Add interfaces to bridge.
	if err := Net.LinkSetMaster(wan, bridge); err != nil {
		d.state = StateError
		return fmt.Errorf("add %s to bridge: %w", wan, err)
	}
	if err := Net.LinkSetMaster(lan, bridge); err != nil {
		d.state = StateError
		return fmt.Errorf("add %s to bridge: %w", lan, err)
	}

	// Step 4: Bring everything up.
	Net.LinkSetUp(wan)
	Net.LinkSetUp(lan)
	Net.LinkSetUp(bridge)

	// Step 5: Assign a link-local management IP to the bridge.
	mgmtIP := cfg["management_ip"]
	if mgmtIP == "" {
		mgmtIP = "169.254.1.1/16"
	}
	if err := Net.AddrAdd(bridge, mgmtIP); err != nil {
		slog.Warn("dropin: failed to assign management IP", "error", err)
	}

	// Step 6: Apply interception rules.
	if err := d.applyInterceptionRules(cfg); err != nil {
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
	cfg := d.cfg

	// Remove nftables interception rules.
	nftDeleteTable(nft.TableFamilyBridge, d.nftTable)
	nftDeleteTable(nft.TableFamilyINet, d.nftTable+"_inet")

	if cfg != nil {
		bridge := cfg["bridge_name"]
		if bridge == "" {
			bridge = "br-dropin"
		}

		// Remove bridge and restore interfaces.
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

// applyInterceptionRules sets up selective traffic interception on the bridge.
//
// Bridge family nftables rules can intercept L2 frames crossing the bridge.
// We use these to redirect DNS queries to our local resolver while passing
// all other traffic transparently.
func (d *DropInGateway) applyInterceptionRules(cfg map[string]string) error {
	var rules [][]expr.Any

	if cfg["intercept_dns"] == "true" {
		dnsPort := uint16(5353)
		if p := cfg["local_dns_port"]; p != "" {
			fmt.Sscanf(p, "%d", &dnsPort)
		}

		// Redirect UDP port 53 to local DNS resolver.
		rules = append(rules, nftRule(
			nftMatchUDPDport(53),
			nftRedirectToPort(dnsPort),
		))

		// Redirect TCP port 53 to local DNS resolver.
		rules = append(rules, nftRule(
			nftMatchTCPDport(53),
			nftRedirectToPort(dnsPort),
		))
	}

	if cfg["enable_ids"] == "true" {
		// Queue all bridge traffic to NFQUEUE 0 for Suricata inspection.
		rules = append(rules, nftRule(
			nftExpr(nftQueue(0)),
		))
	}

	if len(rules) == 0 {
		return nil
	}

	// Use inet family prerouting for redirect (bridge family doesn't support DNAT).
	hook := nft.ChainHookPrerouting
	prio := nft.ChainPriorityNATDest
	policy := nft.ChainPolicyAccept

	return nftApplyRules(nft.TableFamilyINet, d.nftTable+"_inet", []nftChainSpec{{
		Name:     "dns_intercept",
		Type:     nft.ChainTypeNAT,
		Hook:     &hook,
		Priority: &prio,
		Policy:   &policy,
		Rules:    rules,
	}})
}
