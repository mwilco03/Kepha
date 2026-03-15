package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// VPNPolicy defines a single routing policy: which traffic goes through which tunnel.
type VPNPolicy struct {
	Name   string `json:"name"`
	Type   string `json:"type"`   // "device", "network", "domain"
	Match  string `json:"match"`  // IP/CIDR for device/network, domain pattern for domain
	Action string `json:"action"` // "vpn" (route through VPN) or "direct" (bypass VPN)
}

// VPNPolicyRouter provides per-device and per-domain VPN policy routing.
//
// This is the feature GL.iNet calls "VPN Policy Mode" — the ability to route
// some devices through VPN and others directly, or to selectively route
// specific domains through or around VPN tunnels.
//
// Implementation:
//   - Per-device: source IP-based policy routing rules via netlink
//   - Per-domain: nftables marks on DNS-resolved IPs, fwmark-based routing rules
//   - Uses a dedicated routing table (table 301) for policy-routed VPN traffic
//   - Integrates with VPNProvider service for tunnel interface discovery
type VPNPolicyRouter struct {
	mu       sync.Mutex
	state    State
	cfg      map[string]string
	policies []VPNPolicy

	routeTable  int    // routing table for VPN-bound traffic
	vpnIface    string // tunnel interface (from VPNProvider)
	nftTable    string // nftables table for marking
	fwmarkBase  uint32 // base fwmark for policy marking
}

func NewVPNPolicyRouter() *VPNPolicyRouter {
	return &VPNPolicyRouter{
		state:      StateStopped,
		routeTable: 301,
		nftTable:   "gk_vpn_policy",
		fwmarkBase: 0x100,
	}
}

func (v *VPNPolicyRouter) Name() string        { return "vpn-policy" }
func (v *VPNPolicyRouter) DisplayName() string { return "VPN Policy Routing" }
func (v *VPNPolicyRouter) Category() string    { return "vpn" }
func (v *VPNPolicyRouter) Dependencies() []string { return []string{"vpn-provider"} }

func (v *VPNPolicyRouter) Description() string {
	return "Per-device and per-domain VPN policy routing. Route specific devices or domains through VPN while others go direct, or vice versa."
}

func (v *VPNPolicyRouter) DefaultConfig() map[string]string {
	return map[string]string{
		"mode":       "allowlist", // "allowlist" = only listed go through VPN, "blocklist" = all go through VPN except listed
		"vpn_iface":  "wg-vpn0",
		"policies":   "[]",
	}
}

func (v *VPNPolicyRouter) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mode":      {Description: "Routing mode: allowlist (only matched traffic uses VPN) or blocklist (all traffic uses VPN except matched)", Default: "allowlist", Required: true, Type: "string"},
		"vpn_iface": {Description: "VPN tunnel interface name", Default: "wg-vpn0", Required: true, Type: "string"},
		"policies":  {Description: "JSON array of VPNPolicy objects [{name, type, match, action}]", Default: "[]", Type: "string"},
	}
}

func (v *VPNPolicyRouter) Validate(cfg map[string]string) error {
	mode := cfg["mode"]
	if mode != "allowlist" && mode != "blocklist" {
		return fmt.Errorf("invalid mode: %s (use allowlist or blocklist)", mode)
	}
	if cfg["vpn_iface"] == "" {
		return fmt.Errorf("vpn_iface is required")
	}

	if policiesJSON := cfg["policies"]; policiesJSON != "" {
		var policies []VPNPolicy
		if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
			return fmt.Errorf("invalid policies JSON: %w", err)
		}
		for _, p := range policies {
			if p.Name == "" {
				return fmt.Errorf("policy name is required")
			}
			if p.Type != "device" && p.Type != "network" && p.Type != "domain" {
				return fmt.Errorf("policy %q: invalid type %q (use device, network, or domain)", p.Name, p.Type)
			}
			if p.Match == "" {
				return fmt.Errorf("policy %q: match is required", p.Name)
			}
			if p.Action != "vpn" && p.Action != "direct" {
				return fmt.Errorf("policy %q: invalid action %q (use vpn or direct)", p.Name, p.Action)
			}
		}
	}
	return nil
}

func (v *VPNPolicyRouter) Status() State {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state
}

func (v *VPNPolicyRouter) Start(cfg map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = StateStarting
	v.cfg = cfg
	v.vpnIface = cfg["vpn_iface"]

	// Parse policies.
	var policies []VPNPolicy
	if policiesJSON := cfg["policies"]; policiesJSON != "" && policiesJSON != "[]" {
		if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
			v.state = StateError
			return fmt.Errorf("parse policies: %w", err)
		}
	}
	v.policies = policies

	// Set up routing table: default route through VPN tunnel.
	Net.RouteFlushTable(v.routeTable)
	if err := Net.RouteAddTable("default", "", v.vpnIface, v.routeTable); err != nil {
		slog.Warn("vpn-policy: failed to add default VPN route", "error", err)
	}

	// Apply policies.
	if err := v.applyPolicies(cfg["mode"]); err != nil {
		v.state = StateError
		return err
	}

	v.state = StateRunning
	slog.Info("vpn-policy started", "mode", cfg["mode"], "policies", len(policies))
	return nil
}

func (v *VPNPolicyRouter) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = StateStopping

	// Clean up nftables rules.
	nftDeleteTable(nft.TableFamilyINet, v.nftTable)

	// Clean up routing rules and table.
	Net.RuleDel(v.routeTable)
	Net.RouteFlushTable(v.routeTable)

	v.policies = nil
	v.state = StateStopped
	slog.Info("vpn-policy stopped")
	return nil
}

func (v *VPNPolicyRouter) Reload(cfg map[string]string) error {
	if err := v.Stop(); err != nil {
		slog.Warn("vpn-policy stop during reload", "error", err)
	}
	return v.Start(cfg)
}

func (v *VPNPolicyRouter) applyPolicies(mode string) error {
	// In allowlist mode: only explicitly-matched traffic goes through VPN.
	// In blocklist mode: all traffic goes through VPN, except explicitly-matched.

	var nftRules [][]expr.Any

	for i, policy := range v.policies {
		switch policy.Type {
		case "device", "network":
			// Source IP-based routing via netlink rules.
			if err := v.applyIPPolicy(policy, i); err != nil {
				slog.Warn("vpn-policy: failed to apply IP policy", "policy", policy.Name, "error", err)
			}

		case "domain":
			// Domain-based routing via nftables fwmark.
			// Mark packets destined for resolved domain IPs with a fwmark,
			// then use fwmark-based routing rule to send to VPN table.
			rules := v.buildDomainMarkRules(policy, uint32(i))
			nftRules = append(nftRules, rules...)
		}
	}

	// If blocklist mode, add a catch-all rule sending everything through VPN.
	if mode == "blocklist" {
		mark := v.fwmarkBase
		if err := Net.RuleAddFwmark(mark, v.routeTable, 30000); err != nil {
			slog.Warn("vpn-policy: failed to add catch-all fwmark rule", "error", err)
		}

		// Mark all forwarded traffic.
		nftRules = append(nftRules, nftRule(
			nftExpr(&expr.Immediate{Register: 1, Data: fwmarkBytes(mark)}),
			nftExpr(&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1}),
		))
	}

	// Apply nftables rules for domain-based marking.
	if len(nftRules) > 0 {
		hook := nft.ChainHookPrerouting
		prio := nft.ChainPriorityMangle
		policy := nft.ChainPolicyAccept

		if err := nftApplyRules(nft.TableFamilyINet, v.nftTable, []nftChainSpec{{
			Name:     "vpn_policy_mark",
			Type:     nft.ChainTypeRoute,
			Hook:     hook,
			Priority: prio,
			Policy:   &policy,
			Rules:    nftRules,
		}}); err != nil {
			return fmt.Errorf("apply nftables policy rules: %w", err)
		}
	}

	return nil
}

func (v *VPNPolicyRouter) applyIPPolicy(policy VPNPolicy, index int) error {
	match := policy.Match

	// Ensure CIDR format.
	if !strings.Contains(match, "/") {
		ip := net.ParseIP(match)
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", match)
		}
		if ip.To4() != nil {
			match += "/32"
		} else {
			match += "/128"
		}
	}

	priority := 20000 + index

	if policy.Action == "vpn" {
		// Route this source through VPN routing table.
		return Net.RuleAddSrc(match, v.routeTable, priority)
	}

	// Action is "direct": route through main table (table 254).
	return Net.RuleAddSrc(match, 254, priority)
}

func (v *VPNPolicyRouter) buildDomainMarkRules(policy VPNPolicy, index uint32) [][]expr.Any {
	// Domain-based VPN routing works by resolving the domain to IPs and
	// creating nftables rules to mark those destination IPs. In a full
	// implementation, a DNS snooping daemon would update the IP set
	// dynamically. For now, we resolve at policy application time.

	domain := strings.TrimSpace(policy.Match)
	ips, err := net.LookupHost(domain)
	if err != nil {
		slog.Warn("vpn-policy: DNS lookup failed for domain", "domain", domain, "error", err)
		return nil
	}

	mark := v.fwmarkBase + index + 1
	var rules [][]expr.Any

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue // Skip IPv6 for now.
		}

		rule := nftRule(
			// Match destination IP.
			[]expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip.To4()},
			},
			// Set fwmark.
			nftExpr(&expr.Immediate{Register: 1, Data: fwmarkBytes(mark)}),
			nftExpr(&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1}),
		)
		rules = append(rules, rule)
	}

	// Add corresponding fwmark routing rule.
	if len(rules) > 0 {
		table := v.routeTable
		if policy.Action == "direct" {
			table = 254 // main table
		}
		if err := Net.RuleAddFwmark(mark, table, 25000+int(index)); err != nil {
			slog.Warn("vpn-policy: failed to add fwmark routing rule", "domain", domain, "error", err)
		}
	}

	return rules
}

// fwmarkBytes converts a uint32 fwmark to 4 bytes in native endian.
func fwmarkBytes(mark uint32) []byte {
	return []byte{byte(mark), byte(mark >> 8), byte(mark >> 16), byte(mark >> 24)}
}
