package compiler

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// validIfaceName matches valid Linux interface names (alphanumeric, dash, underscore, dot; max 15 chars).
var validIfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$`)

// CompiledRuleset is the output of the compiler — a complete nftables ruleset.
type CompiledRuleset struct {
	Text string // Full nftables ruleset text for `nft -f`
}

// Input holds all config needed for compilation.
type Input struct {
	Zones        []model.Zone
	Aliases      []model.Alias
	Policies     []model.Policy
	Profiles     []model.Profile
	Devices      []model.DeviceAssignment
	WGListenPort int  // WireGuard listen port (0 = disabled).
	MSSClampPMTU bool // Enable TCP MSS clamping to path MTU in forward chain.
	APIPort      int  // Management API port (always allowed inbound; 0 = skip rule).
}

// Compile transforms the config model into an nftables ruleset.
func Compile(input *Input) (*CompiledRuleset, error) {
	if err := validateInput(input); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	var b strings.Builder

	b.WriteString("#!/usr/sbin/nft -f\n\n")
	b.WriteString("# Gatekeeper auto-generated ruleset\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	// Flush existing table.
	tbl := model.NFTablesTableName
	b.WriteString("table inet " + tbl + "\ndelete table inet " + tbl + "\n\n")
	b.WriteString("table inet " + tbl + " {\n\n")

	// Build alias → members map for resolution.
	aliasMap := make(map[string]*model.Alias)
	for i := range input.Aliases {
		aliasMap[input.Aliases[i].Name] = &input.Aliases[i]
	}

	// Build profile → devices map.
	profileDevices := make(map[int64][]model.DeviceAssignment)
	for _, d := range input.Devices {
		profileDevices[d.ProfileID] = append(profileDevices[d.ProfileID], d)
	}

	// Build zone → profile map.
	zoneProfiles := make(map[int64][]model.Profile)
	for i := range input.Profiles {
		zoneProfiles[input.Profiles[i].ZoneID] = append(zoneProfiles[input.Profiles[i].ZoneID], input.Profiles[i])
	}

	// Build policy lookup.
	policyMap := make(map[string]*model.Policy)
	for i := range input.Policies {
		policyMap[input.Policies[i].Name] = &input.Policies[i]
	}

	// Anti-spoof set: RFC1918 + bogon ranges that must never appear as
	// source addresses on ingress from the WAN interface.
	b.WriteString("\tset bogons {\n")
	b.WriteString("\t\ttype ipv4_addr\n")
	b.WriteString("\t\tflags interval\n")
	b.WriteString("\t\telements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,\n")
	b.WriteString("\t\t             169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,\n")
	b.WriteString("\t\t             192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15,\n")
	b.WriteString("\t\t             198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4,\n")
	b.WriteString("\t\t             240.0.0.0/4 }\n")
	b.WriteString("\t}\n\n")

	// Emit sets for each alias.
	for _, a := range input.Aliases {
		members := resolveAliasMembers(&a, aliasMap, 0)
		if len(members) == 0 {
			continue
		}
		setType := inferSetType(a.Type)
		needsInterval := a.Type == model.AliasTypeNetwork
		b.WriteString(fmt.Sprintf("\tset %s {\n", model.SanitizeName(a.Name)))
		b.WriteString(fmt.Sprintf("\t\ttype %s\n", setType))
		if needsInterval {
			b.WriteString("\t\tflags interval\n")
		}
		b.WriteString(fmt.Sprintf("\t\telements = { %s }\n", strings.Join(members, ", ")))
		b.WriteString("\t}\n\n")
	}

	// Find WAN interface once for all chain builders.
	var wanIface string
	for _, z := range input.Zones {
		if z.Name == "wan" {
			wanIface = z.Interface
			break
		}
	}

	// Emit the base chains.
	writeInputChain(&b, input)
	writeForwardChain(&b, input, policyMap, aliasMap, zoneProfiles, profileDevices, wanIface)
	writeNATChain(&b, wanIface)

	b.WriteString("}\n")

	return &CompiledRuleset{Text: b.String()}, nil
}

func writeInputChain(b *strings.Builder, input *Input) {
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy drop;\n\n")
	b.WriteString("\t\t# Allow established/related.\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n\n")
	b.WriteString("\t\t# Allow loopback.\n")
	b.WriteString("\t\tiif lo accept\n\n")
	// Allow only safe ICMP types (echo-reply, dest-unreachable,
	// echo-request, time-exceeded). Rate-limit on WAN interface.
	b.WriteString("\t\t# Allow safe ICMP types.\n")
	b.WriteString("\t\tip protocol icmp icmp type { echo-reply, destination-unreachable, echo-request, time-exceeded } accept\n\n")

	// Allow management API access from all interfaces.
	// The API enforces its own authentication (API key / RBAC),
	// so the firewall must not block the management plane.
	if input.APIPort > 0 {
		fmt.Fprintf(b, "\t\t# Allow management API.\n")
		fmt.Fprintf(b, "\t\ttcp dport %d accept\n\n", input.APIPort)
	}

	// Allow WireGuard if configured.
	if input.WGListenPort > 0 {
		fmt.Fprintf(b, "\t\t# Allow WireGuard.\n")
		fmt.Fprintf(b, "\t\tudp dport %d accept\n\n", input.WGListenPort)
	}

	// Allow DHCP/DNS from all internal zones.
	for _, z := range input.Zones {
		if z.Interface != "" && z.Name != "wan" {
			fmt.Fprintf(b, "\t\tiifname %q udp dport { 53, 67 } accept\n", z.Interface)
			fmt.Fprintf(b, "\t\tiifname %q tcp dport 53 accept\n", z.Interface)
		}
	}

	b.WriteString("\n\t\t# Default drop (policy).\n")
	b.WriteString("\t}\n\n")
}

func writeForwardChain(b *strings.Builder, input *Input, policyMap map[string]*model.Policy,
	aliasMap map[string]*model.Alias, zoneProfiles map[int64][]model.Profile,
	profileDevices map[int64][]model.DeviceAssignment, wanIface string) {

	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy drop;\n\n")
	b.WriteString("\t\t# Allow established/related.\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n\n")

	// Anti-spoof: drop packets from WAN with RFC1918/bogon source addresses.
	if wanIface != "" {
		fmt.Fprintf(b, "\t\t# Anti-spoof: drop bogon sources on WAN ingress.\n")
		fmt.Fprintf(b, "\t\tiifname %q ip saddr @bogons drop\n\n", wanIface)
	}

	// Per-zone forwarding rules based on profiles and policies.
	for _, zone := range input.Zones {
		if zone.Name == "wan" || zone.Interface == "" {
			continue
		}

		profiles := zoneProfiles[zone.ID]
		for _, profile := range profiles {
			policy := policyMap[profile.PolicyName]
			if policy == nil {
				slog.Warn("profile references missing policy — skipping",
					"profile", profile.Name, "zone", zone.Name, "policy", profile.PolicyName)
				continue
			}

			fmt.Fprintf(b, "\t\t# Zone %s, profile %s, policy %s.\n", zone.Name, profile.Name, policy.Name)

			for _, rule := range policy.Rules {
				nftRule := compileRule(rule, zone.Interface, wanIface, aliasMap)
				if nftRule != "" {
					fmt.Fprintf(b, "\t\t%s\n", nftRule)
				}
			}

			// Apply default action for this policy's unmatched traffic from this zone.
			if policy.DefaultAction == model.RuleActionAllow {
				fmt.Fprintf(b, "\t\tiifname %q accept\n", zone.Interface)
			} else if policy.DefaultAction == model.RuleActionReject {
				fmt.Fprintf(b, "\t\tiifname %q reject\n", zone.Interface)
			}
			b.WriteString("\n")
		}
	}

	// TCP MSS clamping: prevent MTU blackholes when forwarding between zones
	// with different MTUs (e.g., jumbo frame LAN → 1500 WAN, or VXLAN overlay).
	if input.MSSClampPMTU {
		b.WriteString("\t\t# TCP MSS clamping — prevents packet blackholes between zones with different MTUs.\n")
		b.WriteString("\t\ttcp flags syn / syn,rst tcp option maxseg size set rt mtu\n\n")
	}

	b.WriteString("\t\t# Default deny (policy).\n")
	b.WriteString("\t}\n\n")
}

func writeNATChain(b *strings.Builder, wanIface string) {
	if wanIface == "" {
		return
	}

	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n\n")
	b.WriteString("\t\t# Masquerade outbound traffic on WAN.\n")
	fmt.Fprintf(b, "\t\toifname %q masquerade\n", wanIface)
	b.WriteString("\t}\n\n")
}

func compileRule(r model.Rule, srcIface, wanIface string, aliasMap map[string]*model.Alias) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("iifname %q", srcIface))

	if wanIface != "" {
		parts = append(parts, fmt.Sprintf("oifname %q", wanIface))
	}

	proto := strings.ToLower(r.Protocol)
	if proto != "" {
		if validate.Protocol(proto) != nil {
			return "" // Skip rules with invalid protocol.
		}
		switch proto {
		case "icmp":
			parts = append(parts, "ip protocol icmp")
		case "icmpv6":
			parts = append(parts, "ip6 nexthdr icmpv6")
		case "tcp", "udp":
			// For TCP/UDP with ports, emit "tcp dport {X}" as a single expression.
			if r.Ports != "" && validate.Ports(r.Ports) == nil {
				parts = append(parts, fmt.Sprintf("%s dport { %s }", proto, r.Ports))
			} else {
				parts = append(parts, "meta l4proto "+proto)
			}
		default:
			parts = append(parts, "meta l4proto "+proto)
		}
	}

	if r.SrcAlias != "" {
		if a, ok := aliasMap[r.SrcAlias]; ok && a.Type != model.AliasTypePort {
			parts = append(parts, fmt.Sprintf("ip saddr @%s", model.SanitizeName(r.SrcAlias)))
		}
	}

	if r.DstAlias != "" {
		if a, ok := aliasMap[r.DstAlias]; ok && a.Type != model.AliasTypePort {
			parts = append(parts, fmt.Sprintf("ip daddr @%s", model.SanitizeName(r.DstAlias)))
		}
	}

	if r.Log {
		parts = append(parts, fmt.Sprintf("log prefix %q", "gk:"))
	}

	if !model.ValidActions[r.Action] {
		return "" // Skip rules with invalid action.
	}
	// Translate model actions to nftables verdicts.
	parts = append(parts, modelActionToNFT(r.Action))

	return strings.Join(parts, " ")
}

// maxAliasExpansion caps the total number of resolved members to prevent
// exponential blowup from deeply nested aliases with many members.
const maxAliasExpansion = 10000

func resolveAliasMembers(a *model.Alias, aliasMap map[string]*model.Alias, depth int) []string {
	seen := make(map[string]struct{})
	return resolveAliasMembersDedup(a, aliasMap, depth, seen)
}

func resolveAliasMembersDedup(a *model.Alias, aliasMap map[string]*model.Alias, depth int, seen map[string]struct{}) []string {
	if depth > 10 {
		return nil // Prevent infinite recursion.
	}

	if a.Type != model.AliasTypeNested {
		safe := make([]string, 0, len(a.Members))
		for _, m := range a.Members {
			if _, dup := seen[m]; dup {
				continue
			}
			if validate.AliasMember(m, string(a.Type)) == nil {
				seen[m] = struct{}{}
				safe = append(safe, m)
			}
		}
		return safe
	}

	var resolved []string
	for _, memberName := range a.Members {
		nested, ok := aliasMap[memberName]
		if !ok {
			continue
		}
		resolved = append(resolved, resolveAliasMembersDedup(nested, aliasMap, depth+1, seen)...)
		if len(resolved) > maxAliasExpansion {
			resolved = resolved[:maxAliasExpansion]
			return resolved
		}
	}
	return resolved
}

func inferSetType(aliasType model.AliasType) string {
	switch aliasType {
	case model.AliasTypeHost, model.AliasTypeNetwork:
		return "ipv4_addr"
	case model.AliasTypePort:
		return "inet_service"
	case model.AliasTypeMAC:
		return "ether_addr"
	default:
		return "ipv4_addr"
	}
}

// modelActionToNFT translates gatekeeper rule actions to nftables verdicts.
func modelActionToNFT(action model.RuleAction) string {
	switch action {
	case model.RuleActionAllow:
		return "accept"
	case model.RuleActionDeny:
		return "drop"
	case model.RuleActionReject:
		return "reject"
	case model.RuleActionLog:
		return "log"
	default:
		return "drop"
	}
}


func validateInput(input *Input) error {
	if len(input.Zones) == 0 {
		return fmt.Errorf("no zones defined")
	}

	// Check for WAN zone and validate interface names.
	hasWAN := false
	for _, z := range input.Zones {
		if z.Name == "wan" {
			hasWAN = true
		}
		if z.Interface != "" && !validIfaceName.MatchString(z.Interface) {
			return fmt.Errorf("zone %q has invalid interface name: %q", z.Name, z.Interface)
		}
	}
	if !hasWAN {
		return fmt.Errorf("no 'wan' zone defined")
	}

	return nil
}
