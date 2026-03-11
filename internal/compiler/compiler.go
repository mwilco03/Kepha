package compiler

import (
	"fmt"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

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
	WGListenPort int // WireGuard listen port (0 = disabled).
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

	// Flush existing gatekeeper tables.
	b.WriteString("table inet gatekeeper\ndelete table inet gatekeeper\n\n")
	b.WriteString("table inet gatekeeper {\n\n")

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

	// Emit sets for each alias.
	for _, a := range input.Aliases {
		members := resolveAliasMembers(&a, aliasMap, 0)
		if len(members) == 0 {
			continue
		}
		setType := inferSetType(a.Type)
		needsInterval := a.Type == model.AliasTypeNetwork
		b.WriteString(fmt.Sprintf("\tset %s {\n", sanitizeName(a.Name)))
		b.WriteString(fmt.Sprintf("\t\ttype %s\n", setType))
		if needsInterval {
			b.WriteString("\t\tflags interval\n")
		}
		b.WriteString(fmt.Sprintf("\t\telements = { %s }\n", strings.Join(members, ", ")))
		b.WriteString("\t}\n\n")
	}

	// Emit the base chains.
	writeInputChain(&b, input)
	writeForwardChain(&b, input, policyMap, aliasMap, zoneProfiles, profileDevices)
	writeNATChain(&b, input)

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
	b.WriteString("\t\t# Allow ICMP.\n")
	b.WriteString("\t\tip protocol icmp accept\n\n")

	// Allow API access from LAN zones.
	for _, z := range input.Zones {
		if z.TrustLevel == "full" && z.Interface != "" {
			fmt.Fprintf(b, "\t\t# Allow API from %s.\n", z.Name)
			fmt.Fprintf(b, "\t\tiifname %q tcp dport 8080 accept\n\n", z.Interface)
		}
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
	profileDevices map[int64][]model.DeviceAssignment) {

	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy drop;\n\n")
	b.WriteString("\t\t# Allow established/related.\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n\n")

	// Find WAN zone for outbound rules.
	var wanIface string
	for _, z := range input.Zones {
		if z.Name == "wan" {
			wanIface = z.Interface
			break
		}
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

	b.WriteString("\t\t# Default deny (policy).\n")
	b.WriteString("\t}\n\n")
}

func writeNATChain(b *strings.Builder, input *Input) {
	var wanIface string
	for _, z := range input.Zones {
		if z.Name == "wan" {
			wanIface = z.Interface
			break
		}
	}

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
			parts = append(parts, fmt.Sprintf("ip saddr @%s", sanitizeName(r.SrcAlias)))
		}
	}

	if r.DstAlias != "" {
		if a, ok := aliasMap[r.DstAlias]; ok && a.Type != model.AliasTypePort {
			parts = append(parts, fmt.Sprintf("ip daddr @%s", sanitizeName(r.DstAlias)))
		}
	}

	if r.Log {
		parts = append(parts, fmt.Sprintf("log prefix %q", "gk:"))
	}

	action := strings.ToLower(string(r.Action))
	if validate.Action(action) != nil {
		return "" // Skip rules with invalid action.
	}
	// Translate model actions to nftables verdicts.
	parts = append(parts, modelActionToNFT(action))

	return strings.Join(parts, " ")
}

func resolveAliasMembers(a *model.Alias, aliasMap map[string]*model.Alias, depth int) []string {
	if depth > 10 {
		return nil // Prevent infinite recursion.
	}

	if a.Type != model.AliasTypeNested {
		var safe []string
		for _, m := range a.Members {
			if validate.AliasMember(m, string(a.Type)) == nil {
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
		resolved = append(resolved, resolveAliasMembers(nested, aliasMap, depth+1)...)
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
func modelActionToNFT(action string) string {
	switch action {
	case "allow":
		return "accept"
	case "deny":
		return "drop"
	case "reject":
		return "reject"
	case "log":
		return "log"
	default:
		return "drop"
	}
}

func sanitizeName(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), ".", "_")
}

func validateInput(input *Input) error {
	if len(input.Zones) == 0 {
		return fmt.Errorf("no zones defined")
	}

	// Check for WAN zone.
	hasWAN := false
	for _, z := range input.Zones {
		if z.Name == "wan" {
			hasWAN = true
			break
		}
	}
	if !hasWAN {
		return fmt.Errorf("no 'wan' zone defined")
	}

	return nil
}
