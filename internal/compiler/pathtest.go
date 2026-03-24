package compiler

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mwilco03/kepha/internal/model"
)

// PathTestRequest describes a simulated packet.
type PathTestRequest struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol string `json:"protocol"` // tcp, udp, icmp
	DstPort  int    `json:"dst_port"`
}

// PathTestResult describes the outcome of a path test.
type PathTestResult struct {
	Action       string   `json:"action"` // allow, deny, drop
	MatchedRules []string `json:"matched_rules"`
	Trace        []string `json:"trace"`
}

// PathTest simulates a packet through the config and returns whether it would be allowed.
func PathTest(input *Input, req PathTestRequest) *PathTestResult {
	result := &PathTestResult{
		Action: "drop",
	}

	// Build lookup structures once instead of scanning per-call.
	aliasMap := buildAliasMap(input.Aliases)
	policyMap := make(map[string]*model.Policy, len(input.Policies))
	for i := range input.Policies {
		policyMap[input.Policies[i].Name] = &input.Policies[i]
	}

	// Find source zone by IP.
	srcZone := findZoneByIP(input.Zones, req.SrcIP)
	if srcZone == nil {
		result.Trace = append(result.Trace, fmt.Sprintf("no zone found for source IP %s", req.SrcIP))
		return result
	}
	result.Trace = append(result.Trace, fmt.Sprintf("source zone: %s (interface: %s)", srcZone.Name, srcZone.Interface))

	// Find destination zone.
	dstZone := findZoneByIP(input.Zones, req.DstIP)
	dstZoneName := "wan"
	if dstZone != nil {
		dstZoneName = dstZone.Name
	}
	result.Trace = append(result.Trace, fmt.Sprintf("destination zone: %s", dstZoneName))

	// Established/related always accepted.
	result.Trace = append(result.Trace, "checking conntrack: new connection")

	// Find profiles for the source zone.
	for _, profile := range input.Profiles {
		if profile.ZoneID != srcZone.ID {
			continue
		}

		result.Trace = append(result.Trace, fmt.Sprintf("evaluating profile: %s (policy: %s)", profile.Name, profile.PolicyName))

		// Find the policy via map lookup (O(1) instead of O(n)).
		policy := policyMap[profile.PolicyName]
		if policy == nil {
			continue
		}

		// Evaluate rules in order.
		for _, rule := range policy.Rules {
			if ruleMatches(rule, req, aliasMap) {
				action := string(rule.Action)
				result.Action = action
				desc := rule.Description
				if desc == "" {
					desc = fmt.Sprintf("rule #%d", rule.Order)
				}
				result.MatchedRules = append(result.MatchedRules, desc)
				result.Trace = append(result.Trace, fmt.Sprintf("MATCH rule %d: %s → %s", rule.Order, desc, action))
				return result
			}
		}

		// No rule matched — apply default action.
		action := string(policy.DefaultAction)
		if action == "" {
			action = "deny"
		}
		result.Action = action
		result.Trace = append(result.Trace, fmt.Sprintf("no rule matched, default action: %s", action))
		return result
	}

	result.Trace = append(result.Trace, "no matching profile/policy, default: drop")
	return result
}

func findZoneByIP(zones []model.Zone, ip string) *model.Zone {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	for i, z := range zones {
		if z.NetworkCIDR == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(z.NetworkCIDR)
		if err != nil {
			continue
		}
		if cidr.Contains(parsed) {
			return &zones[i]
		}
	}
	return nil
}

// aliasIndex provides O(1) alias lookup by name with pre-parsed CIDRs.
type aliasIndex struct {
	members []*net.IPNet // Pre-parsed CIDRs and host IPs (as /32).
	raw     []string     // Original member strings for exact match.
}

func buildAliasMap(aliases []model.Alias) map[string]*aliasIndex {
	m := make(map[string]*aliasIndex, len(aliases))
	for _, a := range aliases {
		idx := &aliasIndex{
			raw:     a.Members,
			members: make([]*net.IPNet, 0, len(a.Members)),
		}
		for _, member := range a.Members {
			// Try CIDR first.
			_, cidr, err := net.ParseCIDR(member)
			if err == nil {
				idx.members = append(idx.members, cidr)
				continue
			}
			// Try bare IP as /32.
			if ip := net.ParseIP(member); ip != nil {
				idx.members = append(idx.members, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				})
			}
		}
		m[a.Name] = idx
	}
	return m
}

func ruleMatches(rule model.Rule, req PathTestRequest, aliasMap map[string]*aliasIndex) bool {
	// Check protocol.
	if rule.Protocol != "" && !strings.EqualFold(rule.Protocol, req.Protocol) {
		return false
	}

	// Check ports.
	if rule.Ports != "" && req.DstPort > 0 {
		if !portMatches(rule.Ports, req.DstPort) {
			return false
		}
	}

	// Check source alias via map lookup (O(1) + O(members)).
	if rule.SrcAlias != "" {
		if !ipInAlias(req.SrcIP, rule.SrcAlias, aliasMap) {
			return false
		}
	}

	// Check destination alias.
	if rule.DstAlias != "" {
		if !ipInAlias(req.DstIP, rule.DstAlias, aliasMap) {
			return false
		}
	}

	return true
}

func portMatches(ports string, dstPort int) bool {
	for _, p := range strings.Split(ports, ",") {
		p = strings.TrimSpace(p)
		port, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		if port == dstPort {
			return true
		}
	}
	return false
}

// ExplainResult gives a detailed breakdown of all rules that apply to a src→dst pair.
type ExplainResult struct {
	SrcZone       string        `json:"src_zone"`
	DstZone       string        `json:"dst_zone"`
	MatchingRules []ExplainRule `json:"matching_rules"`
	FinalAction   string        `json:"final_action"`
	Trace         []string      `json:"trace"`
}

// ExplainRule describes a single rule that was evaluated.
type ExplainRule struct {
	PolicyName  string `json:"policy_name"`
	ProfileName string `json:"profile_name"`
	Order       int    `json:"order"`
	Description string `json:"description"`
	Protocol    string `json:"protocol,omitempty"`
	Ports       string `json:"ports,omitempty"`
	SrcAlias    string `json:"src_alias,omitempty"`
	DstAlias    string `json:"dst_alias,omitempty"`
	Action      string `json:"action"`
	Matches     bool   `json:"matches"`
}

// Explain returns all rules that apply between a source and destination,
// showing which match and which don't, unlike PathTest which stops at the first match.
func Explain(input *Input, req PathTestRequest) *ExplainResult {
	result := &ExplainResult{
		FinalAction: "drop",
	}

	// Build lookup structures once.
	aliasMap := buildAliasMap(input.Aliases)
	policyMap := make(map[string]*model.Policy, len(input.Policies))
	for i := range input.Policies {
		policyMap[input.Policies[i].Name] = &input.Policies[i]
	}

	srcZone := findZoneByIP(input.Zones, req.SrcIP)
	if srcZone == nil {
		result.Trace = append(result.Trace, fmt.Sprintf("no zone found for source IP %s", req.SrcIP))
		return result
	}
	result.SrcZone = srcZone.Name
	result.Trace = append(result.Trace, fmt.Sprintf("source zone: %s", srcZone.Name))

	dstZone := findZoneByIP(input.Zones, req.DstIP)
	if dstZone != nil {
		result.DstZone = dstZone.Name
	} else {
		result.DstZone = "wan"
	}
	result.Trace = append(result.Trace, fmt.Sprintf("destination zone: %s", result.DstZone))

	matched := false
	for _, profile := range input.Profiles {
		if profile.ZoneID != srcZone.ID {
			continue
		}
		// O(1) policy lookup instead of linear scan.
		policy := policyMap[profile.PolicyName]
		if policy == nil {
			continue
		}
		result.Trace = append(result.Trace, fmt.Sprintf("evaluating policy %s via profile %s", policy.Name, profile.Name))

		for _, rule := range policy.Rules {
			matches := ruleMatches(rule, req, aliasMap)
			er := ExplainRule{
				PolicyName:  policy.Name,
				ProfileName: profile.Name,
				Order:       rule.Order,
				Description: rule.Description,
				Protocol:    rule.Protocol,
				Ports:       rule.Ports,
				SrcAlias:    rule.SrcAlias,
				DstAlias:    rule.DstAlias,
				Action:      string(rule.Action),
				Matches:     matches,
			}
			result.MatchingRules = append(result.MatchingRules, er)
			if matches && !matched {
				result.FinalAction = string(rule.Action)
				matched = true
				result.Trace = append(result.Trace, fmt.Sprintf("first match: rule #%d → %s", rule.Order, rule.Action))
			}
		}

		if !matched {
			action := string(policy.DefaultAction)
			if action == "" {
				action = "deny"
			}
			result.FinalAction = action
			result.Trace = append(result.Trace, fmt.Sprintf("no rule matched, default action: %s", action))
		}
		return result
	}

	result.Trace = append(result.Trace, "no matching profile/policy, default: drop")
	return result
}

// ipInAlias checks if an IP is contained in the named alias using the pre-built index.
func ipInAlias(ip, aliasName string, aliasMap map[string]*aliasIndex) bool {
	idx, ok := aliasMap[aliasName]
	if !ok {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	// Check pre-parsed CIDRs (includes /32 host entries).
	for _, cidr := range idx.members {
		if cidr.Contains(parsed) {
			return true
		}
	}
	// Fallback: exact string match for non-IP members.
	for _, m := range idx.raw {
		if m == ip {
			return true
		}
	}
	return false
}
