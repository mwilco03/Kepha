package compiler

import (
	"fmt"
	"net"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
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

		// Find the policy.
		for _, policy := range input.Policies {
			if policy.Name != profile.PolicyName {
				continue
			}

			// Evaluate rules in order.
			for _, rule := range policy.Rules {
				if ruleMatches(rule, req, input.Aliases) {
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

func ruleMatches(rule model.Rule, req PathTestRequest, aliases []model.Alias) bool {
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

	// Check source alias.
	if rule.SrcAlias != "" {
		if !ipInAlias(req.SrcIP, rule.SrcAlias, aliases) {
			return false
		}
	}

	// Check destination alias.
	if rule.DstAlias != "" {
		if !ipInAlias(req.DstIP, rule.DstAlias, aliases) {
			return false
		}
	}

	return true
}

func portMatches(ports string, dstPort int) bool {
	for _, p := range strings.Split(ports, ",") {
		p = strings.TrimSpace(p)
		if fmt.Sprintf("%d", dstPort) == p {
			return true
		}
	}
	return false
}

func ipInAlias(ip, aliasName string, aliases []model.Alias) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, a := range aliases {
		if a.Name != aliasName {
			continue
		}
		for _, m := range a.Members {
			if m == ip {
				return true
			}
			_, cidr, err := net.ParseCIDR(m)
			if err == nil && cidr.Contains(parsed) {
				return true
			}
		}
		return false
	}
	return false
}
