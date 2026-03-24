package compiler

import (
	"testing"

	"github.com/mwilco03/kepha/internal/model"
)

func FuzzCompile(f *testing.F) {
	// Seed with basic valid input.
	f.Add("wan", "eth0", "", "lan", "eth1", "10.10.0.0/24", "web", "host", "10.10.0.1", "tcp", "80", "allow")

	f.Fuzz(func(t *testing.T,
		zone1Name, zone1Iface, zone1CIDR,
		zone2Name, zone2Iface, zone2CIDR,
		aliasName string, aliasType string, aliasMember string,
		protocol, ports, action string,
	) {
		at := model.AliasType(aliasType)
		ra := model.RuleAction(action)

		input := &Input{
			Zones: []model.Zone{
				{ID: 1, Name: zone1Name, Interface: zone1Iface, NetworkCIDR: zone1CIDR, TrustLevel: "none"},
				{ID: 2, Name: zone2Name, Interface: zone2Iface, NetworkCIDR: zone2CIDR, TrustLevel: "full"},
			},
			Aliases: []model.Alias{
				{ID: 1, Name: aliasName, Type: at, Members: []string{aliasMember}},
			},
			Policies: []model.Policy{
				{
					ID:            1,
					Name:          "test-policy",
					DefaultAction: ra,
					Rules: []model.Rule{
						{Order: 1, Protocol: protocol, Ports: ports, Action: ra, SrcAlias: aliasName},
					},
				},
			},
			Profiles: []model.Profile{
				{ID: 1, Name: "test-profile", ZoneID: 2, PolicyName: "test-policy"},
			},
		}

		// Should not panic regardless of input.
		Compile(input)
	})
}

func FuzzPathTest(f *testing.F) {
	f.Add("10.10.0.5", "8.8.8.8", "tcp", 80)

	f.Fuzz(func(t *testing.T, srcIP, dstIP, proto string, port int) {
		input := &Input{
			Zones: []model.Zone{
				{ID: 1, Name: "wan", Interface: "eth0", TrustLevel: "none"},
				{ID: 2, Name: "lan", Interface: "eth1", NetworkCIDR: "10.10.0.0/24", TrustLevel: "full"},
			},
			Policies: []model.Policy{
				{ID: 1, Name: "lan-outbound", DefaultAction: model.RuleActionAllow},
			},
			Profiles: []model.Profile{
				{ID: 1, Name: "desktop", ZoneID: 2, PolicyName: "lan-outbound"},
			},
		}

		req := PathTestRequest{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: proto,
			DstPort:  port,
		}

		// Should not panic regardless of input.
		PathTest(input, req)
	})
}
