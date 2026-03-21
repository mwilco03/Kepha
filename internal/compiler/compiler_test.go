package compiler

import (
	"strings"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func basicInput() *Input {
	return &Input{
		Zones: []model.Zone{
			{ID: 1, Name: "wan", Interface: "eth0", TrustLevel: "none"},
			{ID: 2, Name: "lan", Interface: "eth1", NetworkCIDR: "10.10.0.0/24", TrustLevel: "full"},
		},
		Aliases: []model.Alias{
			{ID: 1, Name: "web-servers", Type: model.AliasTypeHost, Members: []string{"10.10.0.10", "10.10.0.11"}},
		},
		Policies: []model.Policy{
			{
				ID:            1,
				Name:          "lan-outbound",
				DefaultAction: model.RuleActionAllow,
				Rules: []model.Rule{
					{Order: 1, Protocol: "tcp", Ports: "80,443", Action: model.RuleActionAllow},
				},
			},
			{ID: 2, Name: "deny-all", DefaultAction: model.RuleActionDeny},
		},
		Profiles: []model.Profile{
			{ID: 1, Name: "desktop", ZoneID: 2, PolicyName: "lan-outbound"},
		},
		APIPort: 8080,
	}
}

func TestCompileBasic(t *testing.T) {
	result, err := Compile(basicInput())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	text := result.Text

	// Should contain table declaration.
	if !strings.Contains(text, "table inet gatekeeper") {
		t.Error("missing table declaration")
	}

	// Should contain input chain.
	if !strings.Contains(text, "chain input") {
		t.Error("missing input chain")
	}

	// Should contain forward chain.
	if !strings.Contains(text, "chain forward") {
		t.Error("missing forward chain")
	}

	// Should contain NAT masquerade.
	if !strings.Contains(text, "masquerade") {
		t.Error("missing NAT masquerade")
	}

	// Should contain alias set.
	if !strings.Contains(text, "set web_servers") {
		t.Error("missing alias set")
	}

	// Should contain established/related.
	if !strings.Contains(text, "ct state established,related accept") {
		t.Error("missing conntrack rule")
	}

	// Should allow DHCP/DNS from LAN.
	if !strings.Contains(text, "udp dport { 53, 67 }") {
		t.Error("missing DHCP/DNS rule")
	}

	// Should allow management API from all interfaces.
	if !strings.Contains(text, "tcp dport 8080 accept") {
		t.Error("missing management API access rule")
	}
	// Rule must be unconditional (no iifname qualifier).
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "tcp dport 8080") && strings.Contains(line, "iifname") {
			t.Error("management API rule should not be interface-restricted")
		}
	}
}

func TestCompileNoWAN(t *testing.T) {
	input := &Input{
		Zones: []model.Zone{
			{ID: 1, Name: "lan", Interface: "eth0"},
		},
	}
	_, err := Compile(input)
	if err == nil {
		t.Error("expected error for missing WAN zone")
	}
}

func TestCompileEmptyZones(t *testing.T) {
	_, err := Compile(&Input{})
	if err == nil {
		t.Error("expected error for empty zones")
	}
}

func TestCompileMultipleZones(t *testing.T) {
	input := basicInput()
	input.Zones = append(input.Zones, model.Zone{
		ID: 3, Name: "iot", Interface: "eth2", NetworkCIDR: "10.30.0.0/24", TrustLevel: "none",
	})
	input.Policies = append(input.Policies, model.Policy{
		ID:            3,
		Name:          "iot-restricted",
		DefaultAction: model.RuleActionDeny,
		Rules: []model.Rule{
			{Order: 1, Protocol: "tcp", Ports: "80,443", Action: model.RuleActionAllow},
		},
	})
	input.Profiles = append(input.Profiles, model.Profile{
		ID: 2, Name: "iot-device", ZoneID: 3, PolicyName: "iot-restricted",
	})

	result, err := Compile(input)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if !strings.Contains(result.Text, "iot") {
		t.Error("missing IoT zone rules")
	}
}

func TestCompileNestedAlias(t *testing.T) {
	input := basicInput()
	input.Aliases = append(input.Aliases,
		model.Alias{ID: 2, Name: "all-servers", Type: model.AliasTypeNested, Members: []string{"web-servers"}},
	)

	result, err := Compile(input)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Nested alias should be resolved.
	if !strings.Contains(result.Text, "set all_servers") {
		t.Error("missing resolved nested alias set")
	}
	if !strings.Contains(result.Text, "10.10.0.10") {
		t.Error("nested alias members not resolved")
	}
}

func TestCompilePortAlias(t *testing.T) {
	input := basicInput()
	input.Aliases = append(input.Aliases,
		model.Alias{ID: 3, Name: "web-ports", Type: model.AliasTypePort, Members: []string{"80", "443", "8080"}},
	)

	result, err := Compile(input)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if !strings.Contains(result.Text, "inet_service") {
		t.Error("port alias should use inet_service type")
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"web-servers", "web_servers"},
		{"my.alias", "my_alias"},
		{"simple", "simple"},
		{"a-b.c", "a_b_c"},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDryRunOutput(t *testing.T) {
	result, err := Compile(basicInput())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Should be parseable nft syntax (starts with shebang).
	if !strings.HasPrefix(result.Text, "#!/usr/sbin/nft -f") {
		t.Error("missing nft shebang")
	}

	// Should end with closing brace.
	trimmed := strings.TrimSpace(result.Text)
	if !strings.HasSuffix(trimmed, "}") {
		t.Error("ruleset should end with closing brace")
	}
}

func TestMSSClampPMTU(t *testing.T) {
	input := basicInput()
	input.MSSClampPMTU = true

	result, err := Compile(input)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if !strings.Contains(result.Text, "tcp option maxseg size set rt mtu") {
		t.Error("MSS clamping rule missing when MSSClampPMTU=true")
	}
	if !strings.Contains(result.Text, "tcp flags syn / syn,rst") {
		t.Error("SYN flag match missing in MSS clamping rule")
	}
}

func TestMSSClampPMTUDisabled(t *testing.T) {
	input := basicInput()
	input.MSSClampPMTU = false

	result, err := Compile(input)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if strings.Contains(result.Text, "tcp option maxseg size") {
		t.Error("MSS clamping rule should NOT be present when MSSClampPMTU=false")
	}
}
