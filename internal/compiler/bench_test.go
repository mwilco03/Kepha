package compiler

import (
	"fmt"
	"testing"

	"github.com/mwilco03/kepha/internal/model"
)

func buildBenchInput(nZones, nAliases, nPolicies, rulesPerPolicy, nDevices int) *Input {
	input := &Input{}

	// WAN zone is required.
	input.Zones = append(input.Zones, model.Zone{
		ID: 1, Name: "wan", Interface: "eth0", NetworkCIDR: "", TrustLevel: "none",
	})

	// Create additional zones.
	for i := 0; i < nZones; i++ {
		input.Zones = append(input.Zones, model.Zone{
			ID:          int64(i + 2),
			Name:        fmt.Sprintf("zone%d", i),
			Interface:   fmt.Sprintf("eth%d", i+1),
			NetworkCIDR: fmt.Sprintf("10.%d.0.0/24", i),
			TrustLevel:  "full",
		})
	}

	// Create aliases.
	for i := 0; i < nAliases; i++ {
		members := make([]string, 10)
		for j := 0; j < 10; j++ {
			members[j] = fmt.Sprintf("10.%d.%d.%d", i%256, j/256, j%256+1)
		}
		input.Aliases = append(input.Aliases, model.Alias{
			ID:      int64(i + 1),
			Name:    fmt.Sprintf("alias%d", i),
			Type:    model.AliasTypeHost,
			Members: members,
		})
	}

	// Create policies with rules.
	for i := 0; i < nPolicies; i++ {
		policy := model.Policy{
			ID:            int64(i + 1),
			Name:          fmt.Sprintf("policy%d", i),
			DefaultAction: model.RuleActionDeny,
		}
		for j := 0; j < rulesPerPolicy; j++ {
			policy.Rules = append(policy.Rules, model.Rule{
				ID:       int64(i*rulesPerPolicy + j + 1),
				PolicyID: policy.ID,
				Order:    j + 1,
				Protocol: "tcp",
				Ports:    fmt.Sprintf("%d", 80+j),
				Action:   model.RuleActionAllow,
			})
		}
		input.Policies = append(input.Policies, policy)
	}

	// Create profiles linking zones to policies.
	for i := 0; i < nZones && i < nPolicies; i++ {
		input.Profiles = append(input.Profiles, model.Profile{
			ID:         int64(i + 1),
			Name:       fmt.Sprintf("profile%d", i),
			ZoneID:     int64(i + 2),
			PolicyName: fmt.Sprintf("policy%d", i),
		})
	}

	// Create device assignments.
	for i := 0; i < nDevices; i++ {
		profileID := int64(i%nZones + 1)
		if nZones == 0 {
			profileID = 1
		}
		input.Devices = append(input.Devices, model.DeviceAssignment{
			ID:        int64(i + 1),
			IP:        fmt.Sprintf("10.%d.0.%d", i%nZones, i%254+1),
			MAC:       fmt.Sprintf("aa:bb:cc:dd:%02x:%02x", i/256, i%256),
			Hostname:  fmt.Sprintf("dev%d", i),
			ProfileID: profileID,
		})
	}

	return input
}

// BenchmarkCompileSmall: 2 zones, 5 aliases, 2 policies × 5 rules, 10 devices.
func BenchmarkCompileSmall(b *testing.B) {
	input := buildBenchInput(2, 5, 2, 5, 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Compile(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompileMedium: 5 zones, 20 aliases, 5 policies × 20 rules, 100 devices.
func BenchmarkCompileMedium(b *testing.B) {
	input := buildBenchInput(5, 20, 5, 20, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Compile(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompileLarge: 10 zones, 50 aliases, 10 policies × 50 rules, 500 devices.
func BenchmarkCompileLarge(b *testing.B) {
	input := buildBenchInput(10, 50, 10, 50, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Compile(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPathTestSmall benchmarks path testing with a small config.
func BenchmarkPathTestSmall(b *testing.B) {
	input := buildBenchInput(2, 5, 2, 5, 10)
	req := PathTestRequest{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Protocol: "tcp", DstPort: 80}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PathTest(input, req)
	}
}

// BenchmarkPathTestLarge benchmarks path testing with a large config.
func BenchmarkPathTestLarge(b *testing.B) {
	input := buildBenchInput(10, 50, 10, 50, 500)
	req := PathTestRequest{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Protocol: "tcp", DstPort: 80}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PathTest(input, req)
	}
}

// BenchmarkExplainLarge benchmarks the explain function with a large config.
func BenchmarkExplainLarge(b *testing.B) {
	input := buildBenchInput(10, 50, 10, 50, 500)
	req := PathTestRequest{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Protocol: "tcp", DstPort: 80}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Explain(input, req)
	}
}
