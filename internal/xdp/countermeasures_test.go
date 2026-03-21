package xdp

import (
	"testing"
	"time"
)

func TestCountermeasures_AddPolicy(t *testing.T) {
	cm := NewCountermeasures()

	err := cm.AddPolicy(CountermeasurePolicy{
		Target: "10.0.0.1",
		Techniques: []TechniqueConfig{
			{Type: TechniqueTarpit, Enabled: true},
		},
		Reason: "known scanner",
	})
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	policies := cm.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(policies))
	}
	if policies[0].Target != "10.0.0.1" {
		t.Errorf("target = %q", policies[0].Target)
	}
}

func TestCountermeasures_AddPolicyValidation(t *testing.T) {
	cm := NewCountermeasures()

	// No target.
	err := cm.AddPolicy(CountermeasurePolicy{
		Techniques: []TechniqueConfig{{Type: TechniqueTarpit, Enabled: true}},
	})
	if err == nil {
		t.Error("expected error for empty target")
	}

	// No techniques.
	err = cm.AddPolicy(CountermeasurePolicy{Target: "10.0.0.1"})
	if err == nil {
		t.Error("expected error for empty techniques")
	}
}

func TestCountermeasures_Evaluate(t *testing.T) {
	cm := NewCountermeasures()

	_ = cm.AddPolicy(CountermeasurePolicy{
		Target: "10.0.0.1",
		Techniques: []TechniqueConfig{
			{Type: TechniqueTarpit, Enabled: true},
			{Type: TechniqueLatency, Enabled: true},
		},
		Reason: "scanner",
	})

	// Match.
	p := cm.Evaluate("10.0.0.1")
	if p == nil {
		t.Fatal("expected policy match")
	}
	if len(p.Techniques) != 2 {
		t.Errorf("techniques = %d, want 2", len(p.Techniques))
	}

	// No match.
	p2 := cm.Evaluate("10.0.0.2")
	if p2 != nil {
		t.Error("expected no match for different IP")
	}
}

func TestCountermeasures_EvaluateExpired(t *testing.T) {
	cm := NewCountermeasures()

	_ = cm.AddPolicy(CountermeasurePolicy{
		Target: "10.0.0.1",
		Techniques: []TechniqueConfig{
			{Type: TechniqueTarpit, Enabled: true},
		},
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired.
	})

	p := cm.Evaluate("10.0.0.1")
	if p != nil {
		t.Error("expired policy should not match")
	}
}

func TestCountermeasures_RemovePolicy(t *testing.T) {
	cm := NewCountermeasures()

	_ = cm.AddPolicy(CountermeasurePolicy{
		Target:     "10.0.0.1",
		Techniques: []TechniqueConfig{{Type: TechniqueTarpit, Enabled: true}},
	})

	err := cm.RemovePolicy("10.0.0.1")
	if err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}

	if len(cm.ListPolicies()) != 0 {
		t.Error("policy should be removed")
	}

	// Remove non-existent.
	err = cm.RemovePolicy("99.99.99.99")
	if err == nil {
		t.Error("expected error for non-existent policy")
	}
}

func TestCountermeasures_GenerateRules(t *testing.T) {
	cm := NewCountermeasures()

	_ = cm.AddPolicy(CountermeasurePolicy{
		Target: "192.168.1.100",
		Techniques: []TechniqueConfig{
			{Type: TechniqueTarpit, Enabled: true},
			{Type: TechniqueBandwidth, Enabled: true},
			{Type: TechniqueSYNCookie, Enabled: true},
			{Type: TechniqueTTLRandomize, Enabled: true},
		},
		Active: true,
	})

	rules := cm.GenerateRules()
	if len(rules) == 0 {
		t.Fatal("expected structured rules to be generated")
	}

	// All rules should reference the target IP.
	found := false
	for _, r := range rules {
		if r.Target == "192.168.1.100" {
			found = true
		}
	}
	if !found {
		t.Error("expected non-empty rules")
	}
	t.Logf("Generated %d nft rules", len(rules))
}

func TestDefaultThreatPolicy(t *testing.T) {
	p := DefaultThreatPolicy("1.2.3.4", "Cobalt Strike C2")
	if p.Target != "1.2.3.4" {
		t.Errorf("target = %q", p.Target)
	}
	if len(p.Techniques) != 4 {
		t.Errorf("techniques = %d, want 4", len(p.Techniques))
	}
	if p.Source != "threat_feed" {
		t.Errorf("source = %q", p.Source)
	}
	if p.ExpiresAt.IsZero() {
		t.Error("threat policy should auto-expire")
	}
}

func TestDefaultAnomalyPolicy(t *testing.T) {
	p := DefaultAnomalyPolicy("10.0.0.5", "fingerprint change")
	if p.Target != "10.0.0.5" {
		t.Errorf("target = %q", p.Target)
	}
	if p.Source != "anomaly" {
		t.Errorf("source = %q", p.Source)
	}
	// Anomaly policy should be lighter — 2 techniques.
	if len(p.Techniques) != 2 {
		t.Errorf("techniques = %d, want 2", len(p.Techniques))
	}
}

func TestSanitizeForNft(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"10.0.0.1", "10_0_0_1"},
		{"192.168.1.0/24", "192_168_1_0_24"},
		{"safe_name-1", "safe_name-1"},
	}
	for _, tt := range tests {
		got := sanitizeForNft(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeForNft(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMatchCIDRSimple(t *testing.T) {
	tests := []struct {
		ip, target string
		want       bool
	}{
		{"10.0.0.1", "10.0.0.1", true},
		{"10.0.0.2", "10.0.0.1", false},
		{"10.0.0.5", "10.0.0/24", true},
		{"10.0.1.5", "10.0.0/24", false},
		{"192.168.1.50", "192.168/16", true},
	}
	for _, tt := range tests {
		got := matchCIDRSimple(tt.ip, tt.target)
		if got != tt.want {
			t.Errorf("matchCIDRSimple(%q, %q) = %v, want %v", tt.ip, tt.target, got, tt.want)
		}
	}
}
