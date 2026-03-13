package inspect

import (
	"testing"
	"time"
)

func newTestStore() *IOCStore {
	s, _ := NewIOCStore(nil) // In-memory only, no SQLite.
	return s
}

func TestIOCStore_AddAndMatch(t *testing.T) {
	s := newTestStore()

	_, err := s.AddIOC(IOC{
		Type:     IOCTypeIP,
		Value:    "10.0.0.1",
		Severity: IOCSeverityHigh,
		Reason:   "known scanner",
	})
	if err != nil {
		t.Fatalf("AddIOC: %v", err)
	}

	// Should match.
	ioc := s.MatchIP("10.0.0.1")
	if ioc == nil {
		t.Fatal("expected match for 10.0.0.1")
	}
	if ioc.Severity != IOCSeverityHigh {
		t.Errorf("severity = %q, want high", ioc.Severity)
	}

	// Should not match different IP.
	if s.MatchIP("10.0.0.2") != nil {
		t.Error("should not match 10.0.0.2")
	}
}

func TestIOCStore_FingerprintMatch(t *testing.T) {
	s := newTestStore()

	_, err := s.AddIOC(IOC{
		Type:     IOCTypeJA4,
		Value:    "t13d1516h2_8daaf6152771_e5627efa2ab1",
		Severity: IOCSeverityCritical,
		Reason:   "Cobalt Strike beacon fingerprint",
	})
	if err != nil {
		t.Fatalf("AddIOC: %v", err)
	}

	ioc := s.MatchFingerprint("t13d1516h2_8daaf6152771_e5627efa2ab1")
	if ioc == nil {
		t.Fatal("expected fingerprint match")
	}
	if ioc.Severity != IOCSeverityCritical {
		t.Errorf("severity = %q, want critical", ioc.Severity)
	}

	if s.MatchFingerprint("t13d1516h2_different") != nil {
		t.Error("should not match different fingerprint")
	}
}

func TestIOCStore_DomainMatch(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{
		Type:     IOCTypeDomain,
		Value:    "evil.example.com",
		Severity: IOCSeverityHigh,
	})

	if s.MatchDomain("evil.example.com") == nil {
		t.Error("expected domain match")
	}
	if s.MatchDomain("good.example.com") != nil {
		t.Error("should not match different domain")
	}
}

func TestIOCStore_CIDRMatch(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{
		Type:     IOCTypeCIDR,
		Value:    "192.168.1.0/24",
		Severity: IOCSeverityMedium,
		Reason:   "suspicious subnet",
	})

	// Should match IPs in the /24.
	if s.MatchIP("192.168.1.50") == nil {
		t.Error("expected CIDR match for .50")
	}
	if s.MatchIP("192.168.1.200") == nil {
		t.Error("expected CIDR match for .200")
	}

	// Should not match outside the /24.
	if s.MatchIP("192.168.2.1") != nil {
		t.Error("should not match .2.1")
	}
}

func TestIOCStore_Expiry(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{
		Type:      IOCTypeIP,
		Value:     "10.0.0.1",
		Severity:  IOCSeverityHigh,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired.
	})

	if s.MatchIP("10.0.0.1") != nil {
		t.Error("expired IOC should not match")
	}
}

func TestIOCStore_Remove(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{Type: IOCTypeIP, Value: "10.0.0.1", Severity: IOCSeverityHigh})

	if err := s.RemoveIOC(IOCTypeIP, "10.0.0.1"); err != nil {
		t.Fatalf("RemoveIOC: %v", err)
	}

	if s.MatchIP("10.0.0.1") != nil {
		t.Error("removed IOC should not match")
	}

	// Remove non-existent.
	if err := s.RemoveIOC(IOCTypeIP, "99.99.99.99"); err == nil {
		t.Error("expected error for non-existent IOC")
	}
}

func TestIOCStore_Validation(t *testing.T) {
	s := newTestStore()

	// Empty value.
	if _, err := s.AddIOC(IOC{Type: IOCTypeIP}); err == nil {
		t.Error("expected error for empty value")
	}

	// Empty type.
	if _, err := s.AddIOC(IOC{Value: "10.0.0.1"}); err == nil {
		t.Error("expected error for empty type")
	}
}

func TestIOCStore_DefaultSource(t *testing.T) {
	s := newTestStore()

	ioc, err := s.AddIOC(IOC{Type: IOCTypeIP, Value: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if ioc.Source != IOCSourceManual {
		t.Errorf("default source = %q, want manual", ioc.Source)
	}
	if ioc.Severity != IOCSeverityMedium {
		t.Errorf("default severity = %q, want medium", ioc.Severity)
	}
}

func TestIOCStore_BulkAdd(t *testing.T) {
	s := newTestStore()

	iocs := []IOC{
		{Type: IOCTypeIP, Value: "1.2.3.4", Severity: IOCSeverityHigh},
		{Type: IOCTypeIP, Value: "5.6.7.8", Severity: IOCSeverityCritical},
		{Type: IOCTypeDomain, Value: "bad.com", Severity: IOCSeverityMedium},
	}

	added, err := s.BulkAddIOCs(iocs)
	if err != nil {
		t.Fatalf("BulkAddIOCs: %v", err)
	}
	if added != 3 {
		t.Errorf("added = %d, want 3", added)
	}

	if s.MatchIP("1.2.3.4") == nil {
		t.Error("should match 1.2.3.4 after bulk add")
	}
	if s.MatchDomain("bad.com") == nil {
		t.Error("should match bad.com after bulk add")
	}
}

func TestIOCStore_HitCount(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{Type: IOCTypeIP, Value: "10.0.0.1", Severity: IOCSeverityHigh})

	// Match 3 times.
	s.MatchIP("10.0.0.1")
	s.MatchIP("10.0.0.1")
	s.MatchIP("10.0.0.1")

	ioc := s.GetIOC(IOCTypeIP, "10.0.0.1")
	if ioc == nil {
		t.Fatal("expected IOC")
	}
	if ioc.HitCount != 3 {
		t.Errorf("hit_count = %d, want 3", ioc.HitCount)
	}
}

func TestIOCStore_MatchResponse_ThreatBlock(t *testing.T) {
	s := newTestStore()

	ioc := &IOC{Type: IOCTypeIP, Severity: IOCSeverityHigh}
	tmpl := s.MatchResponse(ioc)
	if tmpl == nil {
		t.Fatal("expected response template for high-severity IP")
	}
	if tmpl.Name != "threat_block" {
		t.Errorf("template = %q, want threat_block", tmpl.Name)
	}
}

func TestIOCStore_MatchResponse_Critical(t *testing.T) {
	s := newTestStore()

	ioc := &IOC{Type: IOCTypeIP, Severity: IOCSeverityCritical}
	tmpl := s.MatchResponse(ioc)
	if tmpl == nil {
		t.Fatal("expected response template for critical IP")
	}
	// Critical should match the more specific "critical_full" template.
	if tmpl.Name != "critical_full" {
		t.Errorf("template = %q, want critical_full", tmpl.Name)
	}
}

func TestIOCStore_MatchResponse_LowSeverity(t *testing.T) {
	s := newTestStore()

	ioc := &IOC{Type: IOCTypeIP, Severity: IOCSeverityLow}
	tmpl := s.MatchResponse(ioc)
	// Low severity doesn't meet any template's minimum.
	if tmpl != nil {
		t.Errorf("low severity should not match any template, got %q", tmpl.Name)
	}
}

func TestIOCStore_MatchResponse_Fingerprint(t *testing.T) {
	s := newTestStore()

	ioc := &IOC{Type: IOCTypeJA4, Severity: IOCSeverityHigh}
	tmpl := s.MatchResponse(ioc)
	if tmpl == nil {
		t.Fatal("expected template for JA4 fingerprint")
	}
	if tmpl.Name != "fingerprint_block" {
		t.Errorf("template = %q, want fingerprint_block", tmpl.Name)
	}
}

func TestIOCStore_MatchResponse_Nil(t *testing.T) {
	s := newTestStore()
	if s.MatchResponse(nil) != nil {
		t.Error("nil IOC should return nil template")
	}
}

func TestIOCStore_CustomTemplate(t *testing.T) {
	s := newTestStore()

	err := s.AddTemplate(ResponseTemplate{
		Name:        "custom_block",
		IOCType:     IOCTypeDomain,
		MinSeverity: IOCSeverityMedium,
		Techniques:  []string{"bandwidth"},
	})
	if err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	ioc := &IOC{Type: IOCTypeDomain, Severity: IOCSeverityMedium}
	tmpl := s.MatchResponse(ioc)
	if tmpl == nil {
		t.Fatal("expected custom template match")
	}
	if tmpl.Name != "custom_block" {
		t.Errorf("template = %q, want custom_block", tmpl.Name)
	}
}

func TestIOCStore_RemoveTemplate(t *testing.T) {
	s := newTestStore()

	initial := len(s.Templates())

	err := s.RemoveTemplate("threat_block")
	if err != nil {
		t.Fatalf("RemoveTemplate: %v", err)
	}

	if len(s.Templates()) != initial-1 {
		t.Error("template count should decrease by 1")
	}

	if err := s.RemoveTemplate("nonexistent"); err == nil {
		t.Error("expected error for non-existent template")
	}
}

func TestIOCStore_Stats(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{Type: IOCTypeIP, Value: "1.2.3.4"})
	s.AddIOC(IOC{Type: IOCTypeCIDR, Value: "10.0.0.0/8"})
	s.AddIOC(IOC{Type: IOCTypeJA4, Value: "hash123"})
	s.AddIOC(IOC{Type: IOCTypeDomain, Value: "evil.com"})

	stats := s.Stats()
	if stats.TotalIPs != 1 {
		t.Errorf("ips = %d, want 1", stats.TotalIPs)
	}
	if stats.TotalCIDRs != 1 {
		t.Errorf("cidrs = %d, want 1", stats.TotalCIDRs)
	}
	if stats.TotalFingerprints != 1 {
		t.Errorf("fingerprints = %d, want 1", stats.TotalFingerprints)
	}
	if stats.TotalDomains != 1 {
		t.Errorf("domains = %d, want 1", stats.TotalDomains)
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(IOCSeverityLow) >= severityRank(IOCSeverityMedium) {
		t.Error("low should rank below medium")
	}
	if severityRank(IOCSeverityMedium) >= severityRank(IOCSeverityHigh) {
		t.Error("medium should rank below high")
	}
	if severityRank(IOCSeverityHigh) >= severityRank(IOCSeverityCritical) {
		t.Error("high should rank below critical")
	}
}

func TestJoinSplitTags(t *testing.T) {
	tags := []string{"c2", "apt", "scanner"}
	joined := joinTags(tags)
	if joined != "c2,apt,scanner" {
		t.Errorf("joined = %q", joined)
	}

	split := splitTags(joined)
	if len(split) != 3 {
		t.Fatalf("split = %d, want 3", len(split))
	}
	if split[0] != "c2" || split[1] != "apt" || split[2] != "scanner" {
		t.Errorf("split = %v", split)
	}

	// Empty.
	if splitTags("") != nil {
		t.Error("empty should return nil")
	}
	if joinTags(nil) != "" {
		t.Error("nil should return empty")
	}
}

func TestIOCStore_UpsertBehavior(t *testing.T) {
	s := newTestStore()

	// Add with medium severity.
	s.AddIOC(IOC{Type: IOCTypeIP, Value: "10.0.0.1", Severity: IOCSeverityMedium, Reason: "first"})

	// Add same IOC with high severity — should update.
	s.AddIOC(IOC{Type: IOCTypeIP, Value: "10.0.0.1", Severity: IOCSeverityHigh, Reason: "second"})

	ioc := s.GetIOC(IOCTypeIP, "10.0.0.1")
	if ioc == nil {
		t.Fatal("expected IOC")
	}
	// In-memory store should have the latest version.
	if ioc.Severity != IOCSeverityHigh {
		t.Errorf("severity = %q after upsert, want high", ioc.Severity)
	}
}

func TestMatchCIDRNet(t *testing.T) {
	tests := []struct {
		ip, cidr string
		want     bool
	}{
		{"192.168.1.50", "192.168.1.0/24", true},
		{"192.168.2.1", "192.168.1.0/24", false},
		{"10.0.5.5", "10.0.0.0/8", true},
		{"10.0.0.1", "10.0.0.1", true},
		{"10.0.0.2", "10.0.0.1", false},
	}
	for _, tt := range tests {
		got := matchCIDRNet(tt.ip, tt.cidr)
		if got != tt.want {
			t.Errorf("matchCIDRNet(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
		}
	}
}
