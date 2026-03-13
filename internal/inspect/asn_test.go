package inspect

import (
	"net"
	"testing"
)

func TestStaticASNResolver(t *testing.T) {
	r := NewStaticASNResolver()
	r.AddMapping("8.8.8.8", 15169, "GOOGLE")
	r.AddMapping("1.1.1.1", 13335, "CLOUDFLARENET")

	// Match.
	result := r.Resolve(net.ParseIP("8.8.8.8"))
	if result == nil {
		t.Fatal("expected ASN result for 8.8.8.8")
	}
	if result.Number != 15169 {
		t.Errorf("asn = %d, want 15169", result.Number)
	}
	if result.Org != "GOOGLE" {
		t.Errorf("org = %q, want GOOGLE", result.Org)
	}
	if result.String() != "AS15169" {
		t.Errorf("string = %q, want AS15169", result.String())
	}

	// No match.
	if r.Resolve(net.ParseIP("10.0.0.1")) != nil {
		t.Error("should not resolve private IP")
	}

	r.Close()
}

func TestIOCStore_ASNMatch(t *testing.T) {
	s := newTestStore()

	// Set up a static resolver.
	resolver := NewStaticASNResolver()
	resolver.AddMapping("52.94.76.1", 14618, "AMAZON-AES")
	resolver.AddMapping("8.8.8.8", 15169, "GOOGLE")
	s.SetASNResolver(resolver)

	// Add ASN IOC.
	_, err := s.AddIOC(IOC{
		Type:     IOCTypeASN,
		Value:    "AS14618",
		Severity: IOCSeverityHigh,
		Reason:   "suspicious AWS traffic",
	})
	if err != nil {
		t.Fatalf("AddIOC: %v", err)
	}

	// MatchIP should resolve the IP to AS14618 and match.
	ioc := s.MatchIP("52.94.76.1")
	if ioc == nil {
		t.Fatal("expected ASN match for 52.94.76.1 (AS14618)")
	}
	if ioc.Type != IOCTypeASN {
		t.Errorf("type = %q, want asn", ioc.Type)
	}
	if ioc.Value != "AS14618" {
		t.Errorf("value = %q, want AS14618", ioc.Value)
	}

	// Google IP should not match (no ASN IOC for AS15169).
	if s.MatchIP("8.8.8.8") != nil {
		t.Error("should not match 8.8.8.8 (no IOC for AS15169)")
	}

	// IP with no ASN mapping should not match.
	if s.MatchIP("192.168.1.1") != nil {
		t.Error("should not match private IP with no ASN")
	}
}

func TestIOCStore_ASNMatch_Priority(t *testing.T) {
	s := newTestStore()

	resolver := NewStaticASNResolver()
	resolver.AddMapping("52.94.76.1", 14618, "AMAZON-AES")
	s.SetASNResolver(resolver)

	// Add both an IP IOC and an ASN IOC.
	s.AddIOC(IOC{Type: IOCTypeIP, Value: "52.94.76.1", Severity: IOCSeverityCritical, Reason: "exact IP"})
	s.AddIOC(IOC{Type: IOCTypeASN, Value: "AS14618", Severity: IOCSeverityMedium, Reason: "whole ASN"})

	// Exact IP should match first (higher priority).
	ioc := s.MatchIP("52.94.76.1")
	if ioc == nil {
		t.Fatal("expected match")
	}
	if ioc.Type != IOCTypeIP {
		t.Errorf("type = %q, want ip (exact match should take priority)", ioc.Type)
	}
}

func TestIOCStore_ASNMatch_NoResolver(t *testing.T) {
	s := newTestStore()
	// No resolver set — ASN IOCs should be silently skipped.

	s.AddIOC(IOC{Type: IOCTypeASN, Value: "AS14618", Severity: IOCSeverityHigh})

	// Should not crash, just return nil.
	if s.MatchIP("52.94.76.1") != nil {
		t.Error("should not match without resolver")
	}
}

func TestIOCStore_ASNGetAndRemove(t *testing.T) {
	s := newTestStore()

	s.AddIOC(IOC{Type: IOCTypeASN, Value: "AS14618", Severity: IOCSeverityHigh})

	ioc := s.GetIOC(IOCTypeASN, "AS14618")
	if ioc == nil {
		t.Fatal("expected IOC")
	}

	if err := s.RemoveIOC(IOCTypeASN, "AS14618"); err != nil {
		t.Fatalf("RemoveIOC: %v", err)
	}

	if s.GetIOC(IOCTypeASN, "AS14618") != nil {
		t.Error("should be removed")
	}
}

func TestIOCStore_ASNResponseTemplate(t *testing.T) {
	s := newTestStore()

	// ASN IOC with medium severity should match the "asn_block" template.
	ioc := &IOC{Type: IOCTypeASN, Severity: IOCSeverityMedium}
	tmpl := s.MatchResponse(ioc)
	if tmpl == nil {
		t.Fatal("expected response template for ASN IOC")
	}
	if tmpl.Name != "asn_block" {
		t.Errorf("template = %q, want asn_block", tmpl.Name)
	}

	// ASN IOC with high severity should still match asn_block (most specific for ASN type)
	// unless an IP template also matches.
	ioc2 := &IOC{Type: IOCTypeASN, Severity: IOCSeverityHigh}
	tmpl2 := s.MatchResponse(ioc2)
	if tmpl2 == nil {
		t.Fatal("expected response template")
	}
}

func TestIOCStore_ASNStats(t *testing.T) {
	s := newTestStore()
	s.AddIOC(IOC{Type: IOCTypeASN, Value: "AS14618"})
	s.AddIOC(IOC{Type: IOCTypeASN, Value: "AS4134"})

	stats := s.Stats()
	if stats.TotalASNs != 2 {
		t.Errorf("asns = %d, want 2", stats.TotalASNs)
	}
	if stats.ASNResolverActive {
		t.Error("resolver should be inactive")
	}

	s.SetASNResolver(NewStaticASNResolver())
	stats = s.Stats()
	if !stats.ASNResolverActive {
		t.Error("resolver should be active")
	}
}

func TestMaxMindASNResolver_NilSafe(t *testing.T) {
	// nil resolver should not panic.
	var r *MaxMindASNResolver
	if r.Resolve(net.ParseIP("8.8.8.8")) != nil {
		t.Error("nil resolver should return nil")
	}
}

func TestNewMaxMindASNResolver_MissingFile(t *testing.T) {
	// Empty path returns nil resolver, no error.
	r, err := NewMaxMindASNResolver("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Error("empty path should return nil resolver")
	}

	// Non-existent file returns nil resolver, no error (graceful degradation).
	r, err = NewMaxMindASNResolver("/nonexistent/path.mmdb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Error("missing file should return nil resolver")
	}
}
