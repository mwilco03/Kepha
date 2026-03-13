package inspect

import (
	"testing"
	"time"
)

func TestAnomalyDetector_FirstObservation(t *testing.T) {
	d, err := NewAnomalyDetector(nil)
	if err != nil {
		t.Fatalf("NewAnomalyDetector: %v", err)
	}

	// First observation — no alert.
	alert := d.CheckFingerprint("192.168.1.100", "ja4", "t13d1516h2_abc_def", "example.com")
	if alert != nil {
		t.Error("expected no alert on first observation")
	}
}

func TestAnomalyDetector_SameFingerprint(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	d.CheckFingerprint("192.168.1.100", "ja4", "t13d1516h2_abc_def", "example.com")

	// Same fingerprint — no alert.
	alert := d.CheckFingerprint("192.168.1.100", "ja4", "t13d1516h2_abc_def", "example.com")
	if alert != nil {
		t.Error("expected no alert when fingerprint unchanged")
	}
}

func TestAnomalyDetector_FingerprintChanged(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	d.CheckFingerprint("192.168.1.100", "ja4", "t13d1516h2_abc_def", "example.com")

	// Different fingerprint — alert!
	alert := d.CheckFingerprint("192.168.1.100", "ja4", "t13d1516h2_xyz_uvw", "example.com")
	if alert == nil {
		t.Fatal("expected alert on fingerprint change")
	}

	if alert.SrcIP != "192.168.1.100" {
		t.Errorf("src_ip = %q", alert.SrcIP)
	}
	if alert.OldHash != "t13d1516h2_abc_def" {
		t.Errorf("old_hash = %q", alert.OldHash)
	}
	if alert.NewHash != "t13d1516h2_xyz_uvw" {
		t.Errorf("new_hash = %q", alert.NewHash)
	}
	if alert.Excluded {
		t.Error("alert should not be excluded")
	}
}

func TestAnomalyDetector_ExclusionByIP(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// Add exclusion for this IP.
	err := d.AddExclusion(Exclusion{
		Type:   "ip",
		Value:  "192.168.1.100",
		Reason: "test device, frequent updates",
	})
	if err != nil {
		t.Fatalf("AddExclusion: %v", err)
	}

	d.CheckFingerprint("192.168.1.100", "ja4", "hash_a", "")

	// Change — should be excluded.
	alert := d.CheckFingerprint("192.168.1.100", "ja4", "hash_b", "")
	if alert == nil {
		t.Fatal("expected alert (even if excluded)")
	}
	if !alert.Excluded {
		t.Error("alert should be excluded by IP rule")
	}
}

func TestAnomalyDetector_ExclusionByHash(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// Exclude transitions TO this hash (e.g., known browser update).
	err := d.AddExclusion(Exclusion{
		Type:   "hash",
		Value:  "hash_new_version",
		Reason: "Chrome 120 update fingerprint",
	})
	if err != nil {
		t.Fatalf("AddExclusion: %v", err)
	}

	d.CheckFingerprint("10.0.0.1", "ja4", "hash_old_version", "")
	alert := d.CheckFingerprint("10.0.0.1", "ja4", "hash_new_version", "")
	if alert == nil {
		t.Fatal("expected alert")
	}
	if !alert.Excluded {
		t.Error("alert should be excluded by hash rule")
	}
}

func TestAnomalyDetector_ExclusionByTransition(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// Exclude specific transition pair.
	err := d.AddExclusion(Exclusion{
		Type:   "transition",
		Value:  "hash_v1→hash_v2",
		Reason: "planned update from v1 to v2",
	})
	if err != nil {
		t.Fatalf("AddExclusion: %v", err)
	}

	d.CheckFingerprint("10.0.0.1", "ja4", "hash_v1", "")
	alert := d.CheckFingerprint("10.0.0.1", "ja4", "hash_v2", "")
	if alert == nil {
		t.Fatal("expected alert")
	}
	if !alert.Excluded {
		t.Error("alert should be excluded by transition rule")
	}

	// But a different transition should NOT be excluded.
	d.CheckFingerprint("10.0.0.2", "ja4", "hash_v1", "")
	alert2 := d.CheckFingerprint("10.0.0.2", "ja4", "hash_v3", "")
	if alert2 == nil {
		t.Fatal("expected alert for non-excluded transition")
	}
	if alert2.Excluded {
		t.Error("v1→v3 transition should NOT be excluded")
	}
}

func TestAnomalyDetector_ExclusionExpiry(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// Add time-bounded exclusion that already expired.
	err := d.AddExclusion(Exclusion{
		Type:      "ip",
		Value:     "10.0.0.1",
		Reason:    "maintenance window",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired.
	})
	if err != nil {
		t.Fatalf("AddExclusion: %v", err)
	}

	d.CheckFingerprint("10.0.0.1", "ja4", "hash_a", "")
	alert := d.CheckFingerprint("10.0.0.1", "ja4", "hash_b", "")
	if alert == nil {
		t.Fatal("expected alert")
	}
	if alert.Excluded {
		t.Error("expired exclusion should not suppress alert")
	}
}

func TestAnomalyDetector_SeverityEscalation(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// First observation.
	d.CheckFingerprint("10.0.0.1", "ja4", "hash1", "")
	// First change = warning.
	a1 := d.CheckFingerprint("10.0.0.1", "ja4", "hash2", "")
	if a1 == nil || a1.Severity != "warning" {
		t.Errorf("first change severity = %q, want warning", a1.Severity)
	}

	// More changes escalate severity.
	d.CheckFingerprint("10.0.0.1", "ja4", "hash3", "")
	d.CheckFingerprint("10.0.0.1", "ja4", "hash4", "")
	a4 := d.CheckFingerprint("10.0.0.1", "ja4", "hash5", "")
	if a4 == nil {
		t.Fatal("expected alert")
	}
	// After 3+ changes, severity should be "high".
	if a4.Severity != "high" {
		t.Errorf("multi-change severity = %q, want high", a4.Severity)
	}
}

func TestAnomalyDetector_DifferentTypes(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// JA4 and JA4T are tracked separately.
	d.CheckFingerprint("10.0.0.1", "ja4", "tls_hash", "")
	d.CheckFingerprint("10.0.0.1", "ja4t", "tcp_hash", "")

	// Change JA4T — should alert.
	alert := d.CheckFingerprint("10.0.0.1", "ja4t", "tcp_hash_new", "")
	if alert == nil {
		t.Fatal("expected alert for ja4t change")
	}
	if alert.FPType != "ja4t" {
		t.Errorf("type = %q, want ja4t", alert.FPType)
	}

	// JA4 unchanged — no alert.
	alert2 := d.CheckFingerprint("10.0.0.1", "ja4", "tls_hash", "")
	if alert2 != nil {
		t.Error("expected no alert when ja4 unchanged")
	}
}

func TestAnomalyDetector_RemoveExclusion(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	err := d.AddExclusion(Exclusion{
		Type:  "ip",
		Value: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("AddExclusion: %v", err)
	}

	exclusions := d.ListExclusions()
	if len(exclusions) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(exclusions))
	}

	// In-memory mode, ID will be 0. Just remove by finding it.
	for _, ex := range exclusions {
		d.RemoveExclusion(ex.ID)
	}

	if len(d.ListExclusions()) != 0 {
		t.Error("exclusion should be removed")
	}
}

func TestAnomalyDetector_ListAlerts(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	d.CheckFingerprint("10.0.0.1", "ja4", "hash1", "")
	d.CheckFingerprint("10.0.0.1", "ja4", "hash2", "")
	d.CheckFingerprint("10.0.0.1", "ja4", "hash3", "")

	alerts, err := d.ListAlerts(10)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) != 2 { // Two changes: hash1→hash2, hash2→hash3.
		t.Errorf("alerts = %d, want 2", len(alerts))
	}
}

func TestAnomalyDetector_ClearAlerts(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	d.CheckFingerprint("10.0.0.1", "ja4", "hash1", "")
	d.CheckFingerprint("10.0.0.1", "ja4", "hash2", "")

	err := d.ClearAlerts()
	if err != nil {
		t.Fatalf("ClearAlerts: %v", err)
	}

	alerts, _ := d.ListAlerts(10)
	if len(alerts) != 0 {
		t.Errorf("alerts after clear = %d, want 0", len(alerts))
	}
}

func TestExclusionValidation(t *testing.T) {
	d, _ := NewAnomalyDetector(nil)

	// Missing type.
	err := d.AddExclusion(Exclusion{Value: "10.0.0.1"})
	if err == nil {
		t.Error("expected error for missing type")
	}

	// Missing value.
	err = d.AddExclusion(Exclusion{Type: "ip"})
	if err == nil {
		t.Error("expected error for missing value")
	}

	// Invalid type.
	err = d.AddExclusion(Exclusion{Type: "invalid", Value: "foo"})
	if err == nil {
		t.Error("expected error for invalid type")
	}
}
