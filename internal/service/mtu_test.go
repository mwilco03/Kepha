package service

import (
	"testing"

	"github.com/mwilco03/kepha/internal/model"
)

// ===================================================================
// EffectiveMTU tests
// ===================================================================

func TestEffectiveMTUStandard(t *testing.T) {
	z := model.Zone{MTU: 1500}
	got := EffectiveMTU(z, "")
	if got != 1500 {
		t.Errorf("EffectiveMTU(1500, \"\") = %d, want 1500", got)
	}
}

func TestEffectiveMTUJumbo(t *testing.T) {
	z := model.Zone{MTU: 9000}
	got := EffectiveMTU(z, "")
	if got != 9000 {
		t.Errorf("EffectiveMTU(9000, \"\") = %d, want 9000", got)
	}
}

func TestEffectiveMTUVXLAN(t *testing.T) {
	z := model.Zone{MTU: 1500}
	got := EffectiveMTU(z, "vxlan")
	want := 1500 - OverheadVXLAN
	if got != want {
		t.Errorf("EffectiveMTU(1500, vxlan) = %d, want %d", got, want)
	}
}

func TestEffectiveMTUGENEVE(t *testing.T) {
	z := model.Zone{MTU: 1500}
	got := EffectiveMTU(z, "geneve")
	want := 1500 - OverheadGENEVE
	if got != want {
		t.Errorf("EffectiveMTU(1500, geneve) = %d, want %d", got, want)
	}
}

func TestEffectiveMTUWireGuard(t *testing.T) {
	z := model.Zone{MTU: 1500}
	got := EffectiveMTU(z, "wireguard")
	want := 1500 - OverheadWG
	if got != want {
		t.Errorf("EffectiveMTU(1500, wireguard) = %d, want %d", got, want)
	}
}

func TestEffectiveMTUJumboVXLAN(t *testing.T) {
	z := model.Zone{MTU: 9000}
	got := EffectiveMTU(z, "vxlan")
	want := 9000 - OverheadVXLAN
	if got != want {
		t.Errorf("EffectiveMTU(9000, vxlan) = %d, want %d", got, want)
	}
}

func TestEffectiveMTUDefaultsTo1500(t *testing.T) {
	z := model.Zone{MTU: 0}
	got := EffectiveMTU(z, "")
	if got != MTUStandard {
		t.Errorf("EffectiveMTU(0, \"\") = %d, want %d", got, MTUStandard)
	}
}

// ===================================================================
// overlayOverhead tests
// ===================================================================

func TestOverlayOverhead(t *testing.T) {
	tests := []struct {
		overlay string
		want    int
	}{
		{"vxlan", OverheadVXLAN},
		{"geneve", OverheadGENEVE},
		{"wireguard", OverheadWG},
		{"VXLAN", OverheadVXLAN}, // case insensitive
		{"", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := overlayOverhead(tt.overlay)
		if got != tt.want {
			t.Errorf("overlayOverhead(%q) = %d, want %d", tt.overlay, got, tt.want)
		}
	}
}

// ===================================================================
// MTUManager service interface tests
// ===================================================================

func TestMTUManagerServiceInterface(t *testing.T) {
	mgr := NewMTUManager()

	if mgr.Name() != "mtu-manager" {
		t.Errorf("Name() = %q, want mtu-manager", mgr.Name())
	}
	if mgr.Status() != StateStopped {
		t.Errorf("initial Status() = %q, want stopped", mgr.Status())
	}
	if mgr.Category() != "network" {
		t.Errorf("Category() = %q, want network", mgr.Category())
	}
}

func TestMTUManagerValidation(t *testing.T) {
	mgr := NewMTUManager()

	// Valid config.
	if err := mgr.Validate(map[string]string{"mss_clamp_value": "1460"}); err != nil {
		t.Errorf("valid MSS value rejected: %v", err)
	}

	// Too low MSS.
	if err := mgr.Validate(map[string]string{"mss_clamp_value": "100"}); err == nil {
		t.Error("MSS value 100 should be rejected (min 536)")
	}

	// Invalid overlay.
	if err := mgr.Validate(map[string]string{"overlay_adjustment": "ipip"}); err == nil {
		t.Error("overlay 'ipip' should be rejected")
	}

	// Valid overlays.
	for _, overlay := range []string{"", "vxlan", "geneve", "wireguard"} {
		if err := mgr.Validate(map[string]string{"overlay_adjustment": overlay}); err != nil {
			t.Errorf("overlay %q should be valid: %v", overlay, err)
		}
	}
}

func TestMTUManagerDefaultConfig(t *testing.T) {
	mgr := NewMTUManager()
	cfg := mgr.DefaultConfig()

	if cfg["mss_clamping"] != "true" {
		t.Errorf("default mss_clamping = %q, want true", cfg["mss_clamping"])
	}
	if cfg["pmtud"] != "true" {
		t.Errorf("default pmtud = %q, want true", cfg["pmtud"])
	}
	if cfg["zone_mtu_enforce"] != "true" {
		t.Errorf("default zone_mtu_enforce = %q, want true", cfg["zone_mtu_enforce"])
	}
}

// ===================================================================
// ApplyZoneMTUs tests
// ===================================================================

func TestApplyZoneMTUsSetsMTU(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	mgr := NewMTUManager()
	// Manually set the config (normally done via Start).
	mgr.cfg = map[string]string{
		"zone_mtu_enforce":   "true",
		"mtu_mismatch_log":   "true",
		"overlay_adjustment": "",
	}

	zones := []model.Zone{
		{Name: "lan", Interface: "eth1", MTU: 9000},
		{Name: "wan", Interface: "eth0", MTU: 1500},
	}

	diags := mgr.ApplyZoneMTUs(zones)

	// Verify MTU was set on both interfaces.
	mock.mu.Lock()
	calls := make([]mtuSetCall, len(mock.MTUSetCalls))
	copy(calls, mock.MTUSetCalls)
	mock.mu.Unlock()

	if len(calls) != 2 {
		t.Fatalf("expected 2 MTU set calls, got %d: %v", len(calls), calls)
	}

	found9000, found1500 := false, false
	for _, c := range calls {
		if c.Iface == "eth1" && c.MTU == 9000 {
			found9000 = true
		}
		if c.Iface == "eth0" && c.MTU == 1500 {
			found1500 = true
		}
	}
	if !found9000 {
		t.Error("expected MTU 9000 to be set on eth1")
	}
	if !found1500 {
		t.Error("expected MTU 1500 to be set on eth0")
	}

	// Should detect mismatch between 9000 and 1500.
	hasMismatch := false
	for _, d := range diags {
		if d.Severity == "warning" {
			hasMismatch = true
		}
	}
	if !hasMismatch {
		t.Error("expected MTU mismatch warning between 9000 and 1500 zones")
	}
}

func TestApplyZoneMTUsSkipsZeroMTU(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	mgr := NewMTUManager()
	mgr.cfg = map[string]string{
		"zone_mtu_enforce": "true",
		"mtu_mismatch_log": "false",
	}

	zones := []model.Zone{
		{Name: "lan", Interface: "eth1", MTU: 0}, // No explicit MTU.
	}

	mgr.ApplyZoneMTUs(zones)

	mock.mu.Lock()
	calls := len(mock.MTUSetCalls)
	mock.mu.Unlock()

	if calls != 0 {
		t.Errorf("expected 0 MTU set calls for MTU=0 zone, got %d", calls)
	}
}

func TestApplyZoneMTUsOverlayAdjustment(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	mgr := NewMTUManager()
	mgr.cfg = map[string]string{
		"zone_mtu_enforce":   "true",
		"mtu_mismatch_log":   "false",
		"overlay_adjustment": "vxlan",
	}

	zones := []model.Zone{
		{Name: "lan", Interface: "eth1", MTU: 1500},
	}

	mgr.ApplyZoneMTUs(zones)

	mock.mu.Lock()
	calls := make([]mtuSetCall, len(mock.MTUSetCalls))
	copy(calls, mock.MTUSetCalls)
	mock.mu.Unlock()

	if len(calls) != 1 {
		t.Fatalf("expected 1 MTU set call, got %d", len(calls))
	}
	// 1500 - 50 (VXLAN overhead) = 1450
	if calls[0].MTU != 1450 {
		t.Errorf("expected MTU 1450 (1500 - VXLAN overhead), got %d", calls[0].MTU)
	}
}

// ===================================================================
// GetMTUStatusFromZones tests
// ===================================================================

func TestGetMTUStatusFromZonesDetectsMismatch(t *testing.T) {
	mock := &mockNetworkManager{
		MTUValues: map[string]int{
			"eth0": 1500,
			"eth1": 9000,
		},
	}
	withMockNet(t, mock)

	zones := []model.Zone{
		{Name: "wan", Interface: "eth0", MTU: 1500},
		{Name: "lan", Interface: "eth1", MTU: 9000},
	}

	st := GetMTUStatusFromZones(zones)

	if len(st.Zones) != 2 {
		t.Fatalf("expected 2 zone entries, got %d", len(st.Zones))
	}

	if len(st.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic for MTU mismatch")
	}

	found := false
	for _, d := range st.Diagnostics {
		if d.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Error("expected warning-severity diagnostic for MTU mismatch")
	}
}

func TestGetMTUStatusFromZonesNoMismatch(t *testing.T) {
	mock := &mockNetworkManager{
		MTUValues: map[string]int{
			"eth0": 1500,
			"eth1": 1500,
		},
	}
	withMockNet(t, mock)

	zones := []model.Zone{
		{Name: "wan", Interface: "eth0"},
		{Name: "lan", Interface: "eth1"},
	}

	st := GetMTUStatusFromZones(zones)

	if len(st.Diagnostics) != 0 {
		t.Errorf("expected no diagnostics when MTUs match, got %d", len(st.Diagnostics))
	}
}

// ===================================================================
// PMTUD sysctl tests
// ===================================================================

func TestMTUManagerPMTUDSysctls(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	mgr := NewMTUManager()
	// Only enable PMTUD, disable everything else.
	cfg := map[string]string{
		"pmtud":        "true",
		"mss_clamping": "false",
	}

	if err := mgr.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Stop()

	calls := mock.getSysctlCalls()

	expected := map[string]string{
		"net.ipv4.ip_no_pmtu_disc": "0",
		"net.ipv4.tcp_mtu_probing": "1",
		"net.ipv4.tcp_base_mss":    "1024",
		"net.ipv4.tcp_min_snd_mss": "536",
	}

	for key, wantVal := range expected {
		gotVal, ok := findSysctl(calls, key)
		if !ok {
			t.Errorf("missing PMTUD sysctl %s", key)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("sysctl %s = %q, want %q", key, gotVal, wantVal)
		}
	}
}

func TestMTUManagerPMTUDDisabled(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	mgr := NewMTUManager()
	cfg := map[string]string{
		"pmtud":        "false",
		"mss_clamping": "false",
	}

	if err := mgr.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Stop()

	calls := mock.getSysctlCalls()
	if len(calls) != 0 {
		t.Errorf("expected no sysctl calls when PMTUD disabled, got %d: %v", len(calls), calls)
	}
}

// ===================================================================
// Constants tests
// ===================================================================

func TestMTUConstants(t *testing.T) {
	// Verify the overhead constants are sane.
	if OverheadVXLAN != 50 {
		t.Errorf("OverheadVXLAN = %d, want 50", OverheadVXLAN)
	}
	if OverheadGENEVE != 54 {
		t.Errorf("OverheadGENEVE = %d, want 54", OverheadGENEVE)
	}
	if OverheadWG != 80 {
		t.Errorf("OverheadWG = %d, want 80", OverheadWG)
	}

	// VXLAN on 1500 = 1450.
	if MTUVXLAN1500 != 1450 {
		t.Errorf("MTUVXLAN1500 = %d, want 1450", MTUVXLAN1500)
	}
	// VXLAN on 9000 = 8950.
	if MTUVXLAN9000 != 8950 {
		t.Errorf("MTUVXLAN9000 = %d, want 8950", MTUVXLAN9000)
	}
}
