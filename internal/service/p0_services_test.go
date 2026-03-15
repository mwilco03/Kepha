package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// VPN Policy Router tests
// ---------------------------------------------------------------------------

func TestVPNPolicyRouter_ServiceInterface(t *testing.T) {
	svc := NewVPNPolicyRouter()
	if svc.Name() != "vpn-policy" {
		t.Fatalf("expected name vpn-policy, got %s", svc.Name())
	}
	if svc.Category() != "vpn" {
		t.Fatalf("expected category vpn, got %s", svc.Category())
	}
	if len(svc.Dependencies()) != 1 || svc.Dependencies()[0] != "vpn-provider" {
		t.Fatalf("expected dependency on vpn-provider, got %v", svc.Dependencies())
	}
	if svc.Status() != StateStopped {
		t.Fatalf("expected initial state stopped, got %s", svc.Status())
	}
}

func TestVPNPolicyRouter_Validate(t *testing.T) {
	svc := NewVPNPolicyRouter()

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr bool
	}{
		{
			name: "valid allowlist",
			cfg: map[string]string{
				"mode":      "allowlist",
				"vpn_iface": "wg-vpn0",
				"policies":  `[{"name":"office","type":"device","match":"192.168.1.100","action":"vpn"}]`,
			},
		},
		{
			name: "valid blocklist",
			cfg: map[string]string{
				"mode":      "blocklist",
				"vpn_iface": "wg-vpn0",
				"policies":  "[]",
			},
		},
		{
			name:    "invalid mode",
			cfg:     map[string]string{"mode": "invalid", "vpn_iface": "wg0"},
			wantErr: true,
		},
		{
			name:    "missing vpn_iface",
			cfg:     map[string]string{"mode": "allowlist", "vpn_iface": ""},
			wantErr: true,
		},
		{
			name: "invalid policy type",
			cfg: map[string]string{
				"mode":      "allowlist",
				"vpn_iface": "wg0",
				"policies":  `[{"name":"bad","type":"invalid","match":"x","action":"vpn"}]`,
			},
			wantErr: true,
		},
		{
			name: "invalid policy action",
			cfg: map[string]string{
				"mode":      "allowlist",
				"vpn_iface": "wg0",
				"policies":  `[{"name":"bad","type":"device","match":"1.2.3.4","action":"invalid"}]`,
			},
			wantErr: true,
		},
		{
			name: "missing policy name",
			cfg: map[string]string{
				"mode":      "allowlist",
				"vpn_iface": "wg0",
				"policies":  `[{"name":"","type":"device","match":"1.2.3.4","action":"vpn"}]`,
			},
			wantErr: true,
		},
		{
			name: "invalid JSON",
			cfg: map[string]string{
				"mode":      "allowlist",
				"vpn_iface": "wg0",
				"policies":  `not json`,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.Validate(tc.cfg)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestVPNPolicyRouter_DefaultConfig(t *testing.T) {
	svc := NewVPNPolicyRouter()
	cfg := svc.DefaultConfig()
	if cfg["mode"] != "allowlist" {
		t.Errorf("expected default mode allowlist, got %s", cfg["mode"])
	}
	if cfg["vpn_iface"] != "wg-vpn0" {
		t.Errorf("expected default vpn_iface wg-vpn0, got %s", cfg["vpn_iface"])
	}
}

func TestVPNPolicy_JSON(t *testing.T) {
	p := VPNPolicy{
		Name:   "office-laptop",
		Type:   "device",
		Match:  "192.168.1.100",
		Action: "vpn",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded VPNPolicy
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != p.Name || decoded.Type != p.Type || decoded.Match != p.Match || decoded.Action != p.Action {
		t.Errorf("round-trip failed: got %+v", decoded)
	}
}

// ---------------------------------------------------------------------------
// Parental Controls tests
// ---------------------------------------------------------------------------

func TestParentalControls_ServiceInterface(t *testing.T) {
	svc := NewParentalControls()
	if svc.Name() != "parental-controls" {
		t.Fatalf("expected name parental-controls, got %s", svc.Name())
	}
	if svc.Category() != "security" {
		t.Fatalf("expected category security, got %s", svc.Category())
	}
}

func TestParentalControls_Validate(t *testing.T) {
	svc := NewParentalControls()

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr bool
	}{
		{
			name: "valid schedule",
			cfg: map[string]string{
				"schedules": `[{"name":"kid-tablet","device_ip":"192.168.1.50","allow_from":"08:00","allow_to":"21:00","days":"all","enabled":true}]`,
			},
		},
		{
			name: "valid content filter",
			cfg: map[string]string{
				"content_filters": `[{"device_ip":"192.168.1.50","categories":["adult","gambling"]}]`,
			},
		},
		{
			name:    "missing device_ip in schedule",
			cfg:     map[string]string{"schedules": `[{"name":"bad","device_ip":"","allow_from":"08:00","allow_to":"21:00"}]`},
			wantErr: true,
		},
		{
			name:    "invalid time format",
			cfg:     map[string]string{"schedules": `[{"name":"bad","device_ip":"1.2.3.4","allow_from":"8am","allow_to":"9pm"}]`},
			wantErr: true,
		},
		{
			name:    "invalid category",
			cfg:     map[string]string{"content_filters": `[{"device_ip":"1.2.3.4","categories":["nonexistent"]}]`},
			wantErr: true,
		},
		{
			name:    "missing device_ip in filter",
			cfg:     map[string]string{"content_filters": `[{"device_ip":"","categories":["adult"]}]`},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.Validate(tc.cfg)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestIsWithinTimeWindow(t *testing.T) {
	// 10:00 AM in UTC on any day.
	refTime := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		now      time.Time
		from     string
		to       string
		expected bool
	}{
		{"within normal window", refTime, "08:00", "22:00", true},
		{"before normal window", time.Date(2026, 3, 15, 7, 0, 0, 0, time.UTC), "08:00", "22:00", false},
		{"after normal window", time.Date(2026, 3, 15, 23, 0, 0, 0, time.UTC), "08:00", "22:00", false},
		{"at start boundary", time.Date(2026, 3, 15, 8, 0, 0, 0, time.UTC), "08:00", "22:00", true},
		{"at end boundary", time.Date(2026, 3, 15, 22, 0, 0, 0, time.UTC), "08:00", "22:00", true},
		{"overnight window within", time.Date(2026, 3, 15, 23, 0, 0, 0, time.UTC), "22:00", "06:00", true},
		{"overnight window outside", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), "22:00", "06:00", false},
		{"no restrictions", refTime, "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isWithinTimeWindow(tc.now, tc.from, tc.to)
			if result != tc.expected {
				t.Errorf("got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"192.168.1.1", []byte{192, 168, 1, 1}},
		{"10.0.0.1", []byte{10, 0, 0, 1}},
		{"0.0.0.0", []byte{0, 0, 0, 0}},
		{"255.255.255.255", []byte{255, 255, 255, 255}},
		{"invalid", nil},
		{"256.1.1.1", nil},
		{"1.2.3", nil},
	}

	for _, tc := range tests {
		result := parseIPv4(tc.input)
		if tc.expected == nil {
			if result != nil {
				t.Errorf("parseIPv4(%q) = %v, want nil", tc.input, result)
			}
		} else {
			if len(result) != len(tc.expected) {
				t.Errorf("parseIPv4(%q) = %v, want %v", tc.input, result, tc.expected)
				continue
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("parseIPv4(%q)[%d] = %d, want %d", tc.input, i, result[i], tc.expected[i])
				}
			}
		}
	}
}

func TestCategoryBlocklistURLs(t *testing.T) {
	urls := CategoryBlocklistURLs()
	required := []string{"adult", "gambling", "social", "malware"}
	for _, cat := range required {
		if _, ok := urls[cat]; !ok {
			t.Errorf("missing category blocklist URL for %q", cat)
		}
	}
}

// ---------------------------------------------------------------------------
// Drop-in Gateway tests
// ---------------------------------------------------------------------------

func TestDropInGateway_ServiceInterface(t *testing.T) {
	svc := NewDropInGateway()
	if svc.Name() != "dropin-gateway" {
		t.Fatalf("expected name dropin-gateway, got %s", svc.Name())
	}
	if svc.Category() != "network" {
		t.Fatalf("expected category network, got %s", svc.Category())
	}
}

func TestDropInGateway_Validate(t *testing.T) {
	svc := NewDropInGateway()

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr bool
	}{
		{
			name: "valid",
			cfg:  map[string]string{"wan_interface": "eth0", "lan_interface": "eth1"},
		},
		{
			name:    "missing wan",
			cfg:     map[string]string{"wan_interface": "", "lan_interface": "eth1"},
			wantErr: true,
		},
		{
			name:    "missing lan",
			cfg:     map[string]string{"wan_interface": "eth0", "lan_interface": ""},
			wantErr: true,
		},
		{
			name:    "same interface",
			cfg:     map[string]string{"wan_interface": "eth0", "lan_interface": "eth0"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.Validate(tc.cfg)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Firmware A/B tests
// ---------------------------------------------------------------------------

func TestFirmwareAB_ServiceInterface(t *testing.T) {
	svc := NewFirmwareAB(t.TempDir())
	if svc.Name() != "firmware-ab" {
		t.Fatalf("expected name firmware-ab, got %s", svc.Name())
	}
	if svc.Category() != "system" {
		t.Fatalf("expected category system, got %s", svc.Category())
	}
}

func TestFirmwareAB_Validate(t *testing.T) {
	svc := NewFirmwareAB(t.TempDir())

	err := svc.Validate(map[string]string{
		"slot_a_device": "/dev/sda1",
		"slot_b_device": "/dev/sda2",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = svc.Validate(map[string]string{
		"slot_a_device": "",
		"slot_b_device": "/dev/sda2",
	})
	if err == nil {
		t.Error("expected error for missing slot_a_device")
	}
}

func TestFirmwareAB_SlotStatePersistence(t *testing.T) {
	dir := t.TempDir()
	svc := NewFirmwareAB(dir)

	cfg := svc.DefaultConfig()
	slots := svc.initializeSlots(cfg)

	if err := svc.saveSlotState(slots); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := svc.loadSlotState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 slots, got %d", len(loaded))
	}
	if loaded[0].Label != "A" || loaded[1].Label != "B" {
		t.Errorf("unexpected labels: %s, %s", loaded[0].Label, loaded[1].Label)
	}
	if !loaded[0].Active || loaded[1].Active {
		t.Error("slot A should be active, slot B should not")
	}
	if !loaded[0].Healthy || loaded[1].Healthy {
		t.Error("slot A should be healthy, slot B should not")
	}
}

func TestFirmwareAB_PrepareUpdate(t *testing.T) {
	dir := t.TempDir()
	svc := NewFirmwareAB(dir)

	// Initialize slot state.
	cfg := svc.DefaultConfig()
	slots := svc.initializeSlots(cfg)
	svc.saveSlotState(slots)

	device, err := svc.PrepareUpdate("2.0.0")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if device != cfg["slot_b_device"] {
		t.Errorf("expected device %s, got %s", cfg["slot_b_device"], device)
	}

	// Verify state was saved.
	loaded, _ := svc.loadSlotState()
	inactive := svc.inactiveSlot(loaded)
	if inactive.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", inactive.Version)
	}
	if inactive.Healthy {
		t.Error("inactive slot should not be healthy after prepare")
	}
}

func TestFirmwareAB_ConfirmBoot(t *testing.T) {
	dir := t.TempDir()
	svc := NewFirmwareAB(dir)

	cfg := svc.DefaultConfig()
	slots := svc.initializeSlots(cfg)
	slots[0].Healthy = false // Simulate pending boot.
	slots[0].BootCount = 1
	svc.saveSlotState(slots)

	if err := svc.ConfirmBoot(); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	loaded, _ := svc.loadSlotState()
	active := svc.activeSlot(loaded)
	if !active.Healthy {
		t.Error("active slot should be healthy after confirm")
	}
	if active.BootCount != 0 {
		t.Errorf("boot count should be reset to 0, got %d", active.BootCount)
	}
}

func TestFirmwareAB_RollbackMarker(t *testing.T) {
	dir := t.TempDir()
	svc := NewFirmwareAB(dir)
	svc.stateDir = dir

	cfg := svc.DefaultConfig()
	slots := svc.initializeSlots(cfg)
	// Slot A active but unhealthy; slot B is the fallback.
	slots[0].Healthy = false
	slots[1].Healthy = true
	svc.saveSlotState(slots)

	svc.triggerRollback(slots)

	// Check rollback marker was written.
	markerPath := filepath.Join(dir, "rollback-pending")
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		t.Error("rollback marker file should exist")
	}
}

// ---------------------------------------------------------------------------
// fwmarkBytes test
// ---------------------------------------------------------------------------

func TestFwmarkBytes(t *testing.T) {
	tests := []struct {
		input    uint32
		expected []byte
	}{
		{0x100, []byte{0x00, 0x01, 0x00, 0x00}},
		{0, []byte{0x00, 0x00, 0x00, 0x00}},
		{1, []byte{0x01, 0x00, 0x00, 0x00}},
		{0xFF, []byte{0xFF, 0x00, 0x00, 0x00}},
	}

	for _, tc := range tests {
		result := fwmarkBytes(tc.input)
		if len(result) != 4 {
			t.Fatalf("fwmarkBytes(%d): expected 4 bytes, got %d", tc.input, len(result))
		}
		for i := range result {
			if result[i] != tc.expected[i] {
				t.Errorf("fwmarkBytes(0x%X)[%d] = 0x%02X, want 0x%02X", tc.input, i, result[i], tc.expected[i])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// DeviceSchedule JSON round-trip
// ---------------------------------------------------------------------------

func TestDeviceSchedule_JSON(t *testing.T) {
	s := DeviceSchedule{
		Name:      "kid-tablet",
		DeviceIP:  "192.168.1.50",
		AllowFrom: "08:00",
		AllowTo:   "21:00",
		Days:      "mon,tue,wed,thu,fri",
		Enabled:   true,
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeviceSchedule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != s {
		t.Errorf("round-trip failed: got %+v", decoded)
	}
}
