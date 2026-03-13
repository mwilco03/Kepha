package xdp

import (
	"testing"
	"time"
)

func TestProbeCapabilities(t *testing.T) {
	caps := ProbeCapabilities()

	if caps.KernelVersion == "" {
		t.Error("kernel version is empty")
	}
	if caps.KernelMajor == 0 && caps.KernelMinor == 0 {
		t.Error("kernel version not parsed")
	}
	t.Logf("Kernel: %s (parsed: %d.%d.%d)", caps.KernelVersion,
		caps.KernelMajor, caps.KernelMinor, caps.KernelPatch)
	t.Logf("BPF: %v, BTF: %v, XDP: %v, Ready: %v",
		caps.BPFSupported, caps.BTFAvailable, caps.XDPSupported, caps.Ready)
	if !caps.Ready {
		t.Logf("Not ready: %s", caps.Reason)
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		input                string
		major, minor, patch int
	}{
		{"5.15.0-91-generic", 5, 15, 0},
		{"6.1.0", 6, 1, 0},
		{"5.10.102", 5, 10, 102},
		{"4.19.0-22-amd64", 4, 19, 0},
		{"6.5.13-1-pve", 6, 5, 13},
	}

	for _, tt := range tests {
		major, minor, patch := parseKernelVersion(tt.input)
		if major != tt.major || minor != tt.minor || patch != tt.patch {
			t.Errorf("parseKernelVersion(%q) = %d.%d.%d, want %d.%d.%d",
				tt.input, major, minor, patch, tt.major, tt.minor, tt.patch)
		}
	}
}

func TestManagerBlocklist(t *testing.T) {
	mgr := NewManager()

	// Add IPv4.
	err := mgr.AddToBlocklist(BlocklistEntry{
		IP:     "192.168.1.100",
		Reason: "manual",
		Source: "admin",
	})
	if err != nil {
		t.Fatalf("AddToBlocklist: %v", err)
	}

	// Add IPv6.
	err = mgr.AddToBlocklist(BlocklistEntry{
		IP:     "2001:db8::1",
		Reason: "threat_feed",
		Source: "abuse.ch",
	})
	if err != nil {
		t.Fatalf("AddToBlocklist IPv6: %v", err)
	}

	if mgr.BlocklistSize() != 2 {
		t.Errorf("blocklist size = %d, want 2", mgr.BlocklistSize())
	}

	entries := mgr.BlocklistEntries()
	if len(entries) != 2 {
		t.Errorf("entries = %d, want 2", len(entries))
	}

	// Remove.
	err = mgr.RemoveFromBlocklist("192.168.1.100")
	if err != nil {
		t.Fatalf("RemoveFromBlocklist: %v", err)
	}
	if mgr.BlocklistSize() != 1 {
		t.Errorf("blocklist size after remove = %d, want 1", mgr.BlocklistSize())
	}

	// Invalid IP.
	err = mgr.AddToBlocklist(BlocklistEntry{IP: "not-an-ip"})
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestManagerACLRules(t *testing.T) {
	mgr := NewManager()

	err := mgr.AddACLRule(ACLRule{
		SrcIP:    "10.0.0.0/8",
		DstIP:    "192.168.1.1",
		Protocol: 6, // TCP
		DstPort:  443,
		Action:   XDP_DROP,
	})
	if err != nil {
		t.Fatalf("AddACLRule: %v", err)
	}

	rules := mgr.ACLRules()
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].ID != 1 {
		t.Errorf("auto-assigned ID = %d, want 1", rules[0].ID)
	}

	// Remove by ID.
	err = mgr.RemoveACLRule(1)
	if err != nil {
		t.Fatalf("RemoveACLRule: %v", err)
	}
	if len(mgr.ACLRules()) != 0 {
		t.Error("rule not removed")
	}

	// Remove non-existent.
	err = mgr.RemoveACLRule(99)
	if err == nil {
		t.Error("expected error for non-existent rule")
	}
}

func TestManagerAttachDetach(t *testing.T) {
	mgr := NewManager()

	err := mgr.AttachInterface("eth0", 2)
	if err != nil {
		t.Fatalf("AttachInterface: %v", err)
	}

	if !mgr.IsRunning() {
		t.Error("should be running after attach")
	}

	ifaces := mgr.AttachedInterfaces()
	if len(ifaces) != 1 || ifaces[0].Name != "eth0" {
		t.Errorf("attached = %v", ifaces)
	}

	stats, err := mgr.GetStats("eth0")
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.Interface != "eth0" {
		t.Errorf("stats.Interface = %q", stats.Interface)
	}

	err = mgr.DetachInterface("eth0")
	if err != nil {
		t.Fatalf("DetachInterface: %v", err)
	}

	if mgr.IsRunning() {
		t.Error("should not be running after detach")
	}

	// Detach non-existent.
	err = mgr.DetachInterface("eth99")
	if err == nil {
		t.Error("expected error for non-existent interface")
	}
}

func TestManagerStatus(t *testing.T) {
	mgr := NewManager()
	mgr.Probe()

	_ = mgr.AddToBlocklist(BlocklistEntry{IP: "1.2.3.4", Reason: "test"})
	_ = mgr.AddACLRule(ACLRule{DstPort: 80, Action: XDP_DROP})
	_ = mgr.AttachInterface("eth0", 2)

	status := mgr.Status()
	if !status.Running {
		t.Error("status should be running")
	}
	if status.BlocklistSize != 1 {
		t.Errorf("blocklist = %d, want 1", status.BlocklistSize)
	}
	if status.ACLRuleCount != 1 {
		t.Errorf("acl rules = %d, want 1", status.ACLRuleCount)
	}
	if status.InterfaceCount != 1 {
		t.Errorf("interfaces = %d, want 1", status.InterfaceCount)
	}
}

func TestIPv4Conversions(t *testing.T) {
	key, err := IPv4ToKey("192.168.1.1")
	if err != nil {
		t.Fatalf("IPv4ToKey: %v", err)
	}
	if key != [4]byte{192, 168, 1, 1} {
		t.Errorf("key = %v", key)
	}

	str := IPv4FromKey(key)
	if str != "192.168.1.1" {
		t.Errorf("IPv4FromKey = %q", str)
	}

	nbo, err := IPv4ToNetworkOrder("192.168.1.1")
	if err != nil {
		t.Fatalf("IPv4ToNetworkOrder: %v", err)
	}
	// 192.168.1.1 in big-endian = 0xC0A80101
	if nbo != 0xC0A80101 {
		t.Errorf("network order = 0x%08X, want 0xC0A80101", nbo)
	}

	// Invalid.
	_, err = IPv4ToKey("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}

	// IPv6 should fail for IPv4ToKey.
	_, err = IPv4ToKey("2001:db8::1")
	if err == nil {
		t.Error("expected error for IPv6 in IPv4ToKey")
	}
}

func TestAttachModeString(t *testing.T) {
	if AttachModeNative.String() != "native" {
		t.Errorf("native = %q", AttachModeNative.String())
	}
	if AttachModeGeneric.String() != "generic" {
		t.Errorf("generic = %q", AttachModeGeneric.String())
	}
	if AttachModeOffload.String() != "offload" {
		t.Errorf("offload = %q", AttachModeOffload.String())
	}
}

func TestBlocklistExpiry(t *testing.T) {
	mgr := NewManager()

	// Add with expiry.
	err := mgr.AddToBlocklist(BlocklistEntry{
		IP:        "10.0.0.1",
		Reason:    "rate_limit",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AddToBlocklist: %v", err)
	}

	entries := mgr.BlocklistEntries()
	if len(entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	if entries[0].ExpiresAt.IsZero() {
		t.Error("expiry should be set")
	}
}
