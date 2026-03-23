package driver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

func newTestDnsmasq(t *testing.T) *Dnsmasq {
	t.Helper()
	store, err := config.NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	confDir := filepath.Join(t.TempDir(), "dnsmasq")
	return NewDnsmasq(store, confDir)
}

func TestGenerateConfig(t *testing.T) {
	d := newTestDnsmasq(t)

	if err := d.GenerateConfig(); err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	// Check main config.
	data, err := os.ReadFile(filepath.Join(d.confDir, "dnsmasq.conf"))
	if err != nil {
		t.Fatalf("read dnsmasq.conf: %v", err)
	}
	conf := string(data)

	if !strings.Contains(conf, "server=1.1.1.1") {
		t.Error("missing upstream DNS server")
	}
	if !strings.Contains(conf, "interface=eth1") {
		t.Error("missing LAN interface")
	}
	if !strings.Contains(conf, "dhcp-range=interface:eth1,10.10.0.50,10.10.0.203,12h") {
		t.Error("missing DHCP range for LAN")
	}
	// WAN should not have DHCP.
	if strings.Contains(conf, "dhcp-range=") && strings.Contains(conf, "eth0") {
		// We need to be more precise here.
		for _, line := range strings.Split(conf, "\n") {
			if strings.Contains(line, "dhcp-range=") && strings.Contains(line, "eth0") {
				t.Error("WAN zone should not have DHCP range")
			}
		}
	}

	// Check static leases (should be empty initially).
	data, err = os.ReadFile(filepath.Join(d.confDir, "static-leases.conf"))
	if err != nil {
		t.Fatalf("read static-leases.conf: %v", err)
	}
	if strings.Contains(string(data), "dhcp-host=") {
		t.Error("static leases should be empty initially")
	}
}

func TestDeriveDHCPRange(t *testing.T) {
	tests := []struct {
		cidr, want string
	}{
		{"10.10.0.0/24", "10.10.0.50,10.10.0.203"},
		{"192.168.1.0/24", "192.168.1.50,192.168.1.203"},
		{"invalid", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := deriveDHCPRange(tt.cidr)
		if got != tt.want {
			t.Errorf("deriveDHCPRange(%q) = %q, want %q", tt.cidr, got, tt.want)
		}
	}
}

func TestParseLeaseFile(t *testing.T) {
	d := newTestDnsmasq(t)
	leaseFile := filepath.Join(t.TempDir(), "leases")

	// Non-existent file returns nil.
	leases, err := d.ParseLeaseFile(leaseFile)
	if err != nil {
		t.Fatalf("ParseLeaseFile (missing): %v", err)
	}
	if leases != nil {
		t.Error("expected nil for missing file")
	}

	// Write sample leases.
	content := "1709746800 aa:bb:cc:dd:ee:01 10.10.0.101 workstation-1\n1709746800 aa:bb:cc:dd:ee:02 10.10.0.102 laptop-2\n"
	os.WriteFile(leaseFile, []byte(content), 0o644)

	leases, err = d.ParseLeaseFile(leaseFile)
	if err != nil {
		t.Fatalf("ParseLeaseFile: %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(leases))
	}
	if leases[0].IP != "10.10.0.101" {
		t.Errorf("expected IP 10.10.0.101, got %s", leases[0].IP)
	}
	if leases[1].Hostname != "laptop-2" {
		t.Errorf("expected hostname laptop-2, got %s", leases[1].Hostname)
	}
}
