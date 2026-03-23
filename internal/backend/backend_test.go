package backend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSysctlSetGet(t *testing.T) {
	nm := NewLinuxNetworkManager()

	// Test reading a known sysctl value.
	val, err := nm.SysctlGet("kernel.hostname")
	if err != nil {
		t.Skipf("cannot read sysctl (maybe not root): %v", err)
	}
	if val == "" {
		t.Error("expected non-empty hostname")
	}
}

func TestParseTCPState(t *testing.T) {
	tests := []struct {
		hex  string
		want string
	}{
		{"01", "ESTABLISHED"},
		{"0A", "LISTEN"},
		{"06", "TIME_WAIT"},
		{"FF", "FF"},
	}
	for _, tt := range tests {
		got := parseTCPState(tt.hex)
		if got != tt.want {
			t.Errorf("parseTCPState(%q) = %q, want %q", tt.hex, got, tt.want)
		}
	}
}

func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0100007F:1F90", "127.0.0.1:8080"},
		{"00000000:0000", "0.0.0.0:0"},
	}
	for _, tt := range tests {
		got := parseHexAddr(tt.input)
		if got != tt.want {
			t.Errorf("parseHexAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseConntrackLine(t *testing.T) {
	line := "ipv4     2 tcp      6 299 ESTABLISHED src=192.168.1.1 dst=93.184.216.34 sport=54321 dport=443 bytes=1234 packets=10 src=93.184.216.34 dst=192.168.1.1 sport=443 dport=54321 bytes=5678 packets=20 [ASSURED] mark=0 use=2"

	entry := parseConntrackLine(line)

	if entry.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", entry.Protocol)
	}
	if entry.SrcAddr != "192.168.1.1" {
		t.Errorf("src = %q, want 192.168.1.1", entry.SrcAddr)
	}
	if entry.DstAddr != "93.184.216.34" {
		t.Errorf("dst = %q, want 93.184.216.34", entry.DstAddr)
	}
	if entry.SrcPort != 54321 {
		t.Errorf("sport = %d, want 54321", entry.SrcPort)
	}
	if entry.DstPort != 443 {
		t.Errorf("dport = %d, want 443", entry.DstPort)
	}
	if entry.Bytes != 1234 {
		t.Errorf("bytes = %d, want 1234", entry.Bytes)
	}
}

func TestICMPChecksum(t *testing.T) {
	msg := buildICMPEcho(1, 1)
	if len(msg) != 8 {
		t.Fatalf("ICMP message length = %d, want 8", len(msg))
	}
	if msg[0] != 8 { // Echo Request
		t.Errorf("type = %d, want 8", msg[0])
	}

	// Verify checksum: sum of all 16-bit words should be 0xFFFF.
	var sum uint32
	for i := 0; i < len(msg)-1; i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	if uint16(sum) != 0xffff {
		t.Errorf("checksum verification failed: sum = %04x, want 0xffff", sum)
	}
}

func TestIfname(t *testing.T) {
	b := ifname("eth0")
	if len(b) != 16 {
		t.Fatalf("ifname length = %d, want 16", len(b))
	}
	if string(b[:5]) != "eth0\x00" {
		t.Errorf("ifname prefix = %q, want eth0\\0", b[:5])
	}
}

func TestBinaryPort(t *testing.T) {
	tests := []struct {
		port uint16
		want []byte
	}{
		{80, []byte{0, 80}},
		{443, []byte{1, 187}},
		{8080, []byte{31, 144}},
	}
	for _, tt := range tests {
		got := binaryPort(tt.port)
		if got[0] != tt.want[0] || got[1] != tt.want[1] {
			t.Errorf("binaryPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestOpenRCManagerFindProcessSelf(t *testing.T) {
	mgr := NewOpenRCManager()

	// Our own process should be findable.
	pid := os.Getpid()
	if !mgr.IsRunning(pid) {
		t.Error("expected own process to be running")
	}
}

func TestOpenRCManagerFindProcessNotFound(t *testing.T) {
	mgr := NewOpenRCManager()

	_, err := mgr.FindProcess("nonexistent_process_xyz_12345")
	if err == nil {
		t.Error("expected error for nonexistent process")
	}
}

func TestHTTPClientGet(t *testing.T) {
	// This test requires network. Skip in CI if needed.
	client := NewHTTPClient()
	body, code, err := client.Get("https://httpbin.org/status/200", nil, 5)
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	if code != 200 {
		t.Errorf("status = %d, want 200", code)
	}
	_ = body
}

func TestBackendCaps(t *testing.T) {
	b := NewNftablesBackend("/tmp/test-rulesets")
	caps := b.Capabilities()

	if caps.Name != "nftables (netlink)" {
		t.Errorf("name = %q, want nftables (netlink)", caps.Name)
	}
	if !caps.Sets {
		t.Error("expected Sets = true")
	}
	if !caps.AtomicReplace {
		t.Error("expected AtomicReplace = true")
	}
	if !caps.NAT {
		t.Error("expected NAT = true")
	}
}

func TestNetworkManagerConnections(t *testing.T) {
	nm := NewLinuxNetworkManager()
	conns, err := nm.Connections()
	if err != nil {
		t.Skipf("cannot read /proc/net: %v", err)
	}
	// We should have at least one listening connection (our test process).
	// Just verify no crash.
	_ = conns
}

func TestProcessUptime(t *testing.T) {
	mgr := NewOpenRCManager()
	status, err := mgr.Status("init")
	if err != nil {
		// Init might have PID 1 but no PID file.
		t.Skipf("cannot check init status: %v", err)
	}
	// PID 1 should be running.
	if !status.Running {
		// In containers, PID 1 might not be "init".
		if mgr.IsRunning(1) {
			t.Log("PID 1 is running but status check failed (no PID file)")
		}
	}
}

func TestWriteRulesetFile(t *testing.T) {
	dir := t.TempDir()
	b := NewNftablesBackend(dir)

	artifact := &Artifact{
		Text:     "# test ruleset\ntable inet gatekeeper {}\n",
		Checksum: "abc123",
	}

	if err := b.writeRulesetFile(artifact); err != nil {
		t.Fatalf("writeRulesetFile: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "gatekeeper.nft"))
	if err != nil {
		t.Fatalf("read ruleset: %v", err)
	}
	if !strings.Contains(string(data), "test ruleset") {
		t.Error("ruleset file doesn't contain expected content")
	}
}
