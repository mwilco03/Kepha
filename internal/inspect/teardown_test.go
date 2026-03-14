package inspect

import (
	"testing"
)

func TestFingerprintTCPTeardown_RST(t *testing.T) {
	e := NewEngine(nil)

	td := &TCPTeardown{
		UsedRST: true,
		TTL:     128,
		Window:  0,
		SrcIP:   "10.0.0.1",
		DstIP:   "192.168.1.100",
	}

	fp, err := e.FingerprintTCPTeardown(td)
	if err != nil {
		t.Fatalf("FingerprintTCPTeardown: %v", err)
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.Method != "rst" {
		t.Errorf("method = %q, want rst", fp.Method)
	}
	if fp.OSHint != "Windows" {
		t.Errorf("os_hint = %q, want Windows", fp.OSHint)
	}
}

func TestFingerprintTCPTeardown_FIN(t *testing.T) {
	e := NewEngine(nil)

	td := &TCPTeardown{
		UsedFIN: true,
		TTL:     64,
		Window:  32768,
		SrcIP:   "10.0.0.2",
	}

	fp, err := e.FingerprintTCPTeardown(td)
	if err != nil {
		t.Fatalf("FingerprintTCPTeardown: %v", err)
	}
	if fp.Method != "fin" {
		t.Errorf("method = %q, want fin", fp.Method)
	}
	if fp.OSHint != "Linux/macOS" {
		t.Errorf("os_hint = %q, want Linux/macOS", fp.OSHint)
	}
}

func TestFingerprintTCPTeardown_RSTNonZeroWindow(t *testing.T) {
	e := NewEngine(nil)

	td := &TCPTeardown{
		UsedRST: true,
		Window:  12345,
		TTL:     64,
		SrcIP:   "10.0.0.3",
	}

	fp, err := e.FingerprintTCPTeardown(td)
	if err != nil {
		t.Fatalf("FingerprintTCPTeardown: %v", err)
	}

	found := false
	for _, a := range fp.Alerts {
		if a == "RST with non-zero window (possible scan/probe)" {
			found = true
		}
	}
	if !found {
		t.Error("expected alert for RST with non-zero window")
	}
}

func TestFingerprintTCPTeardown_Nil(t *testing.T) {
	e := NewEngine(nil)
	_, err := e.FingerprintTCPTeardown(nil)
	if err == nil {
		t.Error("expected error for nil")
	}
}

func TestParseTCPFlags_FIN(t *testing.T) {
	pkt := buildTCPFlagPacket(64, 0x01, 0) // FIN
	td, err := ParseTCPFlags(pkt)
	if err != nil {
		t.Fatalf("ParseTCPFlags: %v", err)
	}
	if !td.UsedFIN {
		t.Error("should detect FIN")
	}
	if td.UsedRST {
		t.Error("should not detect RST")
	}
}

func TestParseTCPFlags_RST(t *testing.T) {
	pkt := buildTCPFlagPacket(128, 0x04, 0) // RST
	td, err := ParseTCPFlags(pkt)
	if err != nil {
		t.Fatalf("ParseTCPFlags: %v", err)
	}
	if !td.UsedRST {
		t.Error("should detect RST")
	}
}

func TestParseTCPFlags_NotTeardown(t *testing.T) {
	pkt := buildTCPFlagPacket(64, 0x10, 0) // ACK only
	_, err := ParseTCPFlags(pkt)
	if err == nil {
		t.Error("expected error for non-FIN/RST packet")
	}
}

// buildTCPFlagPacket creates a minimal IP+TCP packet with specific flags.
func buildTCPFlagPacket(ttl uint8, flags uint8, window uint16) []byte {
	pkt := make([]byte, 40) // IP(20) + TCP(20)
	// IP header.
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[8] = ttl
	pkt[9] = 6 // TCP
	pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1 // src IP
	pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 100 // dst IP
	// TCP header.
	pkt[20] = 0; pkt[21] = 80 // src port 80
	pkt[22] = 0xC0; pkt[23] = 0x00 // dst port 49152
	pkt[32] = 0x50 // data offset = 5 (20 bytes)
	pkt[33] = flags
	pkt[34] = byte(window >> 8)
	pkt[35] = byte(window)
	return pkt
}
