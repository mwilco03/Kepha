package inspect

import (
	"testing"
)

func TestFingerprintICMP_EchoReply(t *testing.T) {
	e := NewEngine(nil)

	msg := &ICMPMessage{
		Type:     0, // Echo Reply
		Code:     0,
		TTL:      64,
		DataSize: 56,
		SrcIP:    "10.0.0.1",
	}

	fp, err := e.FingerprintICMP(msg)
	if err != nil {
		t.Fatalf("FingerprintICMP: %v", err)
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.OSHint != "Linux/macOS" {
		t.Errorf("os_hint = %q, want Linux/macOS", fp.OSHint)
	}
}

func TestFingerprintICMP_Windows(t *testing.T) {
	e := NewEngine(nil)

	msg := &ICMPMessage{
		Type:     8, // Echo Request
		TTL:      128,
		DataSize: 32,
		SrcIP:    "10.0.0.2",
	}

	fp, err := e.FingerprintICMP(msg)
	if err != nil {
		t.Fatalf("FingerprintICMP: %v", err)
	}
	if fp.OSHint != "Windows" {
		t.Errorf("os_hint = %q, want Windows", fp.OSHint)
	}
}

func TestFingerprintICMP_LargePayload(t *testing.T) {
	e := NewEngine(nil)

	msg := &ICMPMessage{
		Type:     8,
		TTL:      64,
		DataSize: 2048,
		SrcIP:    "10.0.0.3",
	}

	fp, err := e.FingerprintICMP(msg)
	if err != nil {
		t.Fatalf("FingerprintICMP: %v", err)
	}

	found := false
	for _, a := range fp.Alerts {
		if len(a) > 10 && a[:10] == "large ICMP" {
			found = true
		}
	}
	if !found {
		t.Error("expected large payload alert")
	}
}

func TestFingerprintICMP_Redirect(t *testing.T) {
	e := NewEngine(nil)

	msg := &ICMPMessage{
		Type:  5, // Redirect
		TTL:   64,
		SrcIP: "10.0.0.4",
	}

	fp, err := e.FingerprintICMP(msg)
	if err != nil {
		t.Fatalf("FingerprintICMP: %v", err)
	}

	found := false
	for _, a := range fp.Alerts {
		if a == "ICMP redirect (potential MitM)" {
			found = true
		}
	}
	if !found {
		t.Error("expected redirect alert")
	}
}

func TestFingerprintICMP_Nil(t *testing.T) {
	e := NewEngine(nil)
	_, err := e.FingerprintICMP(nil)
	if err == nil {
		t.Error("expected error for nil")
	}
}

func TestParseICMP_EchoRequest(t *testing.T) {
	pkt := buildICMPPacket(8, 0, 64, 56) // Echo request, TTL=64, 56 bytes data
	msg, err := ParseICMP(pkt)
	if err != nil {
		t.Fatalf("ParseICMP: %v", err)
	}
	if msg.Type != 8 {
		t.Errorf("type = %d, want 8", msg.Type)
	}
	if msg.TTL != 64 {
		t.Errorf("ttl = %d, want 64", msg.TTL)
	}
	if msg.DataSize != 56 {
		t.Errorf("data_size = %d, want 56", msg.DataSize)
	}
}

func TestParseICMP_NotICMP(t *testing.T) {
	pkt := buildICMPPacket(8, 0, 64, 0)
	pkt[9] = 6 // Change protocol to TCP
	_, err := ParseICMP(pkt)
	if err == nil {
		t.Error("expected error for non-ICMP packet")
	}
}

// buildICMPPacket creates a minimal IP+ICMP packet.
func buildICMPPacket(icmpType, code, ttl uint8, dataSize int) []byte {
	pkt := make([]byte, 20+8+dataSize) // IP(20) + ICMP header(8) + data
	// IP header.
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[8] = ttl
	pkt[9] = 1 // ICMP
	pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1
	pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 100
	// ICMP header.
	pkt[20] = icmpType
	pkt[21] = code
	// ID and Seq for echo.
	pkt[24] = 0x00; pkt[25] = 0x01 // ID = 1
	pkt[26] = 0x00; pkt[27] = 0x01 // Seq = 1
	return pkt
}
