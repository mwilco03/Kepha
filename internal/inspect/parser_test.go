package inspect

import (
	"testing"
)

func TestParseClientHello(t *testing.T) {
	// Minimal TLS 1.2 ClientHello with 2 cipher suites, SNI, and ALPN.
	data := buildClientHello(t)

	hello, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	if hello.Version != 0x0303 {
		t.Errorf("version = 0x%04x, want 0x0303", hello.Version)
	}
	if len(hello.CipherSuites) != 2 {
		t.Errorf("cipher suites = %d, want 2", len(hello.CipherSuites))
	}
	if hello.CipherSuites[0] != 0x1301 || hello.CipherSuites[1] != 0xc02f {
		t.Errorf("cipher suites = %v", hello.CipherSuites)
	}
	if hello.SNI != "test.example.com" {
		t.Errorf("sni = %q, want %q", hello.SNI, "test.example.com")
	}
}

func TestParseClientHello_NotHandshake(t *testing.T) {
	data := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00} // Application data
	_, err := ParseClientHello(data)
	if err == nil {
		t.Error("expected error for non-handshake record")
	}
}

func TestParseClientHello_TooShort(t *testing.T) {
	_, err := ParseClientHello([]byte{0x16, 0x03})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseTCPSyn(t *testing.T) {
	// Build a minimal IPv4 + TCP SYN packet.
	pkt := buildTCPSynPacket(t)

	syn, err := ParseTCPSyn(pkt)
	if err != nil {
		t.Fatalf("ParseTCPSyn: %v", err)
	}

	if syn.TTL != 64 {
		t.Errorf("ttl = %d, want 64", syn.TTL)
	}
	if syn.SrcIP != "192.168.1.100" {
		t.Errorf("src_ip = %q, want %q", syn.SrcIP, "192.168.1.100")
	}
	if syn.WindowSize != 65535 {
		t.Errorf("window_size = %d, want 65535", syn.WindowSize)
	}
	if syn.MSS != 1460 {
		t.Errorf("mss = %d, want 1460", syn.MSS)
	}
}

func TestParseTCPSyn_NotSyn(t *testing.T) {
	pkt := buildTCPSynPacket(t)
	// Clear SYN flag.
	pkt[20+13] = 0x10 // ACK only
	_, err := ParseTCPSyn(pkt)
	if err == nil {
		t.Error("expected error for non-SYN packet")
	}
}

// buildClientHello constructs a minimal TLS ClientHello for testing.
func buildClientHello(t *testing.T) []byte {
	t.Helper()

	sni := "test.example.com"

	// Build ClientHello body.
	var body []byte
	// Version: TLS 1.2
	body = append(body, 0x03, 0x03)
	// Random: 32 bytes of zeros.
	body = append(body, make([]byte, 32)...)
	// Session ID: length 0
	body = append(body, 0x00)
	// Cipher suites: 2 suites (4 bytes)
	body = append(body, 0x00, 0x04)
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0xc0, 0x2f) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	// Compression methods: 1 method (null)
	body = append(body, 0x01, 0x00)

	// Extensions.
	var exts []byte

	// SNI extension.
	sniExt := buildSNIExtension(sni)
	exts = append(exts, 0x00, 0x00) // Extension type: SNI
	exts = append(exts, byte(len(sniExt)>>8), byte(len(sniExt)))
	exts = append(exts, sniExt...)

	// ALPN extension.
	alpnData := buildALPNExtension("h2", "http/1.1")
	exts = append(exts, 0x00, 0x10) // Extension type: ALPN
	exts = append(exts, byte(len(alpnData)>>8), byte(len(alpnData)))
	exts = append(exts, alpnData...)

	// Extensions length prefix.
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	// Handshake header.
	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record header.
	var record []byte
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	record = append(record, byte(len(hs)>>8), byte(len(hs)))
	record = append(record, hs...)

	return record
}

func buildSNIExtension(name string) []byte {
	nameBytes := []byte(name)
	// Server name list length (2) + type (1) + name length (2) + name
	listLen := 1 + 2 + len(nameBytes)
	var ext []byte
	ext = append(ext, byte(listLen>>8), byte(listLen)) // List length
	ext = append(ext, 0x00)                             // Type: host_name
	ext = append(ext, byte(len(nameBytes)>>8), byte(len(nameBytes)))
	ext = append(ext, nameBytes...)
	return ext
}

func buildALPNExtension(protos ...string) []byte {
	var protoList []byte
	for _, p := range protos {
		protoList = append(protoList, byte(len(p)))
		protoList = append(protoList, []byte(p)...)
	}
	var ext []byte
	ext = append(ext, byte(len(protoList)>>8), byte(len(protoList)))
	ext = append(ext, protoList...)
	return ext
}

// buildTCPSynPacket constructs a minimal IPv4+TCP SYN packet.
func buildTCPSynPacket(t *testing.T) []byte {
	t.Helper()

	pkt := make([]byte, 44) // 20 IP + 24 TCP (20 header + 4 MSS option)

	// IP header.
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[8] = 64   // TTL
	pkt[9] = 6    // Protocol: TCP
	// Source: 192.168.1.100
	pkt[12], pkt[13], pkt[14], pkt[15] = 192, 168, 1, 100
	// Dest: 93.184.216.34
	pkt[16], pkt[17], pkt[18], pkt[19] = 93, 184, 216, 34

	// TCP header (offset 20).
	tcp := pkt[20:]
	// Source port: 12345
	tcp[0], tcp[1] = 0x30, 0x39
	// Dest port: 443
	tcp[2], tcp[3] = 0x01, 0xBB
	// Data offset: 6 (24 bytes = 20 + 4 option bytes) in upper 4 bits of byte 12
	tcp[12] = 0x60
	// Flags: SYN
	tcp[13] = 0x02
	// Window size: 65535
	tcp[14], tcp[15] = 0xFF, 0xFF

	// TCP option: MSS = 1460
	tcp[20] = 2    // Kind: MSS
	tcp[21] = 4    // Length
	tcp[22] = 0x05 // MSS high byte (1460 = 0x05B4)
	tcp[23] = 0xB4 // MSS low byte

	return pkt
}
