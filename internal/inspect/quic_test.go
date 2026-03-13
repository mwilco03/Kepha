package inspect

import (
	"testing"
)

func TestFingerprintQUIC_Basic(t *testing.T) {
	e := NewEngine(nil)

	qi := &QUICInitial{
		Version:    quicV1,
		DCIDLength: 8,
		SCIDLength: 0,
		DCID:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		ClientHello: &ClientHello{
			Version:       0x0304,
			CipherSuites:  []uint16{0x1301, 0x1302, 0x1303},
			Extensions:    []uint16{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b},
			ALPNProtocols: []string{"h3"},
			SNI:           "example.com",
			SrcIP:         "192.168.1.100",
			DstIP:         "10.0.0.1",
		},
		SrcIP: "192.168.1.100",
		DstIP: "10.0.0.1",
	}

	fp, err := e.FingerprintQUIC(qi)
	if err != nil {
		t.Fatalf("FingerprintQUIC: %v", err)
	}

	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	// Should start with "q" for QUIC.
	if fp.Hash[0] != 'q' {
		t.Errorf("hash should start with 'q', got %q", fp.Hash)
	}
	if fp.QUICVersion != "v1" {
		t.Errorf("quic_version = %q, want v1", fp.QUICVersion)
	}
	if fp.DCIDLen != 8 {
		t.Errorf("dcid_len = %d, want 8", fp.DCIDLen)
	}
	if fp.SrcIP != "192.168.1.100" {
		t.Errorf("src_ip = %q", fp.SrcIP)
	}
}

func TestFingerprintQUIC_Nil(t *testing.T) {
	e := NewEngine(nil)

	_, err := e.FingerprintQUIC(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}

	_, err = e.FingerprintQUIC(&QUICInitial{})
	if err == nil {
		t.Error("expected error for nil ClientHello")
	}
}

func TestFingerprintQUIC_QPrefix(t *testing.T) {
	e := NewEngine(nil)

	qi := &QUICInitial{
		Version: quicV1,
		ClientHello: &ClientHello{
			Version:       0x0304,
			CipherSuites:  []uint16{0x1301},
			Extensions:    []uint16{0x0000},
			ALPNProtocols: []string{"h3"},
			SNI:           "test.com",
		},
	}

	fp, err := e.FingerprintQUIC(qi)
	if err != nil {
		t.Fatalf("FingerprintQUIC: %v", err)
	}

	// The hash should start with "q13d" (QUIC, TLS 1.3, domain SNI).
	if len(fp.Hash) < 4 {
		t.Fatalf("hash too short: %q", fp.Hash)
	}
	if fp.Hash[:4] != "q13d" {
		t.Errorf("hash prefix = %q, want q13d", fp.Hash[:4])
	}
}

func TestFingerprintQUIC_DifferentClientsProduceDifferentHashes(t *testing.T) {
	e := NewEngine(nil)

	qi1 := &QUICInitial{
		Version: quicV1,
		ClientHello: &ClientHello{
			Version:      0x0304,
			CipherSuites: []uint16{0x1301, 0x1302},
			Extensions:   []uint16{0x0000, 0x000a},
		},
	}
	qi2 := &QUICInitial{
		Version: quicV1,
		ClientHello: &ClientHello{
			Version:      0x0304,
			CipherSuites: []uint16{0x1303},
			Extensions:   []uint16{0x000d, 0x002b, 0x0010},
		},
	}

	fp1, _ := e.FingerprintQUIC(qi1)
	fp2, _ := e.FingerprintQUIC(qi2)

	if fp1.Hash == fp2.Hash {
		t.Error("different cipher/ext sets should produce different hashes")
	}
}

func TestFingerprintQUIC_V2Version(t *testing.T) {
	e := NewEngine(nil)

	qi := &QUICInitial{
		Version: quicV2,
		ClientHello: &ClientHello{
			Version:      0x0304,
			CipherSuites: []uint16{0x1301},
			Extensions:   []uint16{0x0000},
		},
	}

	fp, err := e.FingerprintQUIC(qi)
	if err != nil {
		t.Fatalf("FingerprintQUIC: %v", err)
	}

	if fp.QUICVersion != "v2" {
		t.Errorf("quic_version = %q, want v2", fp.QUICVersion)
	}
}

func TestReadVarInt(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		want   uint64
		wantN  int
		wantOK bool
	}{
		{"1 byte: 0", []byte{0x00}, 0, 1, true},
		{"1 byte: 37", []byte{0x25}, 37, 1, true},
		{"2 bytes: 15293", []byte{0x7b, 0xbd}, 15293, 2, true},
		{"4 bytes", []byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4, true},
		{"empty", []byte{}, 0, 0, false},
	}

	for _, tt := range tests {
		val, n, err := readVarInt(tt.data)
		if tt.wantOK {
			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.name, err)
				continue
			}
			if val != tt.want {
				t.Errorf("%s: val = %d, want %d", tt.name, val, tt.want)
			}
			if n != tt.wantN {
				t.Errorf("%s: n = %d, want %d", tt.name, n, tt.wantN)
			}
		} else if err == nil {
			t.Errorf("%s: expected error", tt.name)
		}
	}
}

func TestQuicVersionString(t *testing.T) {
	if s := quicVersionString(quicV1); s != "v1" {
		t.Errorf("v1 = %q", s)
	}
	if s := quicVersionString(quicV2); s != "v2" {
		t.Errorf("v2 = %q", s)
	}
	if s := quicVersionString(0x12345678); s != "0x12345678" {
		t.Errorf("unknown = %q", s)
	}
}

func TestBuildTLSRecord(t *testing.T) {
	handshake := []byte{0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00}
	record := buildTLSRecord(handshake)

	if record[0] != 0x16 {
		t.Errorf("content type = 0x%02x, want 0x16", record[0])
	}
	if record[1] != 0x03 || record[2] != 0x01 {
		t.Errorf("version = 0x%02x%02x, want 0x0301", record[1], record[2])
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if recordLen != len(handshake) {
		t.Errorf("record length = %d, want %d", recordLen, len(handshake))
	}
}

func TestExtractCryptoFrame(t *testing.T) {
	// Build a simple payload with PADDING then CRYPTO frame.
	var payload []byte
	// PADDING frames (type 0x00).
	payload = append(payload, 0x00, 0x00, 0x00)
	// CRYPTO frame: type(1) + offset(1) + length(1) + data.
	cryptoData := []byte("hello TLS handshake")
	payload = append(payload, 0x06)              // CRYPTO frame type
	payload = append(payload, 0x00)              // offset = 0
	payload = append(payload, byte(len(cryptoData))) // length
	payload = append(payload, cryptoData...)

	result, err := extractCryptoFrame(payload)
	if err != nil {
		t.Fatalf("extractCryptoFrame: %v", err)
	}
	if string(result) != "hello TLS handshake" {
		t.Errorf("result = %q", result)
	}
}

func TestExtractCryptoFrame_NoCryptoFrame(t *testing.T) {
	// Only PADDING, no CRYPTO.
	payload := []byte{0x00, 0x00, 0x00}
	// PING frame to terminate.
	payload = append(payload, 0x01)
	// Then something unknown.
	payload = append(payload, 0x04) // RESET_STREAM — unexpected.

	_, err := extractCryptoFrame(payload)
	if err == nil {
		t.Error("expected error when no CRYPTO frame found")
	}
}
