package inspect

import (
	"encoding/binary"
	"testing"
)

func TestFingerprintHTTP2_Chrome(t *testing.T) {
	e := NewEngine(nil)

	// Chrome-like SETTINGS.
	settings := &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: 1, Value: 65536},  // HEADER_TABLE_SIZE
			{ID: 3, Value: 1000},   // MAX_CONCURRENT_STREAMS
			{ID: 4, Value: 6291456},// INITIAL_WINDOW_SIZE
			{ID: 6, Value: 262144}, // MAX_HEADER_LIST_SIZE
		},
		SrcIP: "192.168.1.100",
	}

	fp, err := e.FingerprintHTTP2(settings)
	if err != nil {
		t.Fatalf("FingerprintHTTP2: %v", err)
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.HeaderTableSize != 65536 {
		t.Errorf("header_table_size = %d, want 65536", fp.HeaderTableSize)
	}
	if fp.MaxConcurrent != 1000 {
		t.Errorf("max_concurrent = %d, want 1000", fp.MaxConcurrent)
	}
	if fp.SettingsOrder != "1,3,4,6" {
		t.Errorf("settings_order = %q, want 1,3,4,6", fp.SettingsOrder)
	}
}

func TestFingerprintHTTP2_DifferentSettings(t *testing.T) {
	e := NewEngine(nil)

	chrome := &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: 1, Value: 65536},
			{ID: 3, Value: 1000},
			{ID: 4, Value: 6291456},
		},
	}
	firefox := &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: 1, Value: 65536},
			{ID: 4, Value: 131072},
			{ID: 5, Value: 16384},
		},
	}

	fp1, _ := e.FingerprintHTTP2(chrome)
	fp2, _ := e.FingerprintHTTP2(firefox)

	if fp1.Hash == fp2.Hash {
		t.Error("different settings should produce different hashes")
	}
}

func TestFingerprintHTTP2_Nil(t *testing.T) {
	e := NewEngine(nil)
	_, err := e.FingerprintHTTP2(nil)
	if err == nil {
		t.Error("expected error for nil")
	}
	_, err = e.FingerprintHTTP2(&HTTP2Settings{})
	if err == nil {
		t.Error("expected error for empty settings")
	}
}

func TestParseHTTP2Settings(t *testing.T) {
	// Build a SETTINGS frame with 3 settings.
	settings := []HTTP2Setting{
		{ID: 1, Value: 4096},
		{ID: 3, Value: 100},
		{ID: 4, Value: 65535},
	}
	frame := buildHTTP2SettingsFrame(settings)

	parsed, err := ParseHTTP2Settings(frame)
	if err != nil {
		t.Fatalf("ParseHTTP2Settings: %v", err)
	}

	if len(parsed.Settings) != 3 {
		t.Fatalf("settings = %d, want 3", len(parsed.Settings))
	}
	if parsed.Settings[0].ID != 1 || parsed.Settings[0].Value != 4096 {
		t.Errorf("setting[0] = %d:%d, want 1:4096", parsed.Settings[0].ID, parsed.Settings[0].Value)
	}
}

func TestParseHTTP2Settings_NotSettings(t *testing.T) {
	frame := []byte{0, 0, 0, 0x01, 0, 0, 0, 0, 0} // Type = HEADERS (0x01)
	_, err := ParseHTTP2Settings(frame)
	if err == nil {
		t.Error("expected error for non-SETTINGS frame")
	}
}

func TestDetectHTTP2Preface(t *testing.T) {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if !DetectHTTP2Preface(preface) {
		t.Error("should detect HTTP/2 preface")
	}
	if DetectHTTP2Preface([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("should not detect HTTP/1.1 as HTTP/2")
	}
}

func buildHTTP2SettingsFrame(settings []HTTP2Setting) []byte {
	payloadLen := len(settings) * 6
	frame := make([]byte, 9+payloadLen)
	// Length (3 bytes).
	frame[0] = byte(payloadLen >> 16)
	frame[1] = byte(payloadLen >> 8)
	frame[2] = byte(payloadLen)
	// Type = SETTINGS (0x04).
	frame[3] = 0x04
	// Flags = 0.
	frame[4] = 0
	// Stream ID = 0 (4 bytes).
	binary.BigEndian.PutUint32(frame[5:9], 0)

	for i, s := range settings {
		off := 9 + i*6
		binary.BigEndian.PutUint16(frame[off:off+2], s.ID)
		binary.BigEndian.PutUint32(frame[off+2:off+6], s.Value)
	}

	return frame
}
