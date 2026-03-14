package inspect

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// HTTP2Settings contains parsed HTTP/2 SETTINGS frame parameters.
// These settings are sent by the client in the connection preface and
// are highly discriminating for browser/bot identification.
type HTTP2Settings struct {
	// Settings in the order they appear in the SETTINGS frame.
	Settings []HTTP2Setting
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Timestamp time.Time
}

// HTTP2Setting is a single HTTP/2 SETTINGS parameter.
type HTTP2Setting struct {
	ID    uint16 // Setting identifier (1-6 standard, others reserved)
	Value uint32 // Setting value
}

// HTTP2Fingerprint is an HTTP/2 SETTINGS frame fingerprint.
// Format: {setting_id}:{value};{setting_id}:{value}... (in original order)
// The ordering and values of SETTINGS parameters varies by browser,
// HTTP library, and application.
type HTTP2Fingerprint struct {
	Hash            string    `json:"hash"`             // Truncated SHA256 of settings string
	SettingsOrder   string    `json:"settings_order"`   // IDs in order (e.g. "1,3,4,6")
	SettingsValues  string    `json:"settings_values"`  // Full settings string
	HeaderTableSize uint32    `json:"header_table_size"`// SETTINGS_HEADER_TABLE_SIZE (1)
	MaxConcurrent   uint32    `json:"max_concurrent"`   // SETTINGS_MAX_CONCURRENT_STREAMS (3)
	InitWindowSize  uint32    `json:"init_window_size"` // SETTINGS_INITIAL_WINDOW_SIZE (4)
	MaxFrameSize    uint32    `json:"max_frame_size"`   // SETTINGS_MAX_FRAME_SIZE (5)
	MaxHeaderList   uint32    `json:"max_header_list"`  // SETTINGS_MAX_HEADER_LIST_SIZE (6)
	EnablePush      bool      `json:"enable_push"`      // SETTINGS_ENABLE_PUSH (2)
	SrcIP           string    `json:"src_ip"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Count           int64     `json:"count"`
}

// FingerprintHTTP2 creates a fingerprint from HTTP/2 SETTINGS parameters.
func (e *Engine) FingerprintHTTP2(settings *HTTP2Settings) (*HTTP2Fingerprint, error) {
	if settings == nil {
		return nil, fmt.Errorf("nil HTTP2Settings")
	}
	if len(settings.Settings) == 0 {
		return nil, fmt.Errorf("empty settings")
	}

	// Build canonical string: "id:value;id:value;..." in original order.
	parts := make([]string, len(settings.Settings))
	orderParts := make([]string, len(settings.Settings))
	for i, s := range settings.Settings {
		parts[i] = fmt.Sprintf("%d:%d", s.ID, s.Value)
		orderParts[i] = fmt.Sprintf("%d", s.ID)
	}
	settingsStr := strings.Join(parts, ";")
	orderStr := strings.Join(orderParts, ",")
	hash := truncHash(settingsStr)

	fp := &HTTP2Fingerprint{
		Hash:           hash,
		SettingsOrder:  orderStr,
		SettingsValues: settingsStr,
		SrcIP:          settings.SrcIP,
	}

	// Extract named settings.
	for _, s := range settings.Settings {
		switch s.ID {
		case 1:
			fp.HeaderTableSize = s.Value
		case 2:
			fp.EnablePush = s.Value != 0
		case 3:
			fp.MaxConcurrent = s.Value
		case 4:
			fp.InitWindowSize = s.Value
		case 5:
			fp.MaxFrameSize = s.Value
		case 6:
			fp.MaxHeaderList = s.Value
		}
	}

	now := time.Now()
	fp.FirstSeen = now
	fp.LastSeen = now
	fp.Count = 1

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "http2",
			Hash:      hash,
			SrcIP:     settings.SrcIP,
			DstIP:     settings.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseHTTP2Settings parses HTTP/2 SETTINGS frame from raw bytes.
// The data should start at the HTTP/2 frame header (9 bytes).
//
// HTTP/2 frame format:
//
//	length(3) + type(1) + flags(1) + stream_id(4) = 9 byte header
//	SETTINGS type = 0x04, stream ID must be 0
//	Payload: 6-byte entries (id:2 + value:4)
func ParseHTTP2Settings(data []byte) (*HTTP2Settings, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("data too short for HTTP/2 frame: %d bytes", len(data))
	}

	// Frame header.
	frameLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	frameType := data[3]
	// flags := data[4]  // ACK flag (0x1) not relevant for fingerprinting.
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7fffffff

	if frameType != 0x04 { // SETTINGS
		return nil, fmt.Errorf("not a SETTINGS frame: type 0x%02x", frameType)
	}
	if streamID != 0 {
		return nil, fmt.Errorf("SETTINGS frame must be on stream 0, got %d", streamID)
	}
	if frameLen%6 != 0 {
		return nil, fmt.Errorf("SETTINGS payload not multiple of 6: %d bytes", frameLen)
	}

	payload := data[9:]
	if len(payload) < frameLen {
		return nil, fmt.Errorf("SETTINGS payload truncated: have %d, need %d", len(payload), frameLen)
	}
	payload = payload[:frameLen]

	settings := &HTTP2Settings{}
	for i := 0; i+5 < len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		value := binary.BigEndian.Uint32(payload[i+2 : i+6])
		settings.Settings = append(settings.Settings, HTTP2Setting{ID: id, Value: value})
	}

	return settings, nil
}

// DetectHTTP2Preface checks if data starts with the HTTP/2 connection preface.
// The preface is: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
// followed by a SETTINGS frame.
func DetectHTTP2Preface(data []byte) bool {
	return len(data) >= 24 && string(data[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
}
