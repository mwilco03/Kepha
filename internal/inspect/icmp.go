package inspect

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ICMPMessage contains parsed ICMP message fields for fingerprinting.
type ICMPMessage struct {
	Type     uint8  // ICMP type (0=echo reply, 8=echo request, etc.)
	Code     uint8  // ICMP code
	ID       uint16 // Identifier (echo request/reply)
	Seq      uint16 // Sequence number
	TTL      uint8  // IP TTL from the packet carrying this ICMP message
	DataSize int    // Size of ICMP data payload (after header)
	Data     []byte // First 64 bytes of ICMP data (for pattern matching)
	SrcIP    string
	DstIP    string
	Timestamp time.Time
}

// ICMPFingerprint captures ICMP behavioral characteristics of a host.
type ICMPFingerprint struct {
	Hash     string    `json:"hash"`      // Truncated SHA256 of ICMP behavior
	Type     uint8     `json:"type"`      // ICMP message type
	Code     uint8     `json:"code"`      // ICMP code
	TTL      uint8     `json:"ttl"`       // TTL in ICMP packet
	DataSize int       `json:"data_size"` // Payload size (varies by OS)
	OSHint   string    `json:"os_hint"`   // OS inference from ICMP behavior
	Alerts   []string  `json:"alerts"`    // Suspicious ICMP patterns
	SrcIP    string    `json:"src_ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count    int64     `json:"count"`
}

// FingerprintICMP creates a fingerprint from an ICMP message.
// ICMP echo reply TTL, payload size, and data patterns vary by OS:
//   - Linux: TTL=64, 56 bytes data (filled with timestamp + incrementing bytes)
//   - Windows: TTL=128, 32 bytes data (filled with 'abcdefgh...')
//   - macOS: TTL=64, 56 bytes data (timestamp pattern)
func (e *Engine) FingerprintICMP(msg *ICMPMessage) (*ICMPFingerprint, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil ICMPMessage")
	}

	raw := fmt.Sprintf("%d:%d:%d:%d", msg.Type, msg.Code, msg.TTL, msg.DataSize)
	hash := truncHash(raw)

	osHint := guessICMPOS(msg)

	var alerts []string
	// Large ICMP payloads are suspicious (possible ping flood or exfil).
	if msg.DataSize > 1024 {
		alerts = append(alerts, fmt.Sprintf("large ICMP payload: %d bytes", msg.DataSize))
	}
	// ICMP types that shouldn't appear on a normal network.
	if msg.Type == 5 { // Redirect
		alerts = append(alerts, "ICMP redirect (potential MitM)")
	}
	if msg.Type == 17 || msg.Type == 18 { // Address mask
		alerts = append(alerts, "ICMP address mask (network recon)")
	}
	if msg.Type == 13 || msg.Type == 14 { // Timestamp
		alerts = append(alerts, "ICMP timestamp (network recon)")
	}

	now := time.Now()
	fp := &ICMPFingerprint{
		Hash:      hash,
		Type:      msg.Type,
		Code:      msg.Code,
		TTL:       msg.TTL,
		DataSize:  msg.DataSize,
		OSHint:    osHint,
		Alerts:    alerts,
		SrcIP:     msg.SrcIP,
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "icmp",
			Hash:      hash,
			SrcIP:     msg.SrcIP,
			DstIP:     msg.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseICMP parses an ICMP message from raw bytes.
// Input starts at IP header.
func ParseICMP(data []byte) (*ICMPMessage, error) {
	if len(data) < 28 { // IP(20) + ICMP(8) minimum
		return nil, fmt.Errorf("packet too short for ICMP: %d bytes", len(data))
	}

	// IP header.
	ipVersion := data[0] >> 4
	if ipVersion != 4 {
		return nil, fmt.Errorf("not IPv4: version %d", ipVersion)
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, fmt.Errorf("invalid IP header length: %d", ihl)
	}

	protocol := data[9]
	if protocol != 1 { // ICMP
		return nil, fmt.Errorf("not ICMP: protocol %d", protocol)
	}

	ttl := data[8]
	srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])

	icmp := data[ihl:]
	if len(icmp) < 8 {
		return nil, fmt.Errorf("ICMP header too short")
	}

	msg := &ICMPMessage{
		Type:      icmp[0],
		Code:      icmp[1],
		TTL:       ttl,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Timestamp: time.Now(),
	}

	// Echo request/reply have ID and Seq fields.
	if msg.Type == 0 || msg.Type == 8 {
		msg.ID = binary.BigEndian.Uint16(icmp[4:6])
		msg.Seq = binary.BigEndian.Uint16(icmp[6:8])
	}

	// Data payload starts after the 8-byte ICMP header.
	icmpData := icmp[8:]
	msg.DataSize = len(icmpData)
	if len(icmpData) > 64 {
		msg.Data = make([]byte, 64)
		copy(msg.Data, icmpData[:64])
	} else if len(icmpData) > 0 {
		msg.Data = make([]byte, len(icmpData))
		copy(msg.Data, icmpData)
	}

	return msg, nil
}

// guessICMPOS infers OS from ICMP echo behavior.
func guessICMPOS(msg *ICMPMessage) string {
	// Only meaningful for echo request (8) or echo reply (0).
	if msg.Type != 0 && msg.Type != 8 {
		return "Unknown"
	}

	switch {
	case msg.TTL <= 64 && msg.TTL > 32 && msg.DataSize == 56:
		return "Linux/macOS"
	case msg.TTL <= 128 && msg.TTL > 64 && msg.DataSize == 32:
		return "Windows"
	case msg.TTL <= 64 && msg.TTL > 32 && msg.DataSize == 32:
		return "macOS"
	case msg.TTL <= 128 && msg.TTL > 64:
		return "Windows"
	case msg.TTL <= 64 && msg.TTL > 32:
		return "Linux/macOS"
	case msg.TTL > 128:
		return "Solaris/AIX"
	default:
		return "Unknown"
	}
}
