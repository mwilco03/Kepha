package inspect

import (
	"fmt"
	"time"
)

// TCPTeardown contains observed TCP connection teardown behavior.
type TCPTeardown struct {
	// How the connection ended.
	UsedRST     bool   // Connection terminated with RST (vs FIN)
	UsedFIN     bool   // Normal FIN-based shutdown
	DoubleRST   bool   // RST sent in both directions
	FINWait     bool   // FIN sent but RST received before FIN-ACK
	SimultClose bool   // Both sides sent FIN simultaneously

	// TCP flags observed in the teardown packet.
	Flags    uint8  // Raw TCP flags byte
	TTL      uint8  // TTL from the teardown packet
	Window   uint16 // Window size in teardown packet (RST with window=0 is common)

	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Timestamp time.Time
}

// TCPTeardownFingerprint captures how a host tears down connections.
type TCPTeardownFingerprint struct {
	Hash      string    `json:"hash"`       // Truncated SHA256 of teardown behavior
	Method    string    `json:"method"`     // "rst", "fin", "rst+fin", "timeout"
	TTL       uint8     `json:"ttl"`        // TTL in teardown packet
	Window    uint16    `json:"window"`     // Window in RST (0 = normal, non-0 = suspicious)
	OSHint    string    `json:"os_hint"`    // OS inference from teardown behavior
	Alerts    []string  `json:"alerts"`     // Suspicious teardown patterns
	SrcIP     string    `json:"src_ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// FingerprintTCPTeardown creates a fingerprint from TCP connection teardown.
func (e *Engine) FingerprintTCPTeardown(td *TCPTeardown) (*TCPTeardownFingerprint, error) {
	if td == nil {
		return nil, fmt.Errorf("nil TCPTeardown")
	}

	method := "unknown"
	switch {
	case td.UsedRST && td.UsedFIN:
		method = "rst+fin"
	case td.UsedRST:
		method = "rst"
	case td.UsedFIN:
		method = "fin"
	}

	raw := fmt.Sprintf("%s:%d:%d", method, td.TTL, td.Window)
	hash := truncHash(raw)

	// OS inference from teardown behavior.
	osHint := guessTeardownOS(td)

	// Detect suspicious patterns.
	var alerts []string
	if td.UsedRST && td.Window != 0 {
		alerts = append(alerts, "RST with non-zero window (possible scan/probe)")
	}
	if td.DoubleRST {
		alerts = append(alerts, "double RST (both directions)")
	}
	if td.FINWait {
		alerts = append(alerts, "FIN→RST (connection rejected after initial acceptance)")
	}

	now := time.Now()
	fp := &TCPTeardownFingerprint{
		Hash:      hash,
		Method:    method,
		TTL:       td.TTL,
		Window:    td.Window,
		OSHint:    osHint,
		Alerts:    alerts,
		SrcIP:     td.SrcIP,
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "tcp_teardown",
			Hash:      hash,
			SrcIP:     td.SrcIP,
			DstIP:     td.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseTCPFlags extracts a TCPTeardown from raw TCP packet bytes.
// The data should start at the IP header.
func ParseTCPFlags(data []byte) (*TCPTeardown, error) {
	if len(data) < 40 { // IP(20) + TCP(20) minimum
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
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

	ttl := data[8]
	srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])

	tcp := data[ihl:]
	if len(tcp) < 20 {
		return nil, fmt.Errorf("TCP header too short")
	}

	srcPort := uint16(tcp[0])<<8 | uint16(tcp[1])
	dstPort := uint16(tcp[2])<<8 | uint16(tcp[3])
	flags := tcp[13]
	window := uint16(tcp[14])<<8 | uint16(tcp[15])

	fin := flags&0x01 != 0
	rst := flags&0x04 != 0

	if !fin && !rst {
		return nil, fmt.Errorf("not a FIN or RST packet")
	}

	td := &TCPTeardown{
		UsedRST:   rst,
		UsedFIN:   fin,
		Flags:     flags,
		TTL:       ttl,
		Window:    window,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Timestamp: time.Now(),
	}

	return td, nil
}

// guessTeardownOS infers OS from TCP teardown behavior.
func guessTeardownOS(td *TCPTeardown) string {
	// Windows typically sends RST with window=0 on connection close.
	// Linux sends FIN→FIN-ACK.
	// macOS sends FIN with full window.
	switch {
	case td.UsedRST && td.Window == 0 && td.TTL > 64 && td.TTL <= 128:
		return "Windows"
	case td.UsedFIN && !td.UsedRST && td.TTL <= 64:
		return "Linux/macOS"
	case td.UsedRST && td.TTL <= 64:
		return "Linux"
	default:
		return "Unknown"
	}
}
