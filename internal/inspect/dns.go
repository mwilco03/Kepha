package inspect

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// DNSQuery contains parsed DNS query fields for fingerprinting.
type DNSQuery struct {
	TransactionID uint16   // DNS transaction ID
	Flags         uint16   // DNS flags (QR, Opcode, AA, TC, RD, RA, etc.)
	Questions     []DNSQuestion
	QDCount       uint16   // Number of questions
	ANCount       uint16   // Number of answers
	NSCount       uint16   // Number of authority records
	ARCount       uint16   // Number of additional records
	HasEDNS       bool     // EDNS0 OPT record present
	EDNSVersion   uint8    // EDNS version
	EDNSBufSize   uint16   // EDNS UDP buffer size
	EDNSDO        bool     // EDNS DNSSEC OK flag
	EDNSOptions   []uint16 // EDNS option codes
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	Timestamp     time.Time
}

// DNSQuestion is a single DNS question entry.
type DNSQuestion struct {
	Name  string // Query name (e.g. "example.com")
	Type  uint16 // Query type (A=1, AAAA=28, MX=15, TXT=16, etc.)
	Class uint16 // Query class (IN=1)
}

// DNSFingerprint is a DNS resolver/client fingerprint.
// Captures query patterns, EDNS behavior, and DNSSEC support
// to identify resolver software and detect DNS tunneling.
type DNSFingerprint struct {
	Hash        string   `json:"hash"`         // Truncated SHA256 of canonical fields
	RD          bool     `json:"rd"`           // Recursion Desired flag
	HasEDNS     bool     `json:"has_edns"`     // EDNS0 support
	EDNSBufSize uint16   `json:"edns_buf_size"`// EDNS buffer size
	DNSSECOK    bool     `json:"dnssec_ok"`    // DNSSEC OK flag
	EDNSOptions string   `json:"edns_options"` // EDNS option codes
	QueryTypes  string   `json:"query_types"`  // Observed query types
	Alerts      []string `json:"alerts"`       // Suspicious patterns
	SrcIP       string   `json:"src_ip"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int64    `json:"count"`
}

// FingerprintDNS creates a fingerprint from a DNS query.
func (e *Engine) FingerprintDNS(query *DNSQuery) (*DNSFingerprint, error) {
	if query == nil {
		return nil, fmt.Errorf("nil DNSQuery")
	}

	rd := query.Flags&0x0100 != 0

	// Build canonical string for hashing.
	var parts []string
	if rd {
		parts = append(parts, "RD")
	}
	if query.HasEDNS {
		parts = append(parts, fmt.Sprintf("EDNS:%d:%d", query.EDNSVersion, query.EDNSBufSize))
		if query.EDNSDO {
			parts = append(parts, "DO")
		}
	}
	for _, opt := range query.EDNSOptions {
		parts = append(parts, fmt.Sprintf("OPT:%d", opt))
	}

	ednsOpts := ""
	if len(query.EDNSOptions) > 0 {
		optParts := make([]string, len(query.EDNSOptions))
		for i, o := range query.EDNSOptions {
			optParts[i] = fmt.Sprintf("%d", o)
		}
		ednsOpts = strings.Join(optParts, ",")
	}

	// Query type string.
	var queryTypes []string
	for _, q := range query.Questions {
		queryTypes = append(queryTypes, fmt.Sprintf("%d", q.Type))
	}
	qtStr := strings.Join(queryTypes, ",")

	raw := strings.Join(parts, ";")
	hash := truncHash(raw)

	// Detect suspicious patterns.
	var alerts []string
	for _, q := range query.Questions {
		// Long domain names may indicate DNS tunneling.
		if len(q.Name) > 100 {
			alerts = append(alerts, fmt.Sprintf("long query name: %d chars", len(q.Name)))
		}
		// High label count suggests encoded data.
		labels := strings.Count(q.Name, ".") + 1
		if labels > 10 {
			alerts = append(alerts, fmt.Sprintf("high label count: %d", labels))
		}
		// TXT queries to random-looking subdomains (entropy check).
		if q.Type == 16 { // TXT
			alerts = append(alerts, "TXT query (potential exfil)")
		}
		// NULL (10) or ANY (255) queries are unusual.
		if q.Type == 10 || q.Type == 255 {
			alerts = append(alerts, fmt.Sprintf("unusual query type: %d", q.Type))
		}
	}

	now := time.Now()
	fp := &DNSFingerprint{
		Hash:        hash,
		RD:          rd,
		HasEDNS:     query.HasEDNS,
		EDNSBufSize: query.EDNSBufSize,
		DNSSECOK:    query.EDNSDO,
		EDNSOptions: ednsOpts,
		QueryTypes:  qtStr,
		Alerts:      alerts,
		SrcIP:       query.SrcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "dns",
			Hash:      hash,
			SrcIP:     query.SrcIP,
			DstIP:     query.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseDNSQuery parses a DNS message from raw UDP payload (after UDP header).
func ParseDNSQuery(data []byte) (*DNSQuery, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS message too short: %d bytes", len(data))
	}

	q := &DNSQuery{
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		Flags:         binary.BigEndian.Uint16(data[2:4]),
		QDCount:       binary.BigEndian.Uint16(data[4:6]),
		ANCount:       binary.BigEndian.Uint16(data[6:8]),
		NSCount:       binary.BigEndian.Uint16(data[8:10]),
		ARCount:       binary.BigEndian.Uint16(data[10:12]),
	}

	// Only parse queries (QR=0).
	if q.Flags&0x8000 != 0 {
		return nil, fmt.Errorf("not a query (QR=1)")
	}

	pos := 12

	// Parse questions.
	for i := 0; i < int(q.QDCount); i++ {
		name, newPos, err := parseDNSName(data, pos)
		if err != nil {
			return nil, fmt.Errorf("question %d name: %w", i, err)
		}
		pos = newPos

		if pos+4 > len(data) {
			return nil, fmt.Errorf("question %d truncated", i)
		}
		qtype := binary.BigEndian.Uint16(data[pos : pos+2])
		qclass := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4

		q.Questions = append(q.Questions, DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}

	// Skip answer + authority sections to find additional records (EDNS OPT).
	for i := 0; i < int(q.ANCount)+int(q.NSCount); i++ {
		_, newPos, err := parseDNSName(data, pos)
		if err != nil {
			break
		}
		pos = newPos
		if pos+10 > len(data) {
			break
		}
		rdlen := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
		pos += 10 + rdlen
		if pos > len(data) {
			break
		}
	}

	// Parse additional records looking for OPT (type 41).
	for i := 0; i < int(q.ARCount); i++ {
		_, newPos, err := parseDNSName(data, pos)
		if err != nil {
			break
		}
		pos = newPos
		if pos+10 > len(data) {
			break
		}
		rrType := binary.BigEndian.Uint16(data[pos : pos+2])
		if rrType == 41 { // OPT record
			q.HasEDNS = true
			q.EDNSBufSize = binary.BigEndian.Uint16(data[pos+2 : pos+4])
			// Extended RCODE and flags are in TTL field (bytes pos+4:pos+8).
			extFlags := binary.BigEndian.Uint32(data[pos+4 : pos+8])
			q.EDNSVersion = uint8((extFlags >> 16) & 0xff)
			q.EDNSDO = extFlags&0x8000 != 0

			// Parse EDNS options from RDATA.
			rdlen := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
			optData := data[pos+10:]
			if len(optData) > rdlen {
				optData = optData[:rdlen]
			}
			optPos := 0
			for optPos+4 <= len(optData) {
				optCode := binary.BigEndian.Uint16(optData[optPos : optPos+2])
				optLen := int(binary.BigEndian.Uint16(optData[optPos+2 : optPos+4]))
				q.EDNSOptions = append(q.EDNSOptions, optCode)
				optPos += 4 + optLen
			}
		}
		rdlen := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
		pos += 10 + rdlen
		if pos > len(data) {
			break
		}
	}

	return q, nil
}

// parseDNSName parses a DNS name from wire format, handling compression pointers.
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	pos := offset
	jumped := false
	returnPos := 0
	maxJumps := 10

	for jumps := 0; jumps < maxJumps; jumps++ {
		if pos >= len(data) {
			return "", 0, fmt.Errorf("name extends past data")
		}

		length := int(data[pos])

		if length == 0 {
			if !jumped {
				returnPos = pos + 1
			}
			break
		}

		// Compression pointer (top 2 bits set).
		if length&0xc0 == 0xc0 {
			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("compression pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(data[pos:pos+2])) & 0x3fff
			if !jumped {
				returnPos = pos + 2
				jumped = true
			}
			pos = ptr
			continue
		}

		pos++
		if pos+length > len(data) {
			return "", 0, fmt.Errorf("label extends past data")
		}
		labels = append(labels, string(data[pos:pos+length]))
		pos += length
	}

	if !jumped && returnPos == 0 {
		returnPos = pos
	}

	return strings.Join(labels, "."), returnPos, nil
}
