package inspect

import (
	"encoding/binary"
	"testing"
)

func TestFingerprintDNS_Basic(t *testing.T) {
	e := NewEngine(nil)

	q := &DNSQuery{
		Flags:   0x0100, // RD set
		HasEDNS: true,
		EDNSBufSize: 4096,
		EDNSDO:  true,
		Questions: []DNSQuestion{
			{Name: "example.com", Type: 1, Class: 1},
		},
		SrcIP: "192.168.1.100",
	}

	fp, err := e.FingerprintDNS(q)
	if err != nil {
		t.Fatalf("FingerprintDNS: %v", err)
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if !fp.RD {
		t.Error("RD should be true")
	}
	if !fp.HasEDNS {
		t.Error("EDNS should be true")
	}
	if !fp.DNSSECOK {
		t.Error("DNSSEC OK should be true")
	}
}

func TestFingerprintDNS_TunnelingDetection(t *testing.T) {
	e := NewEngine(nil)

	// Long query name suggests DNS tunneling.
	longName := "aVeryLongSubdomainThatCouldBeEncodedDataInADNSTunnelingAttemptWithLotsOfCharacters.more.labels.even.more.labels.tunneling.example.com"
	q := &DNSQuery{
		Flags: 0x0100,
		Questions: []DNSQuestion{
			{Name: longName, Type: 16, Class: 1}, // TXT query
		},
		SrcIP: "10.0.0.50",
	}

	fp, err := e.FingerprintDNS(q)
	if err != nil {
		t.Fatalf("FingerprintDNS: %v", err)
	}

	if len(fp.Alerts) == 0 {
		t.Error("expected alerts for suspicious DNS query")
	}

	foundLong := false
	foundTXT := false
	for _, a := range fp.Alerts {
		if a == "TXT query (potential exfil)" {
			foundTXT = true
		}
		if len(a) > 10 && a[:10] == "long query" {
			foundLong = true
		}
	}
	if !foundLong {
		t.Error("expected long query name alert")
	}
	if !foundTXT {
		t.Error("expected TXT query alert")
	}
}

func TestFingerprintDNS_Nil(t *testing.T) {
	e := NewEngine(nil)
	_, err := e.FingerprintDNS(nil)
	if err == nil {
		t.Error("expected error for nil")
	}
}

func TestParseDNSQuery(t *testing.T) {
	// Build a simple DNS query for "example.com" A record.
	pkt := buildDNSQuery("example.com", 1, true, false)

	q, err := ParseDNSQuery(pkt)
	if err != nil {
		t.Fatalf("ParseDNSQuery: %v", err)
	}

	if len(q.Questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(q.Questions))
	}
	if q.Questions[0].Name != "example.com" {
		t.Errorf("name = %q, want example.com", q.Questions[0].Name)
	}
	if q.Questions[0].Type != 1 {
		t.Errorf("type = %d, want 1 (A)", q.Questions[0].Type)
	}
	if q.Flags&0x0100 == 0 {
		t.Error("RD flag should be set")
	}
}

func TestParseDNSQuery_EDNS(t *testing.T) {
	pkt := buildDNSQuery("test.com", 1, true, true)

	q, err := ParseDNSQuery(pkt)
	if err != nil {
		t.Fatalf("ParseDNSQuery: %v", err)
	}

	if !q.HasEDNS {
		t.Error("EDNS should be detected")
	}
	if q.EDNSBufSize != 4096 {
		t.Errorf("EDNS buffer size = %d, want 4096", q.EDNSBufSize)
	}
}

func TestParseDNSQuery_Response(t *testing.T) {
	pkt := buildDNSQuery("example.com", 1, true, false)
	// Set QR=1 (response).
	pkt[2] |= 0x80

	_, err := ParseDNSQuery(pkt)
	if err == nil {
		t.Error("expected error for response packet")
	}
}

func TestParseDNSName(t *testing.T) {
	// Wire format: \x07example\x03com\x00
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, _, err := parseDNSName(data, 0)
	if err != nil {
		t.Fatalf("parseDNSName: %v", err)
	}
	if name != "example.com" {
		t.Errorf("name = %q, want example.com", name)
	}
}

func TestParseDNSName_Compression(t *testing.T) {
	// Build data with a name at offset 0, then a pointer at offset 13.
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	// Add a compression pointer to offset 0.
	data = append(data, 0xc0, 0x00)

	name, _, err := parseDNSName(data, 13)
	if err != nil {
		t.Fatalf("parseDNSName: %v", err)
	}
	if name != "example.com" {
		t.Errorf("name = %q, want example.com", name)
	}
}

// buildDNSQuery creates a synthetic DNS query packet.
func buildDNSQuery(name string, qtype uint16, rd, edns bool) []byte {
	var pkt []byte

	// Header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	pkt = append(pkt, 0x12, 0x34) // Transaction ID
	flags := uint16(0)
	if rd {
		flags |= 0x0100
	}
	pkt = append(pkt, byte(flags>>8), byte(flags))
	pkt = append(pkt, 0, 1) // QDCOUNT = 1
	pkt = append(pkt, 0, 0) // ANCOUNT = 0
	pkt = append(pkt, 0, 0) // NSCOUNT = 0
	arcount := uint16(0)
	if edns {
		arcount = 1
	}
	pkt = append(pkt, byte(arcount>>8), byte(arcount))

	// Question: name + type + class
	pkt = append(pkt, encodeDNSName(name)...)
	typeBuf := make([]byte, 4)
	binary.BigEndian.PutUint16(typeBuf[0:2], qtype)
	binary.BigEndian.PutUint16(typeBuf[2:4], 1) // IN class
	pkt = append(pkt, typeBuf...)

	// OPT record for EDNS.
	if edns {
		pkt = append(pkt, 0)    // Root name
		pkt = append(pkt, 0, 41) // Type = OPT (41)
		pkt = append(pkt, 0x10, 0x00) // UDP payload size = 4096
		pkt = append(pkt, 0, 0, 0x80, 0x00) // Extended RCODE=0, version=0, DO=1
		pkt = append(pkt, 0, 0) // RDATA length = 0
	}

	return pkt
}

// encodeDNSName encodes a domain name to DNS wire format.
func encodeDNSName(name string) []byte {
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
			start = i + 1
		}
	}
	buf = append(buf, 0) // Root label
	return buf
}
