package inspect

import (
	"strings"
	"testing"
	"time"
)

func TestFingerprintTLS_Basic(t *testing.T) {
	engine := NewEngine(nil)

	hello := &ClientHello{
		Version: 0x0303, // TLS 1.2
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, // TLS 1.3 suites
			0xc02c, 0xc02b, 0xc030, // ECDHE suites
			0x009f, 0x009e,          // DHE suites
		},
		Extensions: []uint16{
			0x0000, // SNI
			0x0017, // extended_master_secret
			0x0023, // session_ticket
			0xff01, // renegotiation_info
			0x000a, // supported_groups
			0x000b, // ec_point_formats
			0x000d, // signature_algorithms
			0x0010, // ALPN
		},
		EllipticCurves: []uint16{0x0017, 0x0018, 0x0019},
		ECPointFormats: []uint8{0x00},
		SignatureAlgs:  []uint16{0x0401, 0x0501, 0x0601},
		ALPNProtocols:  []string{"h2", "http/1.1"},
		SNI:            "example.com",
		SrcIP:          "192.168.1.100",
		DstIP:          "93.184.216.34",
	}

	fp, err := engine.FingerprintTLS(hello)
	if err != nil {
		t.Fatalf("FingerprintTLS: %v", err)
	}

	// Check prefix format: t{version}{sni}{cipher_count}{ext_count}{alpn}
	if fp.Version != "12" {
		t.Errorf("version = %q, want %q", fp.Version, "12")
	}
	if fp.SNI != "d" {
		t.Errorf("sni = %q, want %q", fp.SNI, "d")
	}
	if fp.CipherCount != "08" {
		t.Errorf("cipher_count = %q, want %q", fp.CipherCount, "08")
	}
	if fp.ExtCount != "08" {
		t.Errorf("ext_count = %q, want %q", fp.ExtCount, "08")
	}
	if fp.ALPN != "h2" {
		t.Errorf("alpn = %q, want %q", fp.ALPN, "h2")
	}

	// Hash should have format: prefix_cipherhash_exthash
	parts := strings.Split(fp.Hash, "_")
	if len(parts) != 3 {
		t.Fatalf("hash has %d parts, want 3: %s", len(parts), fp.Hash)
	}
	if !strings.HasPrefix(parts[0], "t12d0808h2") {
		t.Errorf("hash prefix = %q, want t12d0808h2", parts[0])
	}
	if len(parts[1]) != 12 {
		t.Errorf("cipher hash len = %d, want 12: %s", len(parts[1]), parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("ext hash len = %d, want 12: %s", len(parts[2]), parts[2])
	}

	// Raw hash should differ from sorted hash (different cipher/ext order).
	if fp.RawHash == "" {
		t.Error("raw hash is empty")
	}
}

func TestFingerprintTLS_GREASE(t *testing.T) {
	engine := NewEngine(nil)

	hello := &ClientHello{
		Version: 0x0304, // TLS 1.3
		CipherSuites: []uint16{
			0x0a0a, // GREASE — should be filtered
			0x1301, 0x1302,
		},
		Extensions: []uint16{
			0x2a2a, // GREASE — should be filtered
			0x0000, 0x000d,
		},
		ALPNProtocols: []string{"h2"},
		SNI:           "test.example.com",
		SrcIP:         "10.0.0.1",
	}

	fp, err := engine.FingerprintTLS(hello)
	if err != nil {
		t.Fatalf("FingerprintTLS: %v", err)
	}

	// GREASE should be filtered: 2 ciphers, 2 extensions.
	if fp.CipherCount != "02" {
		t.Errorf("cipher_count = %q, want %q (GREASE not filtered)", fp.CipherCount, "02")
	}
	if fp.ExtCount != "02" {
		t.Errorf("ext_count = %q, want %q (GREASE not filtered)", fp.ExtCount, "02")
	}
	if fp.Version != "13" {
		t.Errorf("version = %q, want %q", fp.Version, "13")
	}
}

func TestFingerprintTLS_IPAddress(t *testing.T) {
	engine := NewEngine(nil)

	hello := &ClientHello{
		Version:      0x0304,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x0000},
		SNI:          "192.168.1.1", // IP address, not domain
		SrcIP:        "10.0.0.1",
	}

	fp, err := engine.FingerprintTLS(hello)
	if err != nil {
		t.Fatalf("FingerprintTLS: %v", err)
	}
	if fp.SNI != "i" {
		t.Errorf("sni = %q, want %q for IP address", fp.SNI, "i")
	}
}

func TestFingerprintTLS_NoSNI(t *testing.T) {
	engine := NewEngine(nil)

	hello := &ClientHello{
		Version:      0x0304,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x0000},
		SNI:          "", // No SNI
		SrcIP:        "10.0.0.1",
	}

	fp, err := engine.FingerprintTLS(hello)
	if err != nil {
		t.Fatalf("FingerprintTLS: %v", err)
	}
	if fp.SNI != "i" {
		t.Errorf("sni = %q, want %q for empty SNI", fp.SNI, "i")
	}
}

func TestFingerprintServer(t *testing.T) {
	engine := NewEngine(nil)

	hello := &ServerHello{
		Version:      0x0303,
		CipherSuite:  0xc02f,
		Extensions:   []uint16{0xff01, 0x000b, 0x0023},
		ALPNProtocol: "h2",
		SrcIP:        "93.184.216.34",
	}

	fp, err := engine.FingerprintServer(hello)
	if err != nil {
		t.Fatalf("FingerprintServer: %v", err)
	}

	if fp.Version != "12" {
		t.Errorf("version = %q, want %q", fp.Version, "12")
	}
	if fp.CipherSuite != "c02f" {
		t.Errorf("cipher_suite = %q, want %q", fp.CipherSuite, "c02f")
	}
	if fp.ExtCount != "03" {
		t.Errorf("ext_count = %q, want %q", fp.ExtCount, "03")
	}

	parts := strings.Split(fp.Hash, "_")
	if len(parts) != 3 {
		t.Fatalf("hash has %d parts, want 3", len(parts))
	}
}

func TestFingerprintTCP(t *testing.T) {
	engine := NewEngine(nil)

	syn := &TCPSyn{
		WindowSize: 65535,
		Options: []TCPOption{
			{Kind: 2, Length: 4},  // MSS
			{Kind: 1},            // NOP
			{Kind: 3, Length: 3}, // Window Scale
			{Kind: 1},            // NOP
			{Kind: 1},            // NOP
			{Kind: 8, Length: 10}, // Timestamps
			{Kind: 4, Length: 2}, // SACK Permitted
		},
		TTL:         64,
		MSS:         1460,
		WindowScale: 7,
		SrcIP:       "192.168.1.100",
		DstIP:       "93.184.216.34",
	}

	fp, err := engine.FingerprintTCP(syn)
	if err != nil {
		t.Fatalf("FingerprintTCP: %v", err)
	}

	if fp.WindowSize != 65535 {
		t.Errorf("window_size = %d, want 65535", fp.WindowSize)
	}
	if fp.TTL != 64 {
		t.Errorf("ttl = %d, want 64", fp.TTL)
	}
	if fp.Options != "2-1-3-1-1-8-4" {
		t.Errorf("options = %q, want %q", fp.Options, "2-1-3-1-1-8-4")
	}
	if fp.Hash == "" {
		t.Error("hash is empty")
	}
	// TTL 64 + window 65535 -> macOS guess.
	if fp.OSGuess != "macOS" {
		t.Errorf("os_guess = %q, want %q", fp.OSGuess, "macOS")
	}
}

func TestFingerprintTCP_Windows(t *testing.T) {
	engine := NewEngine(nil)

	syn := &TCPSyn{
		WindowSize:  8192,
		Options:     []TCPOption{{Kind: 2, Length: 4}, {Kind: 3, Length: 3}},
		TTL:         128,
		MSS:         1460,
		WindowScale: 8,
		SrcIP:       "192.168.1.50",
	}

	fp, err := engine.FingerprintTCP(syn)
	if err != nil {
		t.Fatalf("FingerprintTCP: %v", err)
	}

	if fp.OSGuess != "Windows" {
		t.Errorf("os_guess = %q, want %q", fp.OSGuess, "Windows")
	}
}

func TestFingerprintHTTP(t *testing.T) {
	engine := NewEngine(nil)

	headers := &HTTPHeaders{
		Method: "GET",
		Path:   "/api/data",
		Headers: [][2]string{
			{"Host", "example.com"},
			{"User-Agent", "Mozilla/5.0"},
			{"Accept", "text/html"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Accept-Encoding", "gzip, deflate, br"},
			{"Cookie", "session=abc123; theme=dark"},
		},
		AcceptLang: "en-US,en;q=0.9",
		Cookie:     "session=abc123; theme=dark",
		SrcIP:      "192.168.1.100",
	}

	fp, err := engine.FingerprintHTTP(headers)
	if err != nil {
		t.Fatalf("FingerprintHTTP: %v", err)
	}

	if fp.Method != "GET" {
		t.Errorf("method = %q, want %q", fp.Method, "GET")
	}
	// 6 headers - cookie - accept-language = 4 counted headers
	if fp.HeaderCount != "04" {
		t.Errorf("header_count = %q, want %q", fp.HeaderCount, "04")
	}
	// 2 cookies (separated by ;)
	if fp.CookieCount != "02" {
		t.Errorf("cookie_count = %q, want %q", fp.CookieCount, "02")
	}
	if fp.Hash == "" {
		t.Error("hash is empty")
	}
}

func TestIdentifyDevice(t *testing.T) {
	engine := NewEngine(nil)

	// Test exact prefix match.
	id, conf, err := engine.IdentifyDevice("t13d1516h2_abc123def456_789012345678")
	if err != nil {
		t.Fatalf("IdentifyDevice: %v", err)
	}
	if id == nil {
		t.Fatal("expected device match, got nil")
	}
	if id.Category != "browser" {
		t.Errorf("category = %q, want %q", id.Category, "browser")
	}
	if conf <= 0 {
		t.Errorf("confidence = %f, want > 0", conf)
	}

	// Test no match.
	id, conf, err = engine.IdentifyDevice("x99z0000h2_000000000000_000000000000")
	if err != nil {
		t.Fatalf("IdentifyDevice: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil for unknown fingerprint, got %+v", id)
	}
}

func TestCheckThreat_NoFeed(t *testing.T) {
	engine := NewEngine(nil)

	match, err := engine.CheckThreat("t13d1516h2_abc123def456_789012345678")
	if err != nil {
		t.Fatalf("CheckThreat: %v", err)
	}
	if match.Matched {
		t.Error("expected no match with empty feeds")
	}
}

func TestCheckThreat_WithFeed(t *testing.T) {
	engine := NewEngine(nil)

	engine.AddThreatFeed(ThreatFeed{
		Name:    "test-feed",
		Enabled: true,
		Hashes: map[string]ThreatEntry{
			"t13d1516h2_malware12345_badbadbad123": {
				Hash:       "t13d1516h2_malware12345_badbadbad123",
				ThreatType: "c2",
				ThreatName: "Cobalt Strike",
				Severity:   "critical",
			},
		},
		LastUpdate: time.Now(),
	})

	// Match.
	match, err := engine.CheckThreat("t13d1516h2_malware12345_badbadbad123")
	if err != nil {
		t.Fatalf("CheckThreat: %v", err)
	}
	if !match.Matched {
		t.Error("expected match")
	}
	if match.ThreatName != "Cobalt Strike" {
		t.Errorf("threat_name = %q, want %q", match.ThreatName, "Cobalt Strike")
	}

	// No match.
	match, err = engine.CheckThreat("t13d1516h2_clean1234567_goodgoodgood")
	if err != nil {
		t.Fatalf("CheckThreat: %v", err)
	}
	if match.Matched {
		t.Error("expected no match for clean fingerprint")
	}
}

func TestFilterGREASE(t *testing.T) {
	input := []uint16{0x0a0a, 0x1301, 0x2a2a, 0x1302, 0xfafa}
	result := filterGREASE(input)
	if len(result) != 2 {
		t.Fatalf("filterGREASE: got %d values, want 2", len(result))
	}
	if result[0] != 0x1301 || result[1] != 0x1302 {
		t.Errorf("filterGREASE = %v, want [0x1301, 0x1302]", result)
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0000, "00"},
	}

	for _, tt := range tests {
		got := tlsVersionString(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestTruncHash(t *testing.T) {
	h := truncHash("test data")
	if len(h) != 12 {
		t.Errorf("truncHash length = %d, want 12", len(h))
	}
	// Same input should produce same hash.
	h2 := truncHash("test data")
	if h != h2 {
		t.Errorf("truncHash not deterministic: %q != %q", h, h2)
	}
	// Different input should produce different hash.
	h3 := truncHash("other data")
	if h == h3 {
		t.Errorf("truncHash collision: %q == %q", h, h3)
	}
}

func TestNilInputs(t *testing.T) {
	engine := NewEngine(nil)

	_, err := engine.FingerprintTLS(nil)
	if err == nil {
		t.Error("expected error for nil ClientHello")
	}
	_, err = engine.FingerprintServer(nil)
	if err == nil {
		t.Error("expected error for nil ServerHello")
	}
	_, err = engine.FingerprintTCP(nil)
	if err == nil {
		t.Error("expected error for nil TCPSyn")
	}
	_, err = engine.FingerprintHTTP(nil)
	if err == nil {
		t.Error("expected error for nil HTTPHeaders")
	}
}
