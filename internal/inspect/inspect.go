// Package inspect provides passive TLS fingerprinting and device profiling.
//
// It implements JA4+ fingerprint extraction from TLS ClientHello, ServerHello,
// TCP SYN, and HTTP headers. Fingerprints are stored in a local database and
// can be matched against known device profiles and threat intelligence feeds.
//
// This entire feature is opt-in. When disabled, zero CPU overhead.
package inspect

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PacketInspector defines the interface for passive traffic analysis.
type PacketInspector interface {
	// FingerprintTLS extracts a JA4 fingerprint from a TLS ClientHello.
	FingerprintTLS(hello *ClientHello) (*JA4Fingerprint, error)
	// FingerprintServer extracts a JA4S fingerprint from a TLS ServerHello.
	FingerprintServer(hello *ServerHello) (*JA4SFingerprint, error)
	// FingerprintTCP extracts a JA4T fingerprint from TCP SYN parameters.
	FingerprintTCP(syn *TCPSyn) (*JA4TFingerprint, error)
	// FingerprintHTTP extracts a JA4H fingerprint from HTTP headers.
	FingerprintHTTP(headers *HTTPHeaders) (*JA4HFingerprint, error)
	// IdentifyDevice matches a fingerprint against known device profiles.
	IdentifyDevice(fp string) (*DeviceIdentity, float64, error)
	// CheckThreat checks a fingerprint against threat intelligence feeds.
	CheckThreat(fp string) (*ThreatMatch, error)
}

// ClientHello contains parsed TLS ClientHello fields for JA4 extraction.
type ClientHello struct {
	Version      uint16   // TLS version (0x0303 = TLS 1.2, 0x0301 = TLS 1.0)
	CipherSuites []uint16 // Cipher suite IDs
	Extensions   []uint16 // Extension type IDs
	EllipticCurves []uint16 // Supported groups / named curves
	ECPointFormats []uint8  // EC point format IDs
	SignatureAlgs  []uint16 // Signature algorithms
	ALPNProtocols  []string // ALPN protocol names
	SNI            string   // Server Name Indication
	SrcIP          string   // Source IP address
	DstIP          string   // Destination IP address
	SrcPort        uint16   // Source port
	DstPort        uint16   // Destination port
	Timestamp      time.Time
}

// ServerHello contains parsed TLS ServerHello fields for JA4S extraction.
type ServerHello struct {
	Version      uint16   // Negotiated TLS version
	CipherSuite  uint16   // Selected cipher suite
	Extensions   []uint16 // Extension type IDs
	ALPNProtocol string   // Selected ALPN protocol
	SrcIP        string
	DstIP        string
	Timestamp    time.Time
}

// TCPSyn contains TCP SYN packet parameters for JA4T extraction.
type TCPSyn struct {
	WindowSize uint16     // Initial window size
	Options    []TCPOption // TCP options in order
	TTL        uint8      // IP TTL (used for OS detection)
	MSS        uint16     // Maximum segment size
	WindowScale uint8     // Window scale factor
	SrcIP      string
	DstIP      string
	Timestamp  time.Time
}

// TCPOption represents a single TCP option from the SYN packet.
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// HTTPHeaders contains HTTP request header data for JA4H extraction.
type HTTPHeaders struct {
	Method      string            // GET, POST, etc.
	Path        string            // Request path
	Headers     [][2]string       // Headers in original order (name, value)
	AcceptLang  string            // Accept-Language value
	Cookie      string            // Cookie header (for counting, not storing values)
	SrcIP       string
	Timestamp   time.Time
}

// JA4Fingerprint is a TLS ClientHello fingerprint following the JA4 spec.
type JA4Fingerprint struct {
	Hash       string    `json:"hash"`        // Full JA4 hash (e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1")
	RawHash    string    `json:"raw_hash"`    // Unsorted (original order) hash
	Version    string    `json:"version"`     // TLS version component (e.g. "13" for TLS 1.3)
	SNI        string    `json:"sni"`         // "d" (domain) or "i" (IP)
	CipherCount string  `json:"cipher_count"` // Number of cipher suites (2 chars)
	ExtCount   string    `json:"ext_count"`   // Number of extensions (2 chars)
	ALPN       string    `json:"alpn"`        // First ALPN char pair
	CipherHash string    `json:"cipher_hash"` // Truncated SHA256 of sorted cipher suites
	ExtHash    string    `json:"ext_hash"`    // Truncated SHA256 of sorted extensions
	SrcIP      string    `json:"src_ip"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Count      int64     `json:"count"`
}

// JA4SFingerprint is a TLS ServerHello fingerprint.
type JA4SFingerprint struct {
	Hash      string    `json:"hash"`
	Version   string    `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ExtCount  string    `json:"ext_count"`
	ExtHash   string    `json:"ext_hash"`
	SrcIP     string    `json:"src_ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// JA4TFingerprint is a TCP SYN fingerprint for OS detection.
type JA4TFingerprint struct {
	Hash       string    `json:"hash"`
	WindowSize uint16    `json:"window_size"`
	Options    string    `json:"options"`    // TCP options as ordered string
	TTL        uint8     `json:"ttl"`
	MSS        uint16    `json:"mss"`
	OSGuess    string    `json:"os_guess"`   // Best-guess OS family
	SrcIP      string    `json:"src_ip"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Count      int64     `json:"count"`
}

// JA4HFingerprint is an HTTP header fingerprint.
type JA4HFingerprint struct {
	Hash        string    `json:"hash"`
	Method      string    `json:"method"`
	HeaderCount string    `json:"header_count"`
	HeaderHash  string    `json:"header_hash"`
	CookieCount string    `json:"cookie_count"`
	LangHash    string    `json:"lang_hash"`
	SrcIP       string    `json:"src_ip"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int64     `json:"count"`
}

// DeviceIdentity represents a matched device profile.
type DeviceIdentity struct {
	Name       string  `json:"name"`        // e.g. "Chrome 120 on Windows 11"
	Category   string  `json:"category"`    // "browser", "iot", "mobile", "server"
	OS         string  `json:"os"`          // "Windows", "Linux", "macOS", "iOS", "Android"
	Confidence float64 `json:"confidence"`  // 0.0 - 1.0
}

// ThreatMatch represents a match against a threat intelligence feed.
type ThreatMatch struct {
	Matched    bool      `json:"matched"`
	FeedName   string    `json:"feed_name,omitempty"`   // e.g. "abuse.ch", "Proofpoint ET"
	ThreatType string    `json:"threat_type,omitempty"` // "c2", "malware", "botnet"
	ThreatName string    `json:"threat_name,omitempty"` // e.g. "Cobalt Strike", "Emotet"
	Severity   string    `json:"severity,omitempty"`    // "low", "medium", "high", "critical"
	Reference  string    `json:"reference,omitempty"`   // URL to threat report
	LastUpdate time.Time `json:"last_update,omitempty"`
}

// ObservedFingerprint is a stored observation record.
type ObservedFingerprint struct {
	ID          int64     `json:"id"`
	Type        string    `json:"type"`         // "ja4", "ja4s", "ja4t", "ja4h", "ja4x", "hassh", "hassh_server", "quic"
	Hash        string    `json:"hash"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip,omitempty"`
	SNI         string    `json:"sni,omitempty"`
	DeviceName  string    `json:"device_name,omitempty"`
	AssignedProfile string `json:"assigned_profile,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int64     `json:"count"`
	ThreatMatch bool      `json:"threat_match"`
}

// ThreatFeed represents a configured threat intelligence feed.
type ThreatFeed struct {
	Name       string        `json:"name"`
	URL        string        `json:"url"`
	Format     string        `json:"format"`  // "csv", "json"
	Enabled    bool          `json:"enabled"`
	Hashes     map[string]ThreatEntry `json:"-"` // fingerprint hash -> threat info
	LastUpdate time.Time     `json:"last_update"`
	EntryCount int           `json:"entry_count"`
}

// ThreatEntry is a single entry from a threat feed.
type ThreatEntry struct {
	Hash       string `json:"hash"`
	ThreatType string `json:"threat_type"`
	ThreatName string `json:"threat_name"`
	Severity   string `json:"severity"`
	Reference  string `json:"reference"`
}

// GREASE values to filter from JA4 calculations (RFC 8701).
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// isGREASE returns true if the value is a GREASE sentinel.
func isGREASE(v uint16) bool {
	return greaseValues[v]
}

// tlsVersionString returns the JA4 version component for a TLS version.
func tlsVersionString(v uint16) string {
	switch v {
	case 0x0304:
		return "13" // TLS 1.3
	case 0x0303:
		return "12" // TLS 1.2
	case 0x0302:
		return "11" // TLS 1.1
	case 0x0301:
		return "10" // TLS 1.0
	case 0x0300:
		return "s3" // SSL 3.0
	default:
		return "00"
	}
}

// truncHash returns the first 12 hex characters of a SHA256 hash.
func truncHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:6]) // 6 bytes = 12 hex chars
}

// filterGREASE removes GREASE values from a uint16 slice.
func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// uint16sToSortedString converts sorted uint16 values to a comma-separated hex string.
func uint16sToSortedString(vals []uint16) string {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	parts := make([]string, len(sorted))
	for i, v := range sorted {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// uint16sToString converts uint16 values to a comma-separated hex string (preserving order).
func uint16sToString(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}
