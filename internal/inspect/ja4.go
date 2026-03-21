package inspect

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Engine implements the PacketInspector interface.
//
// Threat feed lookups use a merged index for O(1) performance regardless of
// how many feeds are loaded. When feeds are updated via SetThreatFeeds(), the
// engine rebuilds a single merged map and atomically swaps it in. This means:
//   - 1 feed or 100 feeds: same lookup cost (one map access)
//   - Feed updates don't block in-flight lookups (atomic pointer swap)
//   - No per-packet iteration over feed lists
type Engine struct {
	db           FingerprintStore
	threatFeeds  []ThreatFeed
	knownDevices []KnownDevice
	// mergedThreats is the pre-computed union of all enabled feed hashes.
	// Key: fingerprint hash → value: merged ThreatMatch with source feed info.
	// Swapped atomically via atomic.Value so lookups never block or race.
	mergedThreats atomic.Value // stores map[string]ThreatMatch
}

// KnownDevice maps a fingerprint pattern to a device identity.
type KnownDevice struct {
	Pattern    string         // JA4 hash prefix or exact match
	Identity   DeviceIdentity
}

// FingerprintStore persists observed fingerprints.
type FingerprintStore interface {
	RecordFingerprint(fp ObservedFingerprint) error
	GetFingerprint(hash string) (*ObservedFingerprint, error)
	ListFingerprints(fpType string, limit int) ([]ObservedFingerprint, error)
	AssignProfile(hash, profileName string) error
	ListThreatMatches() ([]ObservedFingerprint, error)
}

// NewEngine creates a new fingerprint engine.
func NewEngine(store FingerprintStore) *Engine {
	e := &Engine{
		db:          store,
		knownDevices: defaultKnownDevices(),
	}
	return e
}

// FingerprintTLS extracts a JA4 fingerprint from a TLS ClientHello.
//
// JA4 format: {q}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
//
// Where:
//   - q: "t" for TCP, "q" for QUIC
//   - version: 2-char TLS version ("13", "12", etc.)
//   - sni: "d" if SNI contains a domain, "i" if IP/empty
//   - cipher_count: 2-digit count of cipher suites (excluding GREASE)
//   - ext_count: 2-digit count of extensions (excluding GREASE)
//   - alpn: first and last char of first ALPN protocol ("h2", "00" if none)
//   - cipher_hash: truncated SHA256 of sorted cipher suites
//   - ext_hash: truncated SHA256 of sorted extensions + signature algs + elliptic curves
func (e *Engine) FingerprintTLS(hello *ClientHello) (*JA4Fingerprint, error) {
	if hello == nil {
		return nil, fmt.Errorf("nil ClientHello")
	}

	ciphers := filterGREASE(hello.CipherSuites)
	extensions := filterGREASE(hello.Extensions)

	// Version component.
	ver := tlsVersionString(hello.Version)

	// SNI component: "d" for domain, "i" for IP or empty.
	sni := "i"
	if hello.SNI != "" && net.ParseIP(hello.SNI) == nil {
		sni = "d"
	}

	// Counts (2 digits, capped at 99).
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN: first and last character of first ALPN protocol.
	alpn := "00"
	if len(hello.ALPNProtocols) > 0 && len(hello.ALPNProtocols[0]) >= 2 {
		p := hello.ALPNProtocols[0]
		alpn = string(p[0]) + string(p[len(p)-1])
	} else if len(hello.ALPNProtocols) > 0 && len(hello.ALPNProtocols[0]) == 1 {
		alpn = string(hello.ALPNProtocols[0][0]) + string(hello.ALPNProtocols[0][0])
	}

	// Prefix: t{version}{sni}{cipher_count}{ext_count}{alpn}
	prefix := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, cipherCount, extCount, alpn)

	// Cipher hash: sorted cipher suites.
	cipherStr := uint16sToSortedString(ciphers)
	cipherHash := truncHash(cipherStr)

	// Extension hash: sorted extensions, then signature algs, then curves.
	extStr := uint16sToSortedString(extensions)
	sigAlgs := uint16sToSortedString(filterGREASE(hello.SignatureAlgs))
	curves := uint16sToSortedString(filterGREASE(hello.EllipticCurves))
	fullExtStr := extStr
	if sigAlgs != "" {
		fullExtStr += "_" + sigAlgs
	}
	if curves != "" {
		fullExtStr += "_" + curves
	}
	extHash := truncHash(fullExtStr)

	hash := fmt.Sprintf("%s_%s_%s", prefix, cipherHash, extHash)

	// Raw hash (original order, not sorted).
	rawCipherStr := uint16sToString(ciphers)
	rawExtStr := uint16sToString(extensions)
	rawCipherHash := truncHash(rawCipherStr)
	rawFullExtStr := rawExtStr
	if sigAlgs != "" {
		rawFullExtStr += "_" + uint16sToString(filterGREASE(hello.SignatureAlgs))
	}
	if curves != "" {
		rawFullExtStr += "_" + uint16sToString(filterGREASE(hello.EllipticCurves))
	}
	rawExtHash := truncHash(rawFullExtStr)
	rawHash := fmt.Sprintf("%s_%s_%s", prefix, rawCipherHash, rawExtHash)

	now := time.Now()
	fp := &JA4Fingerprint{
		Hash:        hash,
		RawHash:     rawHash,
		Version:     ver,
		SNI:         sni,
		CipherCount: fmt.Sprintf("%02d", cipherCount),
		ExtCount:    fmt.Sprintf("%02d", extCount),
		ALPN:        alpn,
		CipherHash:  cipherHash,
		ExtHash:     extHash,
		SrcIP:       hello.SrcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	// Record to store if available.
	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "ja4",
			Hash:      hash,
			SrcIP:     hello.SrcIP,
			DstIP:     hello.DstIP,
			SNI:       hello.SNI,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// FingerprintServer extracts a JA4S fingerprint from a TLS ServerHello.
//
// JA4S format: {q}{version}{ext_count}{alpn}_{cipher}_{ext_hash}
func (e *Engine) FingerprintServer(hello *ServerHello) (*JA4SFingerprint, error) {
	if hello == nil {
		return nil, fmt.Errorf("nil ServerHello")
	}

	extensions := filterGREASE(hello.Extensions)
	ver := tlsVersionString(hello.Version)

	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	alpn := "00"
	if len(hello.ALPNProtocol) >= 2 {
		alpn = string(hello.ALPNProtocol[0]) + string(hello.ALPNProtocol[len(hello.ALPNProtocol)-1])
	}

	prefix := fmt.Sprintf("t%s%02d%s", ver, extCount, alpn)
	cipherStr := fmt.Sprintf("%04x", hello.CipherSuite)
	extHash := truncHash(uint16sToSortedString(extensions))

	hash := fmt.Sprintf("%s_%s_%s", prefix, cipherStr, extHash)

	now := time.Now()
	fp := &JA4SFingerprint{
		Hash:        hash,
		Version:     ver,
		CipherSuite: cipherStr,
		ExtCount:    fmt.Sprintf("%02d", extCount),
		ExtHash:     extHash,
		SrcIP:       hello.SrcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "ja4s",
			Hash:      hash,
			SrcIP:     hello.SrcIP,
			DstIP:     hello.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// FingerprintTCP extracts a JA4T fingerprint from TCP SYN parameters.
//
// JA4T captures: window size, TCP options (in order), TTL, and MSS.
// These parameters vary by OS and are used for passive OS fingerprinting.
func (e *Engine) FingerprintTCP(syn *TCPSyn) (*JA4TFingerprint, error) {
	if syn == nil {
		return nil, fmt.Errorf("nil TCPSyn")
	}

	// Build options string from TCP option kinds.
	optParts := make([]string, len(syn.Options))
	for i, opt := range syn.Options {
		optParts[i] = fmt.Sprintf("%d", opt.Kind)
	}
	optStr := strings.Join(optParts, "-")

	raw := fmt.Sprintf("%d_%s_%d_%d_%d", syn.WindowSize, optStr, syn.TTL, syn.MSS, syn.WindowScale)
	hash := truncHash(raw)

	// Guess OS based on TTL and window size heuristics.
	osGuess := guessOS(syn.TTL, syn.WindowSize, syn.MSS)

	now := time.Now()
	fp := &JA4TFingerprint{
		Hash:       hash,
		WindowSize: syn.WindowSize,
		Options:    optStr,
		TTL:        syn.TTL,
		MSS:        syn.MSS,
		OSGuess:    osGuess,
		SrcIP:      syn.SrcIP,
		FirstSeen:  now,
		LastSeen:   now,
		Count:      1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "ja4t",
			Hash:      hash,
			SrcIP:     syn.SrcIP,
			DstIP:     syn.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// FingerprintHTTP extracts a JA4H fingerprint from HTTP request headers.
//
// JA4H format: {method}{version}{header_count}{accept_lang}_{header_hash}_{cookie_hash}_{lang_hash}
func (e *Engine) FingerprintHTTP(headers *HTTPHeaders) (*JA4HFingerprint, error) {
	if headers == nil {
		return nil, fmt.Errorf("nil HTTPHeaders")
	}

	// Method prefix (2 chars).
	method := strings.ToLower(headers.Method)
	if len(method) > 2 {
		method = method[:2]
	}

	// Header names in order (lowercase, excluding Cookie and accept-language).
	var headerNames []string
	for _, h := range headers.Headers {
		name := strings.ToLower(h[0])
		if name == "cookie" || name == "accept-language" {
			continue
		}
		headerNames = append(headerNames, name)
	}

	headerCount := len(headerNames)
	if headerCount > 99 {
		headerCount = 99
	}

	// Cookie count.
	cookieCount := 0
	if headers.Cookie != "" {
		cookieCount = strings.Count(headers.Cookie, ";") + 1
	}
	if cookieCount > 99 {
		cookieCount = 99
	}

	headerHash := truncHash(strings.Join(headerNames, ","))

	// Language hash.
	langHash := "000000000000"
	if headers.AcceptLang != "" {
		langHash = truncHash(headers.AcceptLang)
	}

	prefix := fmt.Sprintf("%s%02d%02d", method, headerCount, cookieCount)
	hash := fmt.Sprintf("%s_%s_%s", prefix, headerHash, langHash)

	now := time.Now()
	fp := &JA4HFingerprint{
		Hash:        hash,
		Method:      headers.Method,
		HeaderCount: fmt.Sprintf("%02d", headerCount),
		HeaderHash:  headerHash,
		CookieCount: fmt.Sprintf("%02d", cookieCount),
		LangHash:    langHash,
		SrcIP:       headers.SrcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "ja4h",
			Hash:      hash,
			SrcIP:     headers.SrcIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// IdentifyDevice matches a fingerprint hash against the known device database.
func (e *Engine) IdentifyDevice(fp string) (*DeviceIdentity, float64, error) {
	if fp == "" {
		return nil, 0, fmt.Errorf("empty fingerprint")
	}

	// Check exact match first, then prefix match.
	for _, kd := range e.knownDevices {
		if kd.Pattern == fp {
			return &kd.Identity, kd.Identity.Confidence, nil
		}
	}

	// Prefix match on the first section (before first underscore).
	fpPrefix := fp
	if idx := strings.Index(fp, "_"); idx >= 0 {
		fpPrefix = fp[:idx]
	}
	for _, kd := range e.knownDevices {
		if strings.HasPrefix(fpPrefix, kd.Pattern) {
			id := kd.Identity
			id.Confidence *= 0.7 // Lower confidence for prefix match.
			return &id, id.Confidence, nil
		}
	}

	return nil, 0, nil // No match, not an error.
}

// CheckThreat checks a fingerprint against the merged threat index.
//
// Performance: O(1) single map lookup regardless of feed count.
// 100 feeds with 1M entries total = same cost as 1 feed with 100 entries.
// The merged index is rebuilt on feed update, not on every lookup.
func (e *Engine) CheckThreat(fp string) (*ThreatMatch, error) {
	if fp == "" {
		return &ThreatMatch{Matched: false}, nil
	}

	// Single map lookup — O(1). Load atomically to avoid data race.
	threats, _ := e.mergedThreats.Load().(map[string]ThreatMatch)
	if match, ok := threats[fp]; ok {
		return &match, nil
	}

	return &ThreatMatch{Matched: false}, nil
}

// AddThreatFeed adds a threat intelligence feed and rebuilds the merged index.
func (e *Engine) AddThreatFeed(feed ThreatFeed) {
	e.threatFeeds = append(e.threatFeeds, feed)
	e.rebuildMergedIndex()
}

// SetThreatFeeds replaces all feeds and rebuilds the merged index atomically.
// Called by FeedScheduler when any feed is updated.
func (e *Engine) SetThreatFeeds(feeds []ThreatFeed) {
	e.threatFeeds = feeds
	e.rebuildMergedIndex()
}

// rebuildMergedIndex builds a single lookup map from all enabled feeds.
// This runs on feed update (infrequent), not on every packet (hot path).
//
// Merge strategy:
//   - Later feeds override earlier feeds for the same hash
//   - Higher severity entries take priority over lower severity
//   - Disabled feeds are excluded entirely
func (e *Engine) rebuildMergedIndex() {
	// Build new index in a local variable — no locks needed during build.
	merged := make(map[string]ThreatMatch)

	severityRank := map[string]int{
		"critical": 4, "high": 3, "medium": 2, "low": 1,
	}

	for _, feed := range e.threatFeeds {
		if !feed.Enabled {
			continue
		}
		for hash, entry := range feed.Hashes {
			existing, exists := merged[hash]
			if exists {
				// Keep the higher-severity entry.
				if severityRank[entry.Severity] <= severityRank[existing.Severity] {
					continue
				}
			}
			merged[hash] = ThreatMatch{
				Matched:    true,
				FeedName:   feed.Name,
				ThreatType: entry.ThreatType,
				ThreatName: entry.ThreatName,
				Severity:   entry.Severity,
				Reference:  entry.Reference,
				LastUpdate: feed.LastUpdate,
			}
		}
	}

	// Atomic swap via atomic.Value — in-flight CheckThreat calls see
	// either old or new map, never a partially-built one.
	e.mergedThreats.Store(merged)
}

// guessOS uses TTL and window size heuristics for OS fingerprinting.
func guessOS(ttl uint8, windowSize uint16, mss uint16) string {
	// Common initial TTL values:
	// Linux: 64, Windows: 128, macOS/iOS: 64, Solaris: 255
	// After routing, TTL decreases, so we look at ranges.

	switch {
	case ttl <= 64 && ttl > 32:
		// Linux or macOS family.
		switch {
		case windowSize == 65535:
			return "macOS"
		case windowSize == 29200 || windowSize == 5840:
			return "Linux"
		case windowSize == 14600:
			return "Linux"
		default:
			return "Linux/macOS"
		}
	case ttl <= 128 && ttl > 64:
		// Windows family.
		switch {
		case windowSize == 65535:
			return "Windows"
		case windowSize == 8192:
			return "Windows"
		default:
			return "Windows"
		}
	case ttl > 128:
		return "Solaris/AIX"
	default:
		return "Unknown"
	}
}

// defaultKnownDevices returns the built-in device fingerprint database.
func defaultKnownDevices() []KnownDevice {
	return []KnownDevice{
		// Common browser fingerprint prefixes.
		{Pattern: "t13d", Identity: DeviceIdentity{Name: "Modern Browser (TLS 1.3)", Category: "browser", OS: "Unknown", Confidence: 0.6}},
		{Pattern: "t12d", Identity: DeviceIdentity{Name: "Legacy Browser (TLS 1.2)", Category: "browser", OS: "Unknown", Confidence: 0.5}},
		{Pattern: "t13i", Identity: DeviceIdentity{Name: "TLS 1.3 Client (IP-based)", Category: "application", OS: "Unknown", Confidence: 0.4}},

		// IoT device patterns (typically older TLS, fewer cipher suites).
		{Pattern: "t12i02", Identity: DeviceIdentity{Name: "IoT Device (minimal TLS)", Category: "iot", OS: "Embedded", Confidence: 0.7}},
		{Pattern: "t10", Identity: DeviceIdentity{Name: "Legacy Device (TLS 1.0)", Category: "iot", OS: "Embedded", Confidence: 0.6}},
	}
}
