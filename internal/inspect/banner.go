package inspect

import (
	"fmt"
	"strings"
	"time"
)

// BannerType identifies the protocol a banner was captured from.
type BannerType string

const (
	BannerTypeSSH  BannerType = "ssh"
	BannerTypeHTTP BannerType = "http"
	BannerTypeSMTP BannerType = "smtp"
)

// Banner is a captured server banner from passive traffic observation.
type Banner struct {
	Type      BannerType `json:"type"`       // Protocol type
	Value     string     `json:"value"`      // Full banner string
	Software  string     `json:"software"`   // Extracted software name/version
	SrcIP     string     `json:"src_ip"`     // Server IP that sent the banner
	DstIP     string     `json:"dst_ip"`     // Client IP that received it
	Port      uint16     `json:"port"`       // Server port
	Timestamp time.Time  `json:"timestamp"`
}

// BannerFingerprint is a stored banner observation.
type BannerFingerprint struct {
	Hash      string     `json:"hash"`       // Truncated SHA256 of normalized banner
	Type      BannerType `json:"type"`       // Protocol type
	Banner    string     `json:"banner"`     // Full banner value
	Software  string     `json:"software"`   // Extracted software identifier
	SrcIP     string     `json:"src_ip"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Count     int64      `json:"count"`
}

// FingerprintBanner creates a fingerprint from a captured server banner.
func (e *Engine) FingerprintBanner(banner *Banner) (*BannerFingerprint, error) {
	if banner == nil {
		return nil, fmt.Errorf("nil Banner")
	}
	if banner.Value == "" {
		return nil, fmt.Errorf("empty banner")
	}

	// Normalize: trim whitespace, lowercase for hashing.
	normalized := strings.TrimSpace(strings.ToLower(banner.Value))
	hash := truncHash(fmt.Sprintf("%s:%s", banner.Type, normalized))

	now := time.Now()
	fp := &BannerFingerprint{
		Hash:      hash,
		Type:      banner.Type,
		Banner:    banner.Value,
		Software:  banner.Software,
		SrcIP:     banner.SrcIP,
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "banner_" + string(banner.Type),
			Hash:      hash,
			SrcIP:     banner.SrcIP,
			DstIP:     banner.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseHTTPServerBanner extracts the Server header from an HTTP response.
// Looks for "Server:" header in raw HTTP response data.
func ParseHTTPServerBanner(data []byte) *Banner {
	// HTTP response starts with "HTTP/".
	if len(data) < 12 || string(data[:5]) != "HTTP/" {
		return nil
	}

	// Find the end of the status line.
	s := string(data)
	headers := s

	// Search for Server header (case-insensitive scan).
	lower := strings.ToLower(headers)
	idx := strings.Index(lower, "\nserver:")
	if idx < 0 {
		idx = strings.Index(lower, "\r\nserver:")
		if idx >= 0 {
			idx++ // skip past \r
		}
	}
	if idx < 0 {
		return nil
	}

	// Extract the header value.
	start := idx + 1 // skip \n
	colon := strings.IndexByte(headers[start:], ':')
	if colon < 0 {
		return nil
	}
	valueStart := start + colon + 1
	lineEnd := strings.IndexAny(headers[valueStart:], "\r\n")
	if lineEnd < 0 {
		lineEnd = len(headers) - valueStart
	}

	value := strings.TrimSpace(headers[valueStart : valueStart+lineEnd])
	if value == "" {
		return nil
	}

	return &Banner{
		Type:     BannerTypeHTTP,
		Value:    value,
		Software: extractHTTPSoftware(value),
	}
}

// ParseSMTPBanner extracts the SMTP greeting banner from a connection.
// SMTP servers send "220 hostname ESMTP software\r\n" as the greeting.
func ParseSMTPBanner(data []byte) *Banner {
	if len(data) < 4 {
		return nil
	}

	// SMTP greeting starts with "220".
	if string(data[:3]) != "220" {
		return nil
	}

	// Find end of line.
	s := string(data)
	lineEnd := strings.IndexAny(s, "\r\n")
	if lineEnd < 0 {
		lineEnd = len(s)
	}
	if lineEnd > 512 {
		lineEnd = 512
	}

	banner := strings.TrimSpace(s[:lineEnd])

	return &Banner{
		Type:     BannerTypeSMTP,
		Value:    banner,
		Software: extractSMTPSoftware(banner),
	}
}

// extractHTTPSoftware attempts to extract software name from Server header.
// Example: "nginx/1.24.0" → "nginx/1.24.0"
// Example: "Apache/2.4.52 (Ubuntu)" → "Apache/2.4.52"
func extractHTTPSoftware(server string) string {
	// Take the first token (space-separated).
	parts := strings.Fields(server)
	if len(parts) == 0 {
		return server
	}
	return parts[0]
}

// extractSMTPSoftware extracts software from SMTP 220 banner.
// Example: "220 mail.example.com ESMTP Postfix" → "Postfix"
// Example: "220 mx.google.com ESMTP" → "ESMTP"
func extractSMTPSoftware(banner string) string {
	// Strip the "220 " prefix.
	if len(banner) > 4 {
		rest := banner[4:]
		parts := strings.Fields(rest)
		// The software is typically the last word(s) after "ESMTP" or "SMTP".
		for i, p := range parts {
			if strings.EqualFold(p, "ESMTP") || strings.EqualFold(p, "SMTP") {
				if i+1 < len(parts) {
					return strings.Join(parts[i+1:], " ")
				}
				return p
			}
		}
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}
	return banner
}
