package inspect

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
)

// ASNResult holds the resolved ASN information for an IP address.
type ASNResult struct {
	Number uint32 `json:"number"` // e.g. 14618
	Org    string `json:"org"`    // e.g. "AMAZON-AES"
}

// String returns the ASN in standard notation (e.g. "AS14618").
func (a ASNResult) String() string {
	return fmt.Sprintf("AS%d", a.Number)
}

// ASNResolver maps IP addresses to autonomous system numbers.
// Implementations may use MaxMind mmdb, Team Cymru, or any other data source.
type ASNResolver interface {
	// Resolve returns the ASN for an IP address.
	// Returns nil if the IP cannot be resolved (private, unknown, etc.).
	Resolve(ip net.IP) *ASNResult
	// Close releases any resources held by the resolver.
	Close() error
}

// MaxMindASNResolver uses a GeoLite2-ASN mmdb file for IP-to-ASN lookups.
//
// The mmdb file format gives O(1) lookups via a binary trie — each lookup
// is a few hundred nanoseconds regardless of database size. The file is
// memory-mapped, so it doesn't consume heap.
//
// Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
// File: GeoLite2-ASN.mmdb (~7MB)
type MaxMindASNResolver struct {
	mu   sync.RWMutex
	data []byte // Raw mmdb file data

	// Parsed metadata for the mmdb binary search tree.
	nodeCount  uint32
	recordSize uint32
	nodeBytes  int // nodeCount * (recordSize / 4)
	treeSize   int
	dataStart  int
}

// NewMaxMindASNResolver opens a GeoLite2-ASN mmdb file.
// Returns nil (not an error) if the file doesn't exist — ASN resolution
// is optional and gracefully degrades.
func NewMaxMindASNResolver(path string) (*MaxMindASNResolver, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("mmdb file not found, ASN resolution disabled", "path", path)
			return nil, nil
		}
		return nil, fmt.Errorf("read mmdb: %w", err)
	}

	r := &MaxMindASNResolver{data: data}
	if err := r.parseMetadata(); err != nil {
		return nil, fmt.Errorf("parse mmdb metadata: %w", err)
	}

	slog.Info("maxmind ASN resolver loaded", "path", path, "size", len(data))
	return r, nil
}

// Resolve returns the ASN for an IP address using the mmdb binary search tree.
func (r *MaxMindASNResolver) Resolve(ip net.IP) *ASNResult {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Normalize to 16-byte representation.
	ip = ip.To16()
	if ip == nil {
		return nil
	}

	// Walk the binary search tree.
	node := uint32(0)
	for i := 0; i < 128; i++ {
		if node >= r.nodeCount {
			break
		}

		byteIdx := i / 8
		bitIdx := uint(7 - (i % 8))
		bit := (ip[byteIdx] >> bitIdx) & 1

		var next uint32
		if bit == 0 {
			next = r.readNode(node, 0)
		} else {
			next = r.readNode(node, 1)
		}

		if next == r.nodeCount {
			// Empty record — no data for this IP.
			return nil
		}
		if next > r.nodeCount {
			// Data record — resolve the pointer.
			return r.readASNData(next)
		}
		node = next
	}

	return nil
}

// Close releases resources.
func (r *MaxMindASNResolver) Close() error {
	return nil
}

// readNode reads a record from node at position (0=left, 1=right).
func (r *MaxMindASNResolver) readNode(node uint32, pos int) uint32 {
	switch r.recordSize {
	case 24:
		offset := int(node) * 6
		if offset+6 > len(r.data) {
			return r.nodeCount
		}
		if pos == 0 {
			return uint32(r.data[offset])<<16 | uint32(r.data[offset+1])<<8 | uint32(r.data[offset+2])
		}
		return uint32(r.data[offset+3])<<16 | uint32(r.data[offset+4])<<8 | uint32(r.data[offset+5])
	case 28:
		offset := int(node) * 7
		if offset+7 > len(r.data) {
			return r.nodeCount
		}
		if pos == 0 {
			return (uint32(r.data[offset+3])>>4)<<24 | uint32(r.data[offset])<<16 | uint32(r.data[offset+1])<<8 | uint32(r.data[offset+2])
		}
		return (uint32(r.data[offset+3])&0x0f)<<24 | uint32(r.data[offset+4])<<16 | uint32(r.data[offset+5])<<8 | uint32(r.data[offset+6])
	case 32:
		offset := int(node) * 8
		if offset+8 > len(r.data) {
			return r.nodeCount
		}
		if pos == 0 {
			return uint32(r.data[offset])<<24 | uint32(r.data[offset+1])<<16 | uint32(r.data[offset+2])<<8 | uint32(r.data[offset+3])
		}
		return uint32(r.data[offset+4])<<24 | uint32(r.data[offset+5])<<16 | uint32(r.data[offset+6])<<8 | uint32(r.data[offset+7])
	}
	return r.nodeCount
}

// readASNData reads the ASN number and org from the data section.
func (r *MaxMindASNResolver) readASNData(ptr uint32) *ASNResult {
	offset := int(ptr-r.nodeCount) - 16 + r.dataStart
	if offset < 0 || offset >= len(r.data) {
		return nil
	}

	// The data section uses MaxMind's binary format.
	// For ASN databases, each record is a map with:
	//   "autonomous_system_number" -> uint32
	//   "autonomous_system_organization" -> string
	result := &ASNResult{}
	pos := offset

	// Read the map control byte.
	if pos >= len(r.data) {
		return nil
	}
	ctrl := r.data[pos]
	pos++

	typeNum := ctrl >> 5
	size := int(ctrl & 0x1f)

	if typeNum != 7 { // 7 = map
		return nil
	}

	// Extended size.
	if size >= 29 {
		switch size {
		case 29:
			if pos >= len(r.data) {
				return nil
			}
			size = 29 + int(r.data[pos])
			pos++
		case 30:
			if pos+1 >= len(r.data) {
				return nil
			}
			size = 285 + int(r.data[pos])<<8 + int(r.data[pos+1])
			pos += 2
		}
	}

	// Read map entries.
	for i := 0; i < size && pos < len(r.data); i++ {
		// Read key (should be utf8 string).
		key, newPos := r.readString(pos)
		if newPos <= pos {
			break
		}
		pos = newPos

		// Read value.
		switch key {
		case "autonomous_system_number":
			val, newPos := r.readUint(pos)
			if newPos <= pos {
				break
			}
			result.Number = val
			pos = newPos
		case "autonomous_system_organization":
			val, newPos := r.readString(pos)
			if newPos <= pos {
				break
			}
			result.Org = val
			pos = newPos
		default:
			// Skip unknown value.
			pos = r.skipValue(pos)
		}
	}

	if result.Number == 0 {
		return nil
	}
	return result
}

// readString reads a utf8 string from the data section.
func (r *MaxMindASNResolver) readString(pos int) (string, int) {
	if pos >= len(r.data) {
		return "", pos
	}
	ctrl := r.data[pos]
	pos++

	typeNum := ctrl >> 5
	size := int(ctrl & 0x1f)

	// Handle extended types.
	if typeNum == 0 {
		if pos >= len(r.data) {
			return "", pos
		}
		pos++ // skip extended type byte
		typeNum = 2 // utf8_string
	}

	if typeNum != 2 { // 2 = utf8_string
		return "", pos - 1
	}

	// Handle extended sizes.
	if size >= 29 {
		switch size {
		case 29:
			if pos >= len(r.data) {
				return "", pos
			}
			size = 29 + int(r.data[pos])
			pos++
		case 30:
			if pos+1 >= len(r.data) {
				return "", pos
			}
			size = 285 + int(r.data[pos])<<8 + int(r.data[pos+1])
			pos += 2
		case 31:
			if pos+2 >= len(r.data) {
				return "", pos
			}
			size = 65821 + int(r.data[pos])<<16 + int(r.data[pos+1])<<8 + int(r.data[pos+2])
			pos += 3
		}
	}

	end := pos + size
	if end > len(r.data) {
		return "", pos
	}
	return string(r.data[pos:end]), end
}

// readUint reads a uint32 from the data section.
func (r *MaxMindASNResolver) readUint(pos int) (uint32, int) {
	if pos >= len(r.data) {
		return 0, pos
	}
	ctrl := r.data[pos]
	pos++

	typeNum := ctrl >> 5
	size := int(ctrl & 0x1f)

	// Handle extended types for uint types.
	if typeNum == 0 {
		if pos >= len(r.data) {
			return 0, pos
		}
		extType := r.data[pos]
		pos++
		typeNum = extType + 7
	}

	// uint16=5, uint32=6, uint64=9, uint128=10
	if typeNum != 5 && typeNum != 6 {
		return 0, pos - 1
	}

	if size > 4 || pos+size > len(r.data) {
		return 0, pos
	}

	var val uint32
	for i := 0; i < size; i++ {
		val = val<<8 | uint32(r.data[pos+i])
	}
	return val, pos + size
}

// skipValue skips over a value in the data section.
func (r *MaxMindASNResolver) skipValue(pos int) int {
	if pos >= len(r.data) {
		return pos
	}
	ctrl := r.data[pos]
	pos++

	typeNum := ctrl >> 5
	size := int(ctrl & 0x1f)

	if typeNum == 0 {
		if pos >= len(r.data) {
			return pos
		}
		pos++ // skip extended type byte
	}

	if size >= 29 {
		switch size {
		case 29:
			if pos >= len(r.data) {
				return pos
			}
			size = 29 + int(r.data[pos])
			pos++
		case 30:
			if pos+1 >= len(r.data) {
				return pos
			}
			size = 285 + int(r.data[pos])<<8 + int(r.data[pos+1])
			pos += 2
		case 31:
			if pos+2 >= len(r.data) {
				return pos
			}
			size = 65821 + int(r.data[pos])<<16 + int(r.data[pos+1])<<8 + int(r.data[pos+2])
			pos += 3
		}
	}

	return pos + size
}

// parseMetadata reads the mmdb metadata from the end of the file.
func (r *MaxMindASNResolver) parseMetadata() error {
	// The metadata marker is "\xab\xcd\xefMaxMind.com" at the end of the file.
	marker := []byte("\xab\xcd\xefMaxMind.com")
	idx := -1
	for i := len(r.data) - len(marker); i >= 0; i-- {
		match := true
		for j := 0; j < len(marker); j++ {
			if r.data[i+j] != marker[j] {
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("mmdb metadata marker not found")
	}

	// Parse metadata map starting after the marker.
	pos := idx + len(marker)

	if pos >= len(r.data) {
		return fmt.Errorf("mmdb metadata truncated")
	}

	// Read the map.
	ctrl := r.data[pos]
	pos++
	typeNum := ctrl >> 5
	size := int(ctrl & 0x1f)

	if typeNum != 7 { // map
		return fmt.Errorf("mmdb metadata is not a map (type=%d)", typeNum)
	}

	if size >= 29 {
		switch size {
		case 29:
			if pos >= len(r.data) {
				return fmt.Errorf("truncated")
			}
			size = 29 + int(r.data[pos])
			pos++
		case 30:
			if pos+1 >= len(r.data) {
				return fmt.Errorf("truncated")
			}
			size = 285 + int(r.data[pos])<<8 + int(r.data[pos+1])
			pos += 2
		}
	}

	for i := 0; i < size && pos < len(r.data); i++ {
		key, newPos := r.readString(pos)
		if newPos <= pos {
			break
		}
		pos = newPos

		switch key {
		case "node_count":
			val, newPos := r.readUint(pos)
			pos = newPos
			r.nodeCount = val
		case "record_size":
			val, newPos := r.readUint(pos)
			pos = newPos
			r.recordSize = val
		default:
			pos = r.skipValue(pos)
		}
	}

	if r.nodeCount == 0 || r.recordSize == 0 {
		return fmt.Errorf("mmdb metadata missing node_count or record_size")
	}

	r.nodeBytes = int(r.nodeCount) * int(r.recordSize) / 4
	r.treeSize = r.nodeBytes
	r.dataStart = r.treeSize + 16 // 16-byte null separator

	return nil
}

// StaticASNResolver is a simple in-memory resolver for testing and small deployments.
// Maps are populated manually via AddMapping.
type StaticASNResolver struct {
	mu       sync.RWMutex
	mappings map[string]ASNResult // IP string -> ASN
}

// NewStaticASNResolver creates a resolver with no mappings.
func NewStaticASNResolver() *StaticASNResolver {
	return &StaticASNResolver{
		mappings: make(map[string]ASNResult),
	}
}

// AddMapping adds an IP-to-ASN mapping.
func (r *StaticASNResolver) AddMapping(ip string, asn uint32, org string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mappings[ip] = ASNResult{Number: asn, Org: org}
}

// Resolve returns the ASN for an IP from the static map.
func (r *StaticASNResolver) Resolve(ip net.IP) *ASNResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result, ok := r.mappings[ip.String()]
	if !ok {
		return nil
	}
	return &result
}

// Close is a no-op for static resolver.
func (r *StaticASNResolver) Close() error { return nil }
