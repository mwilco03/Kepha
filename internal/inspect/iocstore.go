package inspect

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mwilco03/kepha/internal/validate"
)

// IOCType identifies the kind of indicator of compromise.
type IOCType string

const (
	IOCTypeIP              IOCType = "ip"
	IOCTypeCIDR            IOCType = "cidr"
	IOCTypeFingerprintHash IOCType = "fingerprint"
	IOCTypeJA4             IOCType = "ja4"
	IOCTypeJA4S            IOCType = "ja4s"
	IOCTypeJA4T            IOCType = "ja4t"
	IOCTypeJA4H            IOCType = "ja4h"
	IOCTypeDomain          IOCType = "domain"
	IOCTypeASN             IOCType = "asn" // Autonomous system number (e.g. "AS14618")
)

// IOCSource identifies where the indicator came from.
type IOCSource string

const (
	IOCSourceManual    IOCSource = "manual"     // Defender added via API/CLI
	IOCSourceThreatFeed IOCSource = "threat_feed" // Automated threat feed ingestion
	IOCSourceAnomaly   IOCSource = "anomaly"    // Anomaly detector triggered
	IOCSourceExternal  IOCSource = "external"   // External tool (Zeek, Suricata, Arkime)
	IOCSourceMCP       IOCSource = "mcp"        // MCP tool integration
)

// IOCSeverity controls response escalation.
type IOCSeverity string

const (
	IOCSeverityLow      IOCSeverity = "low"
	IOCSeverityMedium   IOCSeverity = "medium"
	IOCSeverityHigh     IOCSeverity = "high"
	IOCSeverityCritical IOCSeverity = "critical"
)

// IOC is an indicator of compromise with metadata.
type IOC struct {
	ID        int64       `json:"id"`
	Type      IOCType     `json:"type"`
	Value     string      `json:"value"`     // The indicator value (IP, hash, domain, CIDR)
	Source    IOCSource   `json:"source"`    // Where it came from
	Severity  IOCSeverity `json:"severity"`
	Reason    string      `json:"reason"`    // Human-readable context
	Reference string      `json:"reference"` // URL, feed name, ticket number
	Tags      []string    `json:"tags"`      // Freeform tags for grouping/filtering
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"` // Zero = permanent
	Active    bool        `json:"active"`
	HitCount  int64       `json:"hit_count"`  // Times this IOC was matched on the fast path (atomic)
	LastHit   time.Time   `json:"last_hit"`   // Last time this IOC was matched (best-effort under RLock)
}

// ResponseTemplate maps IOC type+severity to a countermeasure response.
// This is the bridge between "I found something bad" and "do something about it."
type ResponseTemplate struct {
	ID       int64       `json:"id"`
	Name     string      `json:"name"`
	IOCType  IOCType     `json:"ioc_type"`  // Which IOC types trigger this template
	MinSeverity IOCSeverity `json:"min_severity"` // Minimum severity to activate
	// Techniques lists countermeasure technique names to apply.
	// These map directly to TechniqueType values in the countermeasures engine.
	Techniques []string  `json:"techniques"`
	// Duration is how long the countermeasure stays active. Zero = use IOC expiry.
	Duration   time.Duration `json:"duration"`
	Enabled    bool          `json:"enabled"`
}

// IOCStore manages indicators of compromise with O(1) fast-path lookups
// and SQLite persistence for durability.
//
// Architecture:
//
//	Write path:  API/feed/anomaly → AddIOC() → SQLite + in-memory indices
//	Read path:   Packet arrives → Match() → O(1) map lookup → ResponseTemplate → enforce
//
// The in-memory indices are rebuilt from SQLite on startup and kept in sync
// on every write. The fast path never touches the database.
type IOCStore struct {
	mu sync.RWMutex
	db *sql.DB

	// In-memory indices for O(1) fast-path lookups.
	// Each index maps a specific value to the IOC for instant matching.
	byIP          map[string]*IOC // Exact IP lookups
	byFingerprint map[string]*IOC // JA4/JA4S/JA4T/JA4H hash lookups
	byDomain      map[string]*IOC // Domain lookups

	// CIDR entries need prefix matching — stored as a flat list.
	// For typical deployment sizes (hundreds, not millions), linear scan
	// is fine. If this becomes a bottleneck, replace with a radix tree.
	cidrs []*IOC

	// ASN index — maps ASN string (e.g. "AS14618") to IOC.
	byASN map[string]*IOC

	// ASN resolver maps IP → ASN for the MatchIP fast path.
	// When set, MatchIP also checks ASN IOCs after IP/CIDR checks.
	// Optional — nil means ASN matching is disabled.
	asnResolver ASNResolver

	// Response templates define what happens when an IOC matches.
	templates []ResponseTemplate
}

// NewIOCStore creates a new IOC store backed by SQLite.
func NewIOCStore(db *sql.DB) (*IOCStore, error) {
	s := &IOCStore{
		db:            db,
		byIP:          make(map[string]*IOC),
		byFingerprint: make(map[string]*IOC),
		byDomain:      make(map[string]*IOC),
		byASN:         make(map[string]*IOC),
	}

	if db != nil {
		if err := s.migrate(); err != nil {
			return nil, fmt.Errorf("ioc store migration: %w", err)
		}
		if err := s.loadAll(); err != nil {
			return nil, fmt.Errorf("ioc store load: %w", err)
		}
	}

	// Seed default response templates.
	s.seedTemplates()

	return s, nil
}

func (s *IOCStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS iocs (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			type       TEXT NOT NULL,
			value      TEXT NOT NULL,
			source     TEXT NOT NULL DEFAULT 'manual',
			severity   TEXT NOT NULL DEFAULT 'medium',
			reason     TEXT NOT NULL DEFAULT '',
			reference  TEXT NOT NULL DEFAULT '',
			tags       TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			active     INTEGER NOT NULL DEFAULT 1,
			hit_count  INTEGER NOT NULL DEFAULT 0,
			last_hit   DATETIME
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);
		CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active);
		CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
		CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);

		CREATE TABLE IF NOT EXISTS ioc_response_templates (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT NOT NULL UNIQUE,
			ioc_type     TEXT NOT NULL,
			min_severity TEXT NOT NULL DEFAULT 'medium',
			techniques   TEXT NOT NULL DEFAULT '',
			duration_sec INTEGER NOT NULL DEFAULT 0,
			enabled      INTEGER NOT NULL DEFAULT 1
		);
	`)
	return err
}

// seedTemplates creates default response templates if none exist.
func (s *IOCStore) seedTemplates() {
	s.templates = []ResponseTemplate{
		{
			ID:          1,
			Name:        "threat_block",
			IOCType:     IOCTypeIP,
			MinSeverity: IOCSeverityHigh,
			Techniques:  []string{"tarpit", "bandwidth", "syn_cookie", "ttl_randomize"},
			Duration:    24 * time.Hour,
			Enabled:     true,
		},
		{
			ID:          2,
			Name:        "anomaly_slow",
			IOCType:     IOCTypeIP,
			MinSeverity: IOCSeverityMedium,
			Techniques:  []string{"latency", "bandwidth"},
			Duration:    1 * time.Hour,
			Enabled:     true,
		},
		{
			ID:          3,
			Name:        "fingerprint_block",
			IOCType:     IOCTypeJA4,
			MinSeverity: IOCSeverityHigh,
			Techniques:  []string{"tarpit", "bandwidth"},
			Duration:    24 * time.Hour,
			Enabled:     true,
		},
		{
			ID:          4,
			Name:        "asn_block",
			IOCType:     IOCTypeASN,
			MinSeverity: IOCSeverityMedium,
			Techniques:  []string{"bandwidth", "syn_cookie"},
			Duration:    24 * time.Hour,
			Enabled:     true,
		},
		{
			ID:          5,
			Name:        "critical_full",
			IOCType:     IOCTypeIP,
			MinSeverity: IOCSeverityCritical,
			Techniques:  []string{"tarpit", "bandwidth", "syn_cookie", "rst_chaos", "ttl_randomize"},
			Duration:    48 * time.Hour,
			Enabled:     true,
		},
	}
}

// SetASNResolver configures the IP-to-ASN resolver for ASN-based IOC matching.
// When set, MatchIP will also check if the source IP's ASN matches any ASN IOC.
func (s *IOCStore) SetASNResolver(resolver ASNResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asnResolver = resolver
}

// --- Write path ---

// AddIOC adds or updates an indicator of compromise.
// The IOC is persisted to SQLite and indexed in memory for fast-path lookups.
func (s *IOCStore) AddIOC(ioc IOC) (*IOC, error) {
	if ioc.Value == "" {
		return nil, fmt.Errorf("ioc value is required")
	}
	if ioc.Type == "" {
		return nil, fmt.Errorf("ioc type is required")
	}

	if ioc.CreatedAt.IsZero() {
		ioc.CreatedAt = time.Now()
	}
	ioc.Active = true

	if ioc.Source == "" {
		ioc.Source = IOCSourceManual
	}
	if ioc.Severity == "" {
		ioc.Severity = IOCSeverityMedium
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Persist to SQLite.
	if s.db != nil {
		tagsStr := joinTags(ioc.Tags)
		var expiresAt *time.Time
		if !ioc.ExpiresAt.IsZero() {
			expiresAt = &ioc.ExpiresAt
		}
		result, err := s.db.Exec(`
			INSERT INTO iocs (type, value, source, severity, reason, reference, tags, created_at, expires_at, active)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
			ON CONFLICT(type, value) DO UPDATE SET
				severity = excluded.severity,
				reason = excluded.reason,
				reference = excluded.reference,
				tags = excluded.tags,
				expires_at = excluded.expires_at,
				active = 1
		`, ioc.Type, ioc.Value, ioc.Source, ioc.Severity, ioc.Reason,
			ioc.Reference, tagsStr, ioc.CreatedAt, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("persist ioc: %w", err)
		}
		ioc.ID, _ = result.LastInsertId()
	}

	// Index in memory.
	s.index(&ioc)

	slog.Info("ioc added",
		"type", ioc.Type,
		"value", ioc.Value,
		"source", ioc.Source,
		"severity", ioc.Severity,
	)

	return &ioc, nil
}

// RemoveIOC deactivates an IOC by type and value.
func (s *IOCStore) RemoveIOC(iocType IOCType, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if IOC exists in memory.
	if !s.existsLocked(iocType, value) {
		return fmt.Errorf("ioc not found: %s/%s", iocType, value)
	}

	if s.db != nil {
		if _, err := s.db.Exec(`UPDATE iocs SET active = 0 WHERE type = ? AND value = ?`, iocType, value); err != nil {
			return fmt.Errorf("deactivate ioc: %w", err)
		}
	}

	s.deindex(iocType, value)

	slog.Info("ioc removed", "type", iocType, "value", value)
	return nil
}

// existsLocked checks if an IOC exists in memory. Must hold s.mu.
func (s *IOCStore) existsLocked(iocType IOCType, value string) bool {
	switch iocType {
	case IOCTypeIP:
		_, ok := s.byIP[value]
		return ok
	case IOCTypeCIDR:
		for _, ioc := range s.cidrs {
			if ioc.Value == value {
				return true
			}
		}
		return false
	case IOCTypeDomain:
		_, ok := s.byDomain[value]
		return ok
	case IOCTypeASN:
		_, ok := s.byASN[value]
		return ok
	default:
		_, ok := s.byFingerprint[value]
		return ok
	}
}

// maxBulkIOCs caps the number of IOCs that can be added in a single bulk operation
// to prevent memory exhaustion.
const maxBulkIOCs = 100000

// BulkAddIOCs adds multiple IOCs in a single transaction.
// Used by threat feed ingestion and external tool imports.
// Capped at maxBulkIOCs entries per call.
func (s *IOCStore) BulkAddIOCs(iocs []IOC) (added int, err error) {
	if len(iocs) > maxBulkIOCs {
		return 0, fmt.Errorf("bulk add limit exceeded: %d entries (max %d)", len(iocs), maxBulkIOCs)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var tx *sql.Tx
	if s.db != nil {
		tx, err = s.db.Begin()
		if err != nil {
			return 0, fmt.Errorf("begin tx: %w", err)
		}
		defer func() {
			if err != nil {
				tx.Rollback()
			}
		}()
	}

	now := time.Now()
	for i := range iocs {
		ioc := &iocs[i]
		if ioc.Value == "" || ioc.Type == "" {
			continue
		}
		if ioc.CreatedAt.IsZero() {
			ioc.CreatedAt = now
		}
		ioc.Active = true
		if ioc.Source == "" {
			ioc.Source = IOCSourceThreatFeed
		}
		if ioc.Severity == "" {
			ioc.Severity = IOCSeverityMedium
		}

		if tx != nil {
			tagsStr := joinTags(ioc.Tags)
			var expiresAt *time.Time
			if !ioc.ExpiresAt.IsZero() {
				expiresAt = &ioc.ExpiresAt
			}
			_, err = tx.Exec(`
				INSERT INTO iocs (type, value, source, severity, reason, reference, tags, created_at, expires_at, active)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
				ON CONFLICT(type, value) DO UPDATE SET
					severity = excluded.severity,
					reason = excluded.reason,
					active = 1
			`, ioc.Type, ioc.Value, ioc.Source, ioc.Severity, ioc.Reason,
				ioc.Reference, tagsStr, ioc.CreatedAt, expiresAt)
			if err != nil {
				return added, fmt.Errorf("insert ioc %q: %w", ioc.Value, err)
			}
		}

		added++
	}

	// L18: Commit BEFORE indexing — if commit fails, in-memory index
	// stays consistent with the database.
	if tx != nil {
		if err = tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit: %w", err)
		}
	}

	// Index in memory only after successful commit.
	for i := range iocs[:added] {
		s.index(&iocs[i])
	}

	slog.Info("bulk iocs added", "count", added)
	return added, nil
}

// --- Fast-path read ---

// MatchIP checks if an IP matches any active IOC.
// Check order: exact IP (O(1)) → CIDR (linear) → ASN (O(1) after resolver lookup).
func (s *IOCStore) MatchIP(ip string) *IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()

	// 1. Exact IP match — O(1).
	if ioc := s.byIP[ip]; ioc != nil && s.isActive(ioc) {
		atomic.AddInt64(&ioc.HitCount, 1)
		ioc.LastHit = now // Best-effort under RLock; acceptable approximation.
		return ioc
	}

	// 2. CIDR scan.
	for _, ioc := range s.cidrs {
		if s.isActive(ioc) && matchCIDRNet(ip, ioc.Value) {
			atomic.AddInt64(&ioc.HitCount, 1)
			ioc.LastHit = now
			return ioc
		}
	}

	// 3. ASN match — resolve IP to ASN, then O(1) map lookup.
	if s.asnResolver != nil && len(s.byASN) > 0 {
		parsed := net.ParseIP(ip)
		if parsed != nil {
			if asn := s.asnResolver.Resolve(parsed); asn != nil {
				asnKey := asn.String() // "AS14618"
				if ioc := s.byASN[asnKey]; ioc != nil && s.isActive(ioc) {
					atomic.AddInt64(&ioc.HitCount, 1)
					ioc.LastHit = now
					return ioc
				}
			}
		}
	}

	return nil
}

// MatchFingerprint checks if a fingerprint hash matches any active IOC.
// O(1) map lookup.
func (s *IOCStore) MatchFingerprint(hash string) *IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if ioc := s.byFingerprint[hash]; ioc != nil && s.isActive(ioc) {
		atomic.AddInt64(&ioc.HitCount, 1)
		ioc.LastHit = time.Now()
		return ioc
	}
	return nil
}

// MatchDomain checks if a domain matches any active IOC.
// O(1) map lookup.
func (s *IOCStore) MatchDomain(domain string) *IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if ioc := s.byDomain[domain]; ioc != nil && s.isActive(ioc) {
		atomic.AddInt64(&ioc.HitCount, 1)
		ioc.LastHit = time.Now()
		return ioc
	}
	return nil
}

// --- Query path ---

// ListIOCs returns IOCs matching the given filters.
func (s *IOCStore) ListIOCs(iocType IOCType, source IOCSource, activeOnly bool, limit int) ([]IOC, error) {
	if s.db == nil {
		return s.listFromMemory(iocType, source, activeOnly, limit), nil
	}

	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, type, value, source, severity, reason, reference, tags,
	                 created_at, expires_at, active, hit_count, last_hit
	          FROM iocs WHERE 1=1`
	var args []any

	if iocType != "" {
		query += " AND type = ?"
		args = append(args, string(iocType))
	}
	if source != "" {
		query += " AND source = ?"
		args = append(args, string(source))
	}
	if activeOnly {
		query += " AND active = 1"
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanIOCRows(rows)
}

// GetIOC returns a specific IOC by type and value.
func (s *IOCStore) GetIOC(iocType IOCType, value string) *IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch iocType {
	case IOCTypeIP:
		return s.byIP[value]
	case IOCTypeCIDR:
		for _, ioc := range s.cidrs {
			if ioc.Value == value {
				return ioc
			}
		}
	case IOCTypeDomain:
		return s.byDomain[value]
	case IOCTypeASN:
		return s.byASN[value]
	default:
		return s.byFingerprint[value]
	}
	return nil
}

// MatchResponse finds the best response template for a matched IOC.
// Returns nil if no template matches.
func (s *IOCStore) MatchResponse(ioc *IOC) *ResponseTemplate {
	if ioc == nil {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	sevRank := severityRank(ioc.Severity)
	var best *ResponseTemplate
	bestExact := false // Track whether best is an exact type match.

	for i := range s.templates {
		t := &s.templates[i]
		if !t.Enabled {
			continue
		}

		// Type matching: exact match first, then broadened matches.
		exact := t.IOCType == ioc.Type
		broad := false
		if !exact {
			// IP templates also cover CIDR and ASN (network-level types).
			if t.IOCType == IOCTypeIP && (ioc.Type == IOCTypeCIDR || ioc.Type == IOCTypeASN) {
				broad = true
			}
			// Fingerprint templates cover all ja4* subtypes.
			if t.IOCType == IOCTypeFingerprintHash {
				switch ioc.Type {
				case IOCTypeJA4, IOCTypeJA4S, IOCTypeJA4T, IOCTypeJA4H:
					broad = true
				}
			}
		}
		if !exact && !broad {
			continue
		}

		// Severity gate: IOC severity must meet template minimum.
		if sevRank < severityRank(t.MinSeverity) {
			continue
		}

		// Selection priority: exact type match > broad match > higher min severity.
		if best == nil {
			best = t
			bestExact = exact
		} else if exact && !bestExact {
			// Exact match always beats broad match.
			best = t
			bestExact = true
		} else if exact == bestExact && severityRank(t.MinSeverity) > severityRank(best.MinSeverity) {
			// Same match class — prefer higher minimum severity (more specific).
			best = t
			bestExact = exact
		}
	}

	return best
}

// Templates returns the current response templates.
func (s *IOCStore) Templates() []ResponseTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]ResponseTemplate, len(s.templates))
	copy(result, s.templates)
	return result
}

// AddTemplate adds a custom response template.
func (s *IOCStore) AddTemplate(t ResponseTemplate) error {
	if t.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if len(t.Techniques) == 0 {
		return fmt.Errorf("at least one technique is required")
	}
	t.Enabled = true

	s.mu.Lock()
	defer s.mu.Unlock()

	// Replace if name already exists.
	for i, existing := range s.templates {
		if existing.Name == t.Name {
			t.ID = existing.ID
			s.templates[i] = t
			return nil
		}
	}

	t.ID = int64(len(s.templates) + 1)
	s.templates = append(s.templates, t)
	return nil
}

// RemoveTemplate removes a response template by name.
func (s *IOCStore) RemoveTemplate(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, t := range s.templates {
		if t.Name == name {
			s.templates = append(s.templates[:i], s.templates[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("template %q not found", name)
}

// Stats returns IOC store statistics.
func (s *IOCStore) Stats() IOCStoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return IOCStoreStats{
		TotalIPs:          len(s.byIP),
		TotalCIDRs:        len(s.cidrs),
		TotalFingerprints: len(s.byFingerprint),
		TotalDomains:      len(s.byDomain),
		TotalASNs:         len(s.byASN),
		ASNResolverActive: s.asnResolver != nil,
		Templates:         len(s.templates),
	}
}

// IOCStoreStats contains store statistics.
type IOCStoreStats struct {
	TotalIPs          int  `json:"total_ips"`
	TotalCIDRs        int  `json:"total_cidrs"`
	TotalFingerprints int  `json:"total_fingerprints"`
	TotalDomains      int  `json:"total_domains"`
	TotalASNs         int  `json:"total_asns"`
	ASNResolverActive bool `json:"asn_resolver_active"`
	Templates         int  `json:"templates"`
}

// --- Internal helpers ---

func (s *IOCStore) index(ioc *IOC) {
	switch ioc.Type {
	case IOCTypeIP:
		s.byIP[ioc.Value] = ioc
	case IOCTypeCIDR:
		// Replace existing or append.
		for i, existing := range s.cidrs {
			if existing.Value == ioc.Value {
				s.cidrs[i] = ioc
				return
			}
		}
		s.cidrs = append(s.cidrs, ioc)
	case IOCTypeDomain:
		s.byDomain[ioc.Value] = ioc
	case IOCTypeASN:
		s.byASN[ioc.Value] = ioc
	case IOCTypeJA4, IOCTypeJA4S, IOCTypeJA4T, IOCTypeJA4H, IOCTypeFingerprintHash:
		s.byFingerprint[ioc.Value] = ioc
	}
}

func (s *IOCStore) deindex(iocType IOCType, value string) {
	switch iocType {
	case IOCTypeIP:
		delete(s.byIP, value)
	case IOCTypeCIDR:
		for i, ioc := range s.cidrs {
			if ioc.Value == value {
				s.cidrs = append(s.cidrs[:i], s.cidrs[i+1:]...)
				return
			}
		}
	case IOCTypeDomain:
		delete(s.byDomain, value)
	case IOCTypeASN:
		delete(s.byASN, value)
	default:
		delete(s.byFingerprint, value)
	}
}

func (s *IOCStore) isActive(ioc *IOC) bool {
	if !ioc.Active {
		return false
	}
	if !ioc.ExpiresAt.IsZero() && time.Now().After(ioc.ExpiresAt) {
		return false
	}
	return true
}

func (s *IOCStore) loadAll() error {
	rows, err := s.db.Query(`
		SELECT id, type, value, source, severity, reason, reference, tags,
		       created_at, expires_at, active, hit_count, last_hit
		FROM iocs WHERE active = 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	iocs, err := scanIOCRows(rows)
	if err != nil {
		return err
	}

	for i := range iocs {
		s.index(&iocs[i])
	}

	slog.Info("ioc store loaded",
		"ips", len(s.byIP),
		"cidrs", len(s.cidrs),
		"fingerprints", len(s.byFingerprint),
		"domains", len(s.byDomain),
	)
	return nil
}

func (s *IOCStore) listFromMemory(iocType IOCType, source IOCSource, activeOnly bool, limit int) []IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []*IOC
	for _, ioc := range s.byIP {
		all = append(all, ioc)
	}
	for _, ioc := range s.cidrs {
		all = append(all, ioc)
	}
	for _, ioc := range s.byFingerprint {
		all = append(all, ioc)
	}
	for _, ioc := range s.byDomain {
		all = append(all, ioc)
	}
	for _, ioc := range s.byASN {
		all = append(all, ioc)
	}

	var result []IOC
	for _, ioc := range all {
		if iocType != "" && ioc.Type != iocType {
			continue
		}
		if source != "" && ioc.Source != source {
			continue
		}
		if activeOnly && !s.isActive(ioc) {
			continue
		}
		result = append(result, *ioc)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func scanIOCRows(rows *sql.Rows) ([]IOC, error) {
	var result []IOC
	for rows.Next() {
		var ioc IOC
		var tagsStr string
		var active int
		var expiresAt sql.NullTime
		var lastHit sql.NullTime
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Source,
			&ioc.Severity, &ioc.Reason, &ioc.Reference, &tagsStr,
			&ioc.CreatedAt, &expiresAt, &active, &ioc.HitCount, &lastHit); err != nil {
			return nil, err
		}
		ioc.Active = active != 0
		if expiresAt.Valid {
			ioc.ExpiresAt = expiresAt.Time
		}
		if lastHit.Valid {
			ioc.LastHit = lastHit.Time
		}
		ioc.Tags = splitTags(tagsStr)
		result = append(result, ioc)
	}
	return result, rows.Err()
}

func severityRank(s IOCSeverity) int {
	switch s {
	case IOCSeverityCritical:
		return 4
	case IOCSeverityHigh:
		return 3
	case IOCSeverityMedium:
		return 2
	case IOCSeverityLow:
		return 1
	default:
		return 0
	}
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	result := ""
	for i, t := range tags {
		if i > 0 {
			result += ","
		}
		result += t
	}
	return result
}

func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	var tags []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if i > start {
				tags = append(tags, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		tags = append(tags, s[start:])
	}
	return tags
}

// matchCIDRNet delegates to the shared validate.MatchCIDR implementation.
func matchCIDRNet(ip, cidr string) bool {
	return validate.MatchCIDR(ip, cidr)
}
