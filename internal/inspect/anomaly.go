package inspect

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// AnomalyDetector watches for fingerprint changes on known devices.
//
// When a device that has been fingerprinted before suddenly presents a
// different TLS fingerprint, this could indicate:
//   - Software update (benign)
//   - MitM proxy insertion (suspicious)
//   - Device compromise / malware (critical)
//   - VPN or proxy added/removed (informational)
//
// The detector tracks per-IP fingerprint history and raises alerts when
// the fingerprint changes. Exclusion lists allow whitelisting known-good
// changes (e.g., after a planned browser update).
//
// # Exclusion Lists
//
// Exclusion requests can be:
//   - Per-IP: "192.168.1.100" — never alert on changes from this IP
//   - Per-hash: "t13d1516h2_*" — never alert on transitions to this fingerprint
//   - Per-pair: "old_hash → new_hash" — allow this specific transition
//   - Time-bounded: "exclude 192.168.1.0/24 for 24h" (maintenance window)
//   - Permanent: "exclude 10.0.0.0/8" (trusted internal segment)
//
// Exclusions are stored in SQLite alongside fingerprints so they survive
// restarts and can be managed via API/CLI.
type AnomalyDetector struct {
	mu         sync.RWMutex
	db         *sql.DB
	exclusions []Exclusion
	history    map[string]fingerprintHistory // IP → last known fingerprint
	alerts     []AnomalyAlert
	maxAlerts  int
}

// fingerprintHistory tracks the last known fingerprint for an IP.
type fingerprintHistory struct {
	IP           string
	LastHash     string
	LastType     string // ja4, ja4s, ja4t
	LastSNI      string
	LastSeen     time.Time
	ChangeCount  int // How many times the fingerprint has changed
}

// AnomalyAlert records a detected fingerprint change.
type AnomalyAlert struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	SNI         string    `json:"sni,omitempty"`
	FPType      string    `json:"fp_type"`      // ja4, ja4s, etc.
	OldHash     string    `json:"old_hash"`
	NewHash     string    `json:"new_hash"`
	Severity    string    `json:"severity"`      // info, warning, critical
	Description string    `json:"description"`
	Excluded    bool      `json:"excluded"`       // Was this suppressed by an exclusion?
	ExcludeRule string    `json:"exclude_rule,omitempty"`
}

// Exclusion defines a rule for suppressing anomaly alerts.
type Exclusion struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`       // "ip", "hash", "transition", "cidr"
	Value     string    `json:"value"`      // The IP, hash, "old→new", or CIDR
	Reason    string    `json:"reason"`     // Why this exclusion exists
	ExpiresAt time.Time `json:"expires_at"` // Zero = permanent
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"` // "admin", "api", "auto"
	HitCount  int64     `json:"hit_count"`  // How many times this exclusion has been matched
}

// NewAnomalyDetector creates a new anomaly detector.
func NewAnomalyDetector(db *sql.DB) (*AnomalyDetector, error) {
	d := &AnomalyDetector{
		db:        db,
		history:   make(map[string]fingerprintHistory),
		maxAlerts: 10000,
	}

	if db != nil {
		if err := d.migrate(); err != nil {
			return nil, fmt.Errorf("anomaly detector migration: %w", err)
		}
		if err := d.loadExclusions(); err != nil {
			return nil, fmt.Errorf("loading exclusions: %w", err)
		}
	}

	return d, nil
}

func (d *AnomalyDetector) migrate() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS fp_anomaly_alerts (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			src_ip      TEXT NOT NULL,
			sni         TEXT NOT NULL DEFAULT '',
			fp_type     TEXT NOT NULL,
			old_hash    TEXT NOT NULL,
			new_hash    TEXT NOT NULL,
			severity    TEXT NOT NULL DEFAULT 'warning',
			description TEXT NOT NULL DEFAULT '',
			excluded    INTEGER NOT NULL DEFAULT 0,
			exclude_rule TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_anomaly_ip ON fp_anomaly_alerts(src_ip);
		CREATE INDEX IF NOT EXISTS idx_anomaly_time ON fp_anomaly_alerts(timestamp);

		CREATE TABLE IF NOT EXISTS fp_exclusions (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			type       TEXT NOT NULL,
			value      TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT '',
			expires_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT NOT NULL DEFAULT 'admin',
			hit_count  INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_exclusion_type ON fp_exclusions(type);
	`)
	return err
}

// CheckFingerprint evaluates whether a new fingerprint observation represents
// a change from a previously known fingerprint for the same source IP.
//
// Returns an alert if the fingerprint changed (nil if no change or excluded).
func (d *AnomalyDetector) CheckFingerprint(srcIP, fpType, newHash, sni string) *AnomalyAlert {
	d.mu.Lock()
	defer d.mu.Unlock()

	histKey := srcIP + ":" + fpType
	prev, exists := d.history[histKey]

	// Update history.
	d.history[histKey] = fingerprintHistory{
		IP:          srcIP,
		LastHash:    newHash,
		LastType:    fpType,
		LastSNI:     sni,
		LastSeen:    time.Now(),
		ChangeCount: prev.ChangeCount,
	}

	if !exists {
		return nil // First observation — no previous to compare.
	}

	if prev.LastHash == newHash {
		return nil // Same fingerprint — no change.
	}

	// Increment change count BEFORE assessing severity so the threshold
	// check uses the current count, not the stale one (off-by-one fix).
	h := d.history[histKey]
	h.ChangeCount++
	d.history[histKey] = h

	// Fingerprint changed! Check exclusions before alerting.
	alert := &AnomalyAlert{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		SNI:         sni,
		FPType:      fpType,
		OldHash:     prev.LastHash,
		NewHash:     newHash,
		Severity:    d.assessSeverity(h, newHash),
		Description: fmt.Sprintf("%s fingerprint changed for %s", fpType, srcIP),
	}

	// Check exclusions.
	if rule := d.matchExclusion(srcIP, prev.LastHash, newHash); rule != nil {
		alert.Excluded = true
		alert.ExcludeRule = rule.Value
		rule.HitCount++
		d.updateExclusionHitCount(rule.ID, rule.HitCount)
	}

	// Store alert.
	d.storeAlert(alert)

	if !alert.Excluded {
		slog.Warn("fingerprint change detected",
			"src_ip", srcIP,
			"type", fpType,
			"old_hash", prev.LastHash,
			"new_hash", newHash,
			"severity", alert.Severity,
			"sni", sni,
		)
	}

	return alert
}

// assessSeverity determines alert severity based on context.
func (d *AnomalyDetector) assessSeverity(prev fingerprintHistory, newHash string) string {
	// Multiple changes in a short period = more suspicious.
	if prev.ChangeCount >= 5 {
		return "critical"
	}
	if prev.ChangeCount >= 2 {
		return "high"
	}

	// Quick change (within 5 minutes) is more suspicious than gradual.
	if time.Since(prev.LastSeen) < 5*time.Minute {
		return "high"
	}

	return "warning"
}

// matchExclusion checks if any exclusion rule matches this change.
func (d *AnomalyDetector) matchExclusion(srcIP, oldHash, newHash string) *Exclusion {
	now := time.Now()

	for i := range d.exclusions {
		ex := &d.exclusions[i]

		// Check expiry.
		if !ex.ExpiresAt.IsZero() && now.After(ex.ExpiresAt) {
			continue
		}

		switch ex.Type {
		case "ip":
			if ex.Value == srcIP {
				return ex
			}
		case "hash":
			if ex.Value == newHash || ex.Value == oldHash {
				return ex
			}
		case "transition":
			// Format: "old_hash→new_hash"
			expected := oldHash + "→" + newHash
			if ex.Value == expected {
				return ex
			}
		case "cidr":
			// Check if IP is in CIDR range.
			if matchCIDR(srcIP, ex.Value) {
				return ex
			}
		}
	}

	return nil
}

// matchCIDR delegates to the shared validate.MatchCIDR implementation.
func matchCIDR(ip, cidr string) bool {
	return validate.MatchCIDR(ip, cidr)
}

// AddExclusion adds a new exclusion rule.
func (d *AnomalyDetector) AddExclusion(ex Exclusion) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if ex.Type == "" || ex.Value == "" {
		return fmt.Errorf("exclusion type and value are required")
	}

	switch ex.Type {
	case "ip", "hash", "transition", "cidr":
	default:
		return fmt.Errorf("invalid exclusion type: %q (must be ip, hash, transition, or cidr)", ex.Type)
	}

	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now()
	}
	if ex.CreatedBy == "" {
		ex.CreatedBy = "admin"
	}

	if d.db != nil {
		result, err := d.db.Exec(`
			INSERT INTO fp_exclusions (type, value, reason, expires_at, created_at, created_by)
			VALUES (?, ?, ?, ?, ?, ?)
		`, ex.Type, ex.Value, ex.Reason, ex.ExpiresAt, ex.CreatedAt, ex.CreatedBy)
		if err != nil {
			return fmt.Errorf("store exclusion: %w", err)
		}
		ex.ID, _ = result.LastInsertId()
	}

	d.exclusions = append(d.exclusions, ex)
	return nil
}

// RemoveExclusion removes an exclusion by ID.
func (d *AnomalyDetector) RemoveExclusion(id int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i, ex := range d.exclusions {
		if ex.ID == id {
			d.exclusions = append(d.exclusions[:i], d.exclusions[i+1:]...)
			if d.db != nil {
				d.db.Exec("DELETE FROM fp_exclusions WHERE id = ?", id)
			}
			return nil
		}
	}
	return fmt.Errorf("exclusion %d not found", id)
}

// ListExclusions returns all active exclusions.
func (d *AnomalyDetector) ListExclusions() []Exclusion {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]Exclusion, len(d.exclusions))
	copy(result, d.exclusions)
	return result
}

// ListAlerts returns recent anomaly alerts.
func (d *AnomalyDetector) ListAlerts(limit int) ([]AnomalyAlert, error) {
	if d.db == nil {
		d.mu.RLock()
		defer d.mu.RUnlock()
		if limit <= 0 || limit > len(d.alerts) {
			limit = len(d.alerts)
		}
		result := make([]AnomalyAlert, limit)
		copy(result, d.alerts[len(d.alerts)-limit:])
		return result, nil
	}

	if limit <= 0 {
		limit = 100
	}

	rows, err := d.db.Query(`
		SELECT id, timestamp, src_ip, sni, fp_type, old_hash, new_hash,
		       severity, description, excluded, exclude_rule
		FROM fp_anomaly_alerts ORDER BY timestamp DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []AnomalyAlert
	for rows.Next() {
		var a AnomalyAlert
		var excluded int
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.SrcIP, &a.SNI, &a.FPType,
			&a.OldHash, &a.NewHash, &a.Severity, &a.Description,
			&excluded, &a.ExcludeRule); err != nil {
			return nil, err
		}
		a.Excluded = excluded != 0
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// ClearAlerts removes all alerts (e.g., after investigation).
func (d *AnomalyDetector) ClearAlerts() error {
	d.mu.Lock()
	d.alerts = nil
	d.mu.Unlock()

	if d.db != nil {
		_, err := d.db.Exec("DELETE FROM fp_anomaly_alerts")
		return err
	}
	return nil
}

// storeAlert persists an alert.
func (d *AnomalyDetector) storeAlert(alert *AnomalyAlert) {
	// In-memory buffer.
	d.alerts = append(d.alerts, *alert)
	if len(d.alerts) > d.maxAlerts {
		d.alerts = d.alerts[len(d.alerts)-d.maxAlerts:]
	}

	// SQLite persistence.
	if d.db != nil {
		result, err := d.db.Exec(`
			INSERT INTO fp_anomaly_alerts (timestamp, src_ip, sni, fp_type, old_hash, new_hash,
			                                severity, description, excluded, exclude_rule)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, alert.Timestamp, alert.SrcIP, alert.SNI, alert.FPType,
			alert.OldHash, alert.NewHash, alert.Severity, alert.Description,
			boolToInt(alert.Excluded), alert.ExcludeRule)
		if err == nil {
			alert.ID, _ = result.LastInsertId()
		}
	}
}

func (d *AnomalyDetector) updateExclusionHitCount(id, count int64) {
	if d.db != nil {
		d.db.Exec("UPDATE fp_exclusions SET hit_count = ? WHERE id = ?", count, id)
	}
}

func (d *AnomalyDetector) loadExclusions() error {
	rows, err := d.db.Query(`
		SELECT id, type, value, reason, expires_at, created_at, created_by, hit_count
		FROM fp_exclusions
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ex Exclusion
		var expiresAt sql.NullTime
		if err := rows.Scan(&ex.ID, &ex.Type, &ex.Value, &ex.Reason,
			&expiresAt, &ex.CreatedAt, &ex.CreatedBy, &ex.HitCount); err != nil {
			return err
		}
		if expiresAt.Valid {
			ex.ExpiresAt = expiresAt.Time
		}
		d.exclusions = append(d.exclusions, ex)
	}
	return rows.Err()
}
