package inspect

import (
	"database/sql"
	"fmt"
	"time"
)

// SQLiteStore implements FingerprintStore backed by SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a fingerprint store and runs migrations.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("fingerprint store migration: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS fingerprints (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			type        TEXT NOT NULL,
			hash        TEXT NOT NULL,
			src_ip      TEXT NOT NULL DEFAULT '',
			dst_ip      TEXT NOT NULL DEFAULT '',
			sni         TEXT NOT NULL DEFAULT '',
			device_name TEXT NOT NULL DEFAULT '',
			assigned_profile TEXT NOT NULL DEFAULT '',
			first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			count       INTEGER NOT NULL DEFAULT 1,
			threat_match INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_fingerprints_hash ON fingerprints(hash);
		CREATE INDEX IF NOT EXISTS idx_fingerprints_type ON fingerprints(type);
		CREATE INDEX IF NOT EXISTS idx_fingerprints_src_ip ON fingerprints(src_ip);
		CREATE INDEX IF NOT EXISTS idx_fingerprints_threat ON fingerprints(threat_match);
	`)
	return err
}

// RecordFingerprint upserts a fingerprint observation.
func (s *SQLiteStore) RecordFingerprint(fp ObservedFingerprint) error {
	_, err := s.db.Exec(`
		INSERT INTO fingerprints (type, hash, src_ip, dst_ip, sni, first_seen, last_seen, count, threat_match)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_seen = excluded.last_seen,
			count = count + 1
	`, fp.Type, fp.Hash, fp.SrcIP, fp.DstIP, fp.SNI, fp.FirstSeen, fp.LastSeen, boolToInt(fp.ThreatMatch))

	// If the hash+src_ip combo already exists, update instead.
	if err == nil {
		_, _ = s.db.Exec(`
			UPDATE fingerprints SET last_seen = ?, count = count + 1
			WHERE hash = ? AND src_ip = ? AND id != last_insert_rowid()
		`, time.Now(), fp.Hash, fp.SrcIP)
	}
	return err
}

// GetFingerprint retrieves a fingerprint by hash.
func (s *SQLiteStore) GetFingerprint(hash string) (*ObservedFingerprint, error) {
	fp := &ObservedFingerprint{}
	var threatMatch int
	err := s.db.QueryRow(`
		SELECT id, type, hash, src_ip, dst_ip, sni, device_name, assigned_profile,
		       first_seen, last_seen, count, threat_match
		FROM fingerprints WHERE hash = ? ORDER BY last_seen DESC LIMIT 1
	`, hash).Scan(&fp.ID, &fp.Type, &fp.Hash, &fp.SrcIP, &fp.DstIP, &fp.SNI,
		&fp.DeviceName, &fp.AssignedProfile, &fp.FirstSeen, &fp.LastSeen,
		&fp.Count, &threatMatch)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fp.ThreatMatch = threatMatch != 0
	return fp, nil
}

// ListFingerprints returns observed fingerprints, optionally filtered by type.
func (s *SQLiteStore) ListFingerprints(fpType string, limit int) ([]ObservedFingerprint, error) {
	if limit <= 0 {
		limit = 100
	}

	var rows *sql.Rows
	var err error

	if fpType != "" {
		rows, err = s.db.Query(`
			SELECT id, type, hash, src_ip, dst_ip, sni, device_name, assigned_profile,
			       first_seen, last_seen, count, threat_match
			FROM fingerprints WHERE type = ? ORDER BY last_seen DESC LIMIT ?
		`, fpType, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT id, type, hash, src_ip, dst_ip, sni, device_name, assigned_profile,
			       first_seen, last_seen, count, threat_match
			FROM fingerprints ORDER BY last_seen DESC LIMIT ?
		`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ObservedFingerprint
	for rows.Next() {
		var fp ObservedFingerprint
		var threatMatch int
		if err := rows.Scan(&fp.ID, &fp.Type, &fp.Hash, &fp.SrcIP, &fp.DstIP, &fp.SNI,
			&fp.DeviceName, &fp.AssignedProfile, &fp.FirstSeen, &fp.LastSeen,
			&fp.Count, &threatMatch); err != nil {
			return nil, err
		}
		fp.ThreatMatch = threatMatch != 0
		result = append(result, fp)
	}
	return result, rows.Err()
}

// AssignProfile maps a fingerprint hash to a named device profile.
func (s *SQLiteStore) AssignProfile(hash, profileName string) error {
	res, err := s.db.Exec(`
		UPDATE fingerprints SET assigned_profile = ? WHERE hash = ?
	`, profileName, hash)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fingerprint %q not found", hash)
	}
	return nil
}

// ListThreatMatches returns all fingerprints flagged as threat matches.
func (s *SQLiteStore) ListThreatMatches() ([]ObservedFingerprint, error) {
	return s.ListFingerprints("", 1000) // Reuse with filter applied below.
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
