package config

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database for transactional config management.
type Store struct {
	db *sql.DB
}

// NewStore opens or creates a SQLite database at the given path.
func NewStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// M-DB8: SQLite is single-writer. Limit connections to reduce write-lock
	// contention. Allow 2 for concurrent reads during a write.
	db.SetMaxOpenConns(2)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{db: db}, nil
}

// Ping verifies the database connection is alive.
func (s *Store) Ping() error {
	return s.db.Ping()
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Maintenance runs periodic SQLite housekeeping: WAL checkpoint and
// revision pruning. Should be called on a schedule (e.g., daily).
func (s *Store) Maintenance(keepRevisions int) error {
	// WAL checkpoint — truncate the WAL file to reclaim disk.
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}

	// Prune old revisions, keeping the most recent N.
	if keepRevisions > 0 {
		_, err := s.db.Exec(`DELETE FROM config_revisions WHERE id NOT IN
			(SELECT id FROM config_revisions ORDER BY rev_number DESC LIMIT ?)`,
			keepRevisions)
		if err != nil {
			return fmt.Errorf("prune revisions: %w", err)
		}
	}

	// Prune old audit log entries (keep last 10,000).
	if _, err := s.db.Exec(`DELETE FROM audit_log WHERE id NOT IN
		(SELECT id FROM audit_log ORDER BY id DESC LIMIT 10000)`); err != nil {
		// audit_log may not exist yet; ignore errors.
		_ = err
	}

	return nil
}

// DB returns the underlying sql.DB for use in transactions.
func (s *Store) DB() *sql.DB {
	return s.db
}
