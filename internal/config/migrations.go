package config

import (
	"database/sql"
	"fmt"
	"log/slog"
)

var migrations = []struct {
	name string
	sql  string
}{
	{
		name: "001_initial_schema",
		sql: `
CREATE TABLE IF NOT EXISTS zones (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	interface   TEXT NOT NULL DEFAULT '',
	network_cidr TEXT NOT NULL DEFAULT '',
	trust_level TEXT NOT NULL DEFAULT 'none',
	description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS aliases (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	type        TEXT NOT NULL CHECK(type IN ('host','network','port','mac','nested','external_url')),
	description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alias_members (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	alias_id INTEGER NOT NULL REFERENCES aliases(id) ON DELETE CASCADE,
	value    TEXT NOT NULL,
	UNIQUE(alias_id, value)
);

CREATE TABLE IF NOT EXISTS policies (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	name           TEXT NOT NULL UNIQUE,
	description    TEXT NOT NULL DEFAULT '',
	default_action TEXT NOT NULL DEFAULT 'deny' CHECK(default_action IN ('allow','deny','reject','log'))
);

CREATE TABLE IF NOT EXISTS rules (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	policy_id   INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
	"order"     INTEGER NOT NULL DEFAULT 0,
	src_alias   TEXT NOT NULL DEFAULT '',
	dst_alias   TEXT NOT NULL DEFAULT '',
	protocol    TEXT NOT NULL DEFAULT '',
	ports       TEXT NOT NULL DEFAULT '',
	action      TEXT NOT NULL DEFAULT 'deny' CHECK(action IN ('allow','deny','reject','log')),
	log         INTEGER NOT NULL DEFAULT 0,
	description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS profiles (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	zone_id     INTEGER NOT NULL REFERENCES zones(id),
	policy_name TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS device_assignments (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ip          TEXT NOT NULL UNIQUE,
	mac         TEXT NOT NULL DEFAULT '',
	hostname    TEXT NOT NULL DEFAULT '',
	profile_id  INTEGER NOT NULL REFERENCES profiles(id),
	assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS config_revisions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	rev_number INTEGER NOT NULL UNIQUE,
	timestamp  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	message    TEXT NOT NULL DEFAULT '',
	snapshot   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS schema_migrations (
	name       TEXT PRIMARY KEY,
	applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`,
	},
	{
		name: "002_audit_log",
		sql: `
CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	action      TEXT NOT NULL,
	resource    TEXT NOT NULL,
	resource_id TEXT NOT NULL DEFAULT '',
	detail      TEXT NOT NULL DEFAULT '',
	source      TEXT NOT NULL DEFAULT 'api'
);
`,
	},
}

// Migrate runs all pending schema migrations.
func (s *Store) Migrate() error {
	// Ensure schema_migrations table exists first.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	for _, m := range migrations {
		var exists int
		err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE name = ?", m.name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", m.name, err)
		}
		if exists > 0 {
			continue
		}

		slog.Info("running migration", "name", m.name)
		if err := runMigration(s.db, m.name, m.sql); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

func runMigration(db *sql.DB, name, sql string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(sql); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO schema_migrations (name) VALUES (?)", name); err != nil {
		return err
	}
	return tx.Commit()
}
