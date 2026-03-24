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
	{
		name: "003_zone_mtu",
		sql:  `ALTER TABLE zones ADD COLUMN mtu INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name: "004_content_filter",
		sql: `
CREATE TABLE IF NOT EXISTS content_filters (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	name              TEXT NOT NULL UNIQUE,
	zone_id           INTEGER NOT NULL DEFAULT 0,
	profile_id        INTEGER NOT NULL DEFAULT 0,
	blocked_categories TEXT NOT NULL DEFAULT '',
	blocked_domains   TEXT NOT NULL DEFAULT '',
	allowed_domains   TEXT NOT NULL DEFAULT '',
	enabled           INTEGER NOT NULL DEFAULT 1,
	description       TEXT NOT NULL DEFAULT '',
	created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS filter_exceptions (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	filter_id       INTEGER NOT NULL REFERENCES content_filters(id) ON DELETE CASCADE,
	domain          TEXT NOT NULL,
	category        TEXT NOT NULL DEFAULT '',
	justification   TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','expired','revoked')),
	approved_by     TEXT NOT NULL DEFAULT '',
	approval_note   TEXT NOT NULL DEFAULT '',
	expires_at      DATETIME NOT NULL,
	created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	reviewed_at     DATETIME
);
CREATE INDEX IF NOT EXISTS idx_filter_exceptions_status ON filter_exceptions(status);
CREATE INDEX IF NOT EXISTS idx_filter_exceptions_filter ON filter_exceptions(filter_id);
CREATE INDEX IF NOT EXISTS idx_filter_exceptions_domain ON filter_exceptions(domain);
`,
	},
	{
		name: "002_add_missing_indexes",
		sql: `
-- M-DB4: Index on rules.policy_id for efficient per-policy rule lookups.
CREATE INDEX IF NOT EXISTS idx_rules_policy_id ON rules(policy_id);

-- M-DB5: Index on alias_members.alias_id for efficient member lookups.
CREATE INDEX IF NOT EXISTS idx_alias_members_alias_id ON alias_members(alias_id);

-- M-DB6: Index on audit_log for efficient ordered queries.
CREATE INDEX IF NOT EXISTS idx_audit_log_id ON audit_log(id DESC);
`,
	},
	{
		name: "005_dns_hosts_and_feeds",
		sql: `
-- DNS host overrides: standalone hostname→IP records independent of device assignments.
CREATE TABLE IF NOT EXISTS dns_hosts (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	hostname    TEXT NOT NULL,
	domain      TEXT NOT NULL DEFAULT '',
	record_type TEXT NOT NULL DEFAULT 'A',
	value       TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	enabled     INTEGER NOT NULL DEFAULT 1,
	created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(hostname, domain, record_type)
);

-- DNS feed subscriptions: blocklist feeds for ad/tracker/malware blocking.
CREATE TABLE IF NOT EXISTS dns_feeds (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL UNIQUE,
	url          TEXT NOT NULL,
	category     TEXT NOT NULL DEFAULT 'general',
	enabled      INTEGER NOT NULL DEFAULT 0,
	entry_count  INTEGER NOT NULL DEFAULT 0,
	last_updated DATETIME,
	update_interval_sec INTEGER NOT NULL DEFAULT 86400,
	description  TEXT NOT NULL DEFAULT '',
	created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- DNS block log: records blocked queries for the "recently blocked" UI.
CREATE TABLE IF NOT EXISTS dns_block_log (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT NOT NULL,
	client_ip  TEXT NOT NULL DEFAULT '',
	feed_name  TEXT NOT NULL DEFAULT '',
	blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dns_block_log_domain ON dns_block_log(domain);
CREATE INDEX IF NOT EXISTS idx_dns_block_log_time ON dns_block_log(blocked_at DESC);

-- Seed default feed sources (disabled by default — user opts in).
INSERT OR IGNORE INTO dns_feeds (name, url, category, description) VALUES
	('stevenblack-unified', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'ads+malware', 'StevenBlack unified hosts — ads, malware, fakenews'),
	('oisd-small', 'https://small.oisd.nl/domainswildcard', 'ads', 'OISD small — balanced ad blocking with low false positives'),
	('oisd-big', 'https://big.oisd.nl/domainswildcard', 'ads+tracking', 'OISD big — aggressive ad + tracker blocking'),
	('hagezi-light', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt', 'ads', 'Hagezi light — minimal blocking, very few false positives'),
	('hagezi-normal', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt', 'ads+tracking', 'Hagezi normal — recommended balance'),
	('hagezi-pro', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt', 'ads+tracking+privacy', 'Hagezi pro — aggressive, may break some sites'),
	('phishing-army', 'https://phishing.army/download/phishing_army_blocklist.txt', 'phishing', 'Phishing Army — phishing domain blocklist'),
	('malware-filter', 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt', 'malware', 'URLhaus malware domain filter');
`,
	},
	{
		name: "003_content_filter_fk_note",
		sql: `
-- M-DB7: content_filters.zone_id and profile_id lack FK constraints.
-- SQLite does not support ALTER TABLE ADD CONSTRAINT for foreign keys.
-- Adding FKs requires a full table rebuild (CREATE new → INSERT SELECT →
-- DROP old → ALTER TABLE RENAME). Deferred to a major schema revision.
-- Application-level validation in CreateZone/DeleteZone handles integrity.
-- This migration is a no-op placeholder to track the decision.
SELECT 1;
`,
	},
}

// Migrate runs all pending schema migrations.
// Refuses to start if the database has migrations newer than this binary
// (downgrade guard — prevents silent data corruption).
func (s *Store) Migrate() error {
	// Ensure schema_migrations table exists first.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	// Downgrade guard: check for migrations in DB that this binary doesn't know about.
	knownNames := make(map[string]bool, len(migrations))
	for _, m := range migrations {
		knownNames[m.name] = true
	}
	rows, err := s.db.Query("SELECT name FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("list applied migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan migration: %w", err)
		}
		if !knownNames[name] {
			return fmt.Errorf("database has migration %q not known to this binary — refusing to start (possible downgrade)", name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migrations: %w", err)
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
