package config

import "log/slog"

// Seed inserts default zones, policies, and profiles if they don't exist.
func (s *Store) Seed() error {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM zones").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil // Already seeded.
	}

	slog.Info("seeding default configuration")

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Default zones: wan and lan only (per rebuttal).
	if _, err := tx.Exec(`INSERT INTO zones (name, interface, network_cidr, trust_level, description) VALUES
		('wan', 'eth0', '', 'none', 'Upstream / Internet'),
		('lan', 'eth1', '10.10.0.0/24', 'full', 'Trusted local network')
	`); err != nil {
		return err
	}

	// Default policies.
	if _, err := tx.Exec(`INSERT INTO policies (name, description, default_action) VALUES
		('lan-outbound', 'Allow LAN to WAN', 'allow'),
		('deny-all', 'Default deny between zones', 'deny')
	`); err != nil {
		return err
	}

	// Default profiles.
	if _, err := tx.Exec(`INSERT INTO profiles (name, description, zone_id, policy_name) VALUES
		('desktop', 'Desktop workstation', 2, 'lan-outbound'),
		('server', 'Server with restricted access', 2, 'lan-outbound')
	`); err != nil {
		return err
	}

	return tx.Commit()
}
