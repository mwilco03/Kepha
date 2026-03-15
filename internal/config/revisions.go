package config

import (
	"encoding/json"
	"fmt"
)

// ConfigSnapshot holds the full exportable state of the firewall config.
type ConfigSnapshot struct {
	Zones    json.RawMessage `json:"zones"`
	Aliases  json.RawMessage `json:"aliases"`
	Policies json.RawMessage `json:"policies"`
	Profiles json.RawMessage `json:"profiles"`
	Devices  json.RawMessage `json:"devices"`
}

// Commit creates a new config revision with a snapshot of the current state.
func (s *Store) Commit(message string) (int, error) {
	snapshot, err := s.Export()
	if err != nil {
		return 0, fmt.Errorf("export for commit: %w", err)
	}

	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return 0, fmt.Errorf("marshal snapshot: %w", err)
	}

	var nextRev int
	err = s.db.QueryRow("SELECT COALESCE(MAX(rev_number), 0) + 1 FROM config_revisions").Scan(&nextRev)
	if err != nil {
		return 0, err
	}

	_, err = s.db.Exec(
		"INSERT INTO config_revisions (rev_number, message, snapshot) VALUES (?, ?, ?)",
		nextRev, message, string(snapshotJSON),
	)
	if err != nil {
		return 0, fmt.Errorf("insert revision: %w", err)
	}

	return nextRev, nil
}

// Rollback restores the config to a previous revision.
func (s *Store) Rollback(rev int) error {
	var snapshotStr string
	err := s.db.QueryRow("SELECT snapshot FROM config_revisions WHERE rev_number = ?", rev).Scan(&snapshotStr)
	if err != nil {
		return fmt.Errorf("revision %d not found: %w", rev, err)
	}

	var snapshot ConfigSnapshot
	if err := json.Unmarshal([]byte(snapshotStr), &snapshot); err != nil {
		return fmt.Errorf("unmarshal snapshot: %w", err)
	}

	return s.Import(&snapshot)
}

// Diff returns the snapshots for two revisions so the caller can compare them.
func (s *Store) Diff(rev1, rev2 int) (*ConfigSnapshot, *ConfigSnapshot, error) {
	snap1, err := s.getSnapshot(rev1)
	if err != nil {
		return nil, nil, fmt.Errorf("get revision %d: %w", rev1, err)
	}
	snap2, err := s.getSnapshot(rev2)
	if err != nil {
		return nil, nil, fmt.Errorf("get revision %d: %w", rev2, err)
	}
	return snap1, snap2, nil
}

// ListRevisions returns all config revisions.
func (s *Store) ListRevisions() ([]struct {
	RevNumber int    `json:"rev_number"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}, error) {
	rows, err := s.db.Query("SELECT rev_number, timestamp, message FROM config_revisions ORDER BY rev_number DESC LIMIT 1000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var revs []struct {
		RevNumber int    `json:"rev_number"`
		Timestamp string `json:"timestamp"`
		Message   string `json:"message"`
	}
	for rows.Next() {
		var r struct {
			RevNumber int    `json:"rev_number"`
			Timestamp string `json:"timestamp"`
			Message   string `json:"message"`
		}
		if err := rows.Scan(&r.RevNumber, &r.Timestamp, &r.Message); err != nil {
			return nil, err
		}
		revs = append(revs, r)
	}
	return revs, rows.Err()
}

// Export returns the full current config as a snapshot.
func (s *Store) Export() (*ConfigSnapshot, error) {
	zones, err := s.ListZones()
	if err != nil {
		return nil, err
	}
	aliases, err := s.ListAliases()
	if err != nil {
		return nil, err
	}
	policies, err := s.ListPolicies()
	if err != nil {
		return nil, err
	}
	profiles, err := s.ListProfiles()
	if err != nil {
		return nil, err
	}
	devices, err := s.ListDevices()
	if err != nil {
		return nil, err
	}

	zonesJSON, _ := json.Marshal(zones)
	aliasesJSON, _ := json.Marshal(aliases)
	policiesJSON, _ := json.Marshal(policies)
	profilesJSON, _ := json.Marshal(profiles)
	devicesJSON, _ := json.Marshal(devices)

	return &ConfigSnapshot{
		Zones:    zonesJSON,
		Aliases:  aliasesJSON,
		Policies: policiesJSON,
		Profiles: profilesJSON,
		Devices:  devicesJSON,
	}, nil
}

// Import restores config from a snapshot, replacing all current data.
func (s *Store) Import(snap *ConfigSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear all tables in dependency order.
	for _, table := range []string{"device_assignments", "rules", "profiles", "alias_members", "aliases", "policies", "zones"} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Re-import zones.
	var zones []struct {
		Name        string `json:"name"`
		Interface   string `json:"interface"`
		NetworkCIDR string `json:"network_cidr"`
		TrustLevel  string `json:"trust_level"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(snap.Zones, &zones); err != nil {
		return fmt.Errorf("unmarshal zones: %w", err)
	}
	for _, z := range zones {
		if _, err := tx.Exec("INSERT INTO zones (name, interface, network_cidr, trust_level, description) VALUES (?, ?, ?, ?, ?)",
			z.Name, z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description); err != nil {
			return fmt.Errorf("import zone %s: %w", z.Name, err)
		}
	}

	// Re-import aliases.
	var aliases []struct {
		Name        string   `json:"name"`
		Type        string   `json:"type"`
		Description string   `json:"description"`
		Members     []string `json:"members"`
	}
	if err := json.Unmarshal(snap.Aliases, &aliases); err != nil {
		return fmt.Errorf("unmarshal aliases: %w", err)
	}
	for _, a := range aliases {
		res, err := tx.Exec("INSERT INTO aliases (name, type, description) VALUES (?, ?, ?)", a.Name, a.Type, a.Description)
		if err != nil {
			return fmt.Errorf("import alias %s: %w", a.Name, err)
		}
		id, _ := res.LastInsertId()
		for _, m := range a.Members {
			if _, err := tx.Exec("INSERT INTO alias_members (alias_id, value) VALUES (?, ?)", id, m); err != nil {
				return fmt.Errorf("import alias member: %w", err)
			}
		}
	}

	// Re-import policies and rules.
	var policies []struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		DefaultAction string `json:"default_action"`
		Rules         []struct {
			Order       int    `json:"order"`
			SrcAlias    string `json:"src_alias"`
			DstAlias    string `json:"dst_alias"`
			Protocol    string `json:"protocol"`
			Ports       string `json:"ports"`
			Action      string `json:"action"`
			Log         bool   `json:"log"`
			Description string `json:"description"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(snap.Policies, &policies); err != nil {
		return fmt.Errorf("unmarshal policies: %w", err)
	}
	for _, p := range policies {
		res, err := tx.Exec("INSERT INTO policies (name, description, default_action) VALUES (?, ?, ?)",
			p.Name, p.Description, p.DefaultAction)
		if err != nil {
			return fmt.Errorf("import policy %s: %w", p.Name, err)
		}
		pID, _ := res.LastInsertId()
		for _, r := range p.Rules {
			logInt := 0
			if r.Log {
				logInt = 1
			}
			if _, err := tx.Exec(
				`INSERT INTO rules (policy_id, "order", src_alias, dst_alias, protocol, ports, action, log, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				pID, r.Order, r.SrcAlias, r.DstAlias, r.Protocol, r.Ports, r.Action, logInt, r.Description); err != nil {
				return fmt.Errorf("import rule: %w", err)
			}
		}
	}

	// Re-import profiles.
	var profiles []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		ZoneID      int64  `json:"zone_id"`
		PolicyName  string `json:"policy_name"`
	}
	if err := json.Unmarshal(snap.Profiles, &profiles); err != nil {
		return fmt.Errorf("unmarshal profiles: %w", err)
	}
	for _, p := range profiles {
		// Look up zone by position since IDs may differ after re-import.
		if _, err := tx.Exec("INSERT INTO profiles (name, description, zone_id, policy_name) VALUES (?, ?, ?, ?)",
			p.Name, p.Description, p.ZoneID, p.PolicyName); err != nil {
			return fmt.Errorf("import profile %s: %w", p.Name, err)
		}
	}

	// Re-import devices.
	var devices []struct {
		IP        string `json:"ip"`
		MAC       string `json:"mac"`
		Hostname  string `json:"hostname"`
		ProfileID int64  `json:"profile_id"`
	}
	if snap.Devices != nil {
		if err := json.Unmarshal(snap.Devices, &devices); err != nil {
			return fmt.Errorf("unmarshal devices: %w", err)
		}
		for _, d := range devices {
			if _, err := tx.Exec("INSERT INTO device_assignments (ip, mac, hostname, profile_id) VALUES (?, ?, ?, ?)",
				d.IP, d.MAC, d.Hostname, d.ProfileID); err != nil {
				return fmt.Errorf("import device %s: %w", d.IP, err)
			}
		}
	}

	return tx.Commit()
}

func (s *Store) getSnapshot(rev int) (*ConfigSnapshot, error) {
	var snapshotStr string
	if err := s.db.QueryRow("SELECT snapshot FROM config_revisions WHERE rev_number = ?", rev).Scan(&snapshotStr); err != nil {
		return nil, err
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal([]byte(snapshotStr), &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
