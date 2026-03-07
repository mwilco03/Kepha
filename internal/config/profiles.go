package config

import (
	"database/sql"
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func (s *Store) ListProfiles() ([]model.Profile, error) {
	rows, err := s.db.Query("SELECT id, name, description, zone_id, policy_name FROM profiles ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []model.Profile
	for rows.Next() {
		var p model.Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.ZoneID, &p.PolicyName); err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

func (s *Store) GetProfile(name string) (*model.Profile, error) {
	var p model.Profile
	err := s.db.QueryRow("SELECT id, name, description, zone_id, policy_name FROM profiles WHERE name = ?", name).
		Scan(&p.ID, &p.Name, &p.Description, &p.ZoneID, &p.PolicyName)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) CreateProfile(p *model.Profile) error {
	res, err := s.db.Exec(
		"INSERT INTO profiles (name, description, zone_id, policy_name) VALUES (?, ?, ?, ?)",
		p.Name, p.Description, p.ZoneID, p.PolicyName,
	)
	if err != nil {
		return fmt.Errorf("insert profile: %w", err)
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateProfile(p *model.Profile) error {
	_, err := s.db.Exec(
		"UPDATE profiles SET description = ?, zone_id = ?, policy_name = ? WHERE name = ?",
		p.Description, p.ZoneID, p.PolicyName, p.Name,
	)
	return err
}

func (s *Store) DeleteProfile(name string) error {
	_, err := s.db.Exec("DELETE FROM profiles WHERE name = ?", name)
	return err
}
