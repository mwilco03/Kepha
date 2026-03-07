package config

import (
	"database/sql"
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func (s *Store) ListZones() ([]model.Zone, error) {
	rows, err := s.db.Query("SELECT id, name, interface, network_cidr, trust_level, description FROM zones ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var zones []model.Zone
	for rows.Next() {
		var z model.Zone
		if err := rows.Scan(&z.ID, &z.Name, &z.Interface, &z.NetworkCIDR, &z.TrustLevel, &z.Description); err != nil {
			return nil, err
		}
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

func (s *Store) GetZone(name string) (*model.Zone, error) {
	var z model.Zone
	err := s.db.QueryRow(
		"SELECT id, name, interface, network_cidr, trust_level, description FROM zones WHERE name = ?", name,
	).Scan(&z.ID, &z.Name, &z.Interface, &z.NetworkCIDR, &z.TrustLevel, &z.Description)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &z, nil
}

func (s *Store) CreateZone(z *model.Zone) error {
	res, err := s.db.Exec(
		"INSERT INTO zones (name, interface, network_cidr, trust_level, description) VALUES (?, ?, ?, ?, ?)",
		z.Name, z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description,
	)
	if err != nil {
		return fmt.Errorf("insert zone: %w", err)
	}
	z.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateZone(z *model.Zone) error {
	_, err := s.db.Exec(
		"UPDATE zones SET interface = ?, network_cidr = ?, trust_level = ?, description = ? WHERE name = ?",
		z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description, z.Name,
	)
	return err
}

func (s *Store) ListZonesPaginated(p Pagination) ([]model.Zone, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM zones").Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query("SELECT id, name, interface, network_cidr, trust_level, description FROM zones ORDER BY id LIMIT ? OFFSET ?", p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var zones []model.Zone
	for rows.Next() {
		var z model.Zone
		if err := rows.Scan(&z.ID, &z.Name, &z.Interface, &z.NetworkCIDR, &z.TrustLevel, &z.Description); err != nil {
			return nil, 0, err
		}
		zones = append(zones, z)
	}
	return zones, total, rows.Err()
}

func (s *Store) DeleteZone(name string) error {
	_, err := s.db.Exec("DELETE FROM zones WHERE name = ?", name)
	return err
}
