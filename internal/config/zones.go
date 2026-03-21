package config

import (
	"database/sql"
	"fmt"
	"net"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func (s *Store) ListZones() ([]model.Zone, error) {
	rows, err := s.db.Query("SELECT id, name, interface, network_cidr, trust_level, description, mtu FROM zones ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var zones []model.Zone
	for rows.Next() {
		var z model.Zone
		if err := rows.Scan(&z.ID, &z.Name, &z.Interface, &z.NetworkCIDR, &z.TrustLevel, &z.Description, &z.MTU); err != nil {
			return nil, err
		}
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

func (s *Store) GetZone(name string) (*model.Zone, error) {
	var z model.Zone
	err := s.db.QueryRow(
		"SELECT id, name, interface, network_cidr, trust_level, description, mtu FROM zones WHERE name = ?", name,
	).Scan(&z.ID, &z.Name, &z.Interface, &z.NetworkCIDR, &z.TrustLevel, &z.Description, &z.MTU)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &z, nil
}

func (s *Store) CreateZone(z *model.Zone) error {
	// Validate CIDR overlap with existing zones.
	if z.NetworkCIDR != "" {
		if err := s.checkCIDROverlap(z.NetworkCIDR, ""); err != nil {
			return err
		}
	}

	res, err := s.db.Exec(
		"INSERT INTO zones (name, interface, network_cidr, trust_level, description, mtu) VALUES (?, ?, ?, ?, ?, ?)",
		z.Name, z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description, z.MTU,
	)
	if err != nil {
		return fmt.Errorf("insert zone: %w", err)
	}
	z.ID, _ = res.LastInsertId()
	return nil
}

// checkCIDROverlap verifies that a new CIDR does not overlap with any existing
// zone's subnet. excludeName is the zone being updated (empty for create).
func (s *Store) checkCIDROverlap(cidr, excludeName string) error {
	_, newNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	zones, err := s.ListZones()
	if err != nil {
		return fmt.Errorf("list zones for overlap check: %w", err)
	}

	for _, z := range zones {
		if z.NetworkCIDR == "" || z.Name == excludeName {
			continue
		}
		_, existingNet, err := net.ParseCIDR(z.NetworkCIDR)
		if err != nil {
			continue // Skip zones with unparseable CIDRs.
		}
		if newNet.Contains(existingNet.IP) || existingNet.Contains(newNet.IP) {
			return fmt.Errorf("CIDR %s overlaps with zone %q (%s)", cidr, z.Name, z.NetworkCIDR)
		}
	}
	return nil
}

func (s *Store) UpdateZone(z *model.Zone) error {
	// Validate CIDR overlap (exclude self).
	if z.NetworkCIDR != "" {
		if err := s.checkCIDROverlap(z.NetworkCIDR, z.Name); err != nil {
			return err
		}
	}

	_, err := s.db.Exec(
		"UPDATE zones SET interface = ?, network_cidr = ?, trust_level = ?, description = ?, mtu = ? WHERE name = ?",
		z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description, z.MTU, z.Name,
	)
	return err
}

func (s *Store) ListZonesPaginated(p Pagination) ([]model.Zone, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM zones").Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query("SELECT id, name, interface, network_cidr, trust_level, description, mtu FROM zones ORDER BY id LIMIT ? OFFSET ?", p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var zones []model.Zone
	for rows.Next() {
		var z model.Zone
		if err := rows.Scan(&z.ID, &z.Name, &z.Interface, &z.NetworkCIDR, &z.TrustLevel, &z.Description, &z.MTU); err != nil {
			return nil, 0, err
		}
		zones = append(zones, z)
	}
	return zones, total, rows.Err()
}

func (s *Store) DeleteZone(name string) error {
	// M-N6: Check for profiles referencing this zone before deleting.
	var profileCount int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM profiles WHERE zone_id = (SELECT id FROM zones WHERE name = ?)", name,
	).Scan(&profileCount); err == nil && profileCount > 0 {
		return fmt.Errorf("cannot delete zone %q: %d profile(s) still reference it", name, profileCount)
	}
	_, err := s.db.Exec("DELETE FROM zones WHERE name = ?", name)
	return err
}
