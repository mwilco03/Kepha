package config

import (
	"database/sql"
	"fmt"
	"net"

	"github.com/mwilco03/kepha/internal/model"
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
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Validate CIDR overlap within the transaction to prevent TOCTOU.
	if z.NetworkCIDR != "" {
		if err := s.checkCIDROverlapTx(tx, z.NetworkCIDR, ""); err != nil {
			return err
		}
	}

	res, err := tx.Exec(
		"INSERT INTO zones (name, interface, network_cidr, trust_level, description, mtu) VALUES (?, ?, ?, ?, ?, ?)",
		z.Name, z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description, z.MTU,
	)
	if err != nil {
		return fmt.Errorf("insert zone: %w", err)
	}
	z.ID, _ = res.LastInsertId()
	return tx.Commit()
}

// querier abstracts *sql.DB and *sql.Tx for shared query logic.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// checkCIDROverlap verifies that a new CIDR does not overlap with any existing
// zone's subnet. excludeName is the zone being updated (empty for create).
func (s *Store) checkCIDROverlap(cidr, excludeName string) error {
	return s.checkCIDROverlapTx(s.db, cidr, excludeName)
}

func (s *Store) checkCIDROverlapTx(q querier, cidr, excludeName string) error {
	_, newNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	rows, err := q.Query("SELECT name, network_cidr FROM zones ORDER BY id")
	if err != nil {
		return fmt.Errorf("list zones for overlap check: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, netCIDR string
		if err := rows.Scan(&name, &netCIDR); err != nil {
			continue
		}
		if netCIDR == "" || name == excludeName {
			continue
		}
		_, existingNet, err := net.ParseCIDR(netCIDR)
		if err != nil {
			continue
		}
		if newNet.Contains(existingNet.IP) || existingNet.Contains(newNet.IP) {
			return fmt.Errorf("CIDR %s overlaps with zone %q (%s)", cidr, name, netCIDR)
		}
	}
	return nil
}

func (s *Store) UpdateZone(z *model.Zone) error {
	// Validate CIDR overlap (exclude self) — uses non-transactional path since
	// the UPDATE itself will fail on UNIQUE constraint if there's a real conflict.
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
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// M-N6: Check for profiles referencing this zone before deleting (within tx).
	var profileCount int
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM profiles WHERE zone_id = (SELECT id FROM zones WHERE name = ?)", name,
	).Scan(&profileCount); err == nil && profileCount > 0 {
		return fmt.Errorf("cannot delete zone %q: %d profile(s) still reference it", name, profileCount)
	}
	if _, err := tx.Exec("DELETE FROM zones WHERE name = ?", name); err != nil {
		return err
	}
	return tx.Commit()
}
