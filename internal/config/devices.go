package config

import (
	"database/sql"
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func (s *Store) ListDevices() ([]model.DeviceAssignment, error) {
	rows, err := s.db.Query("SELECT id, ip, mac, hostname, profile_id, assigned_at FROM device_assignments ORDER BY ip")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []model.DeviceAssignment
	for rows.Next() {
		var d model.DeviceAssignment
		if err := rows.Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.ProfileID, &d.AssignedAt); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Store) GetDevice(ip string) (*model.DeviceAssignment, error) {
	var d model.DeviceAssignment
	err := s.db.QueryRow(
		"SELECT id, ip, mac, hostname, profile_id, assigned_at FROM device_assignments WHERE ip = ?", ip,
	).Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.ProfileID, &d.AssignedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) AssignDevice(d *model.DeviceAssignment) error {
	res, err := s.db.Exec(
		`INSERT INTO device_assignments (ip, mac, hostname, profile_id) VALUES (?, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac, hostname = excluded.hostname, profile_id = excluded.profile_id, assigned_at = CURRENT_TIMESTAMP`,
		d.IP, d.MAC, d.Hostname, d.ProfileID,
	)
	if err != nil {
		return fmt.Errorf("assign device: %w", err)
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UnassignDevice(ip string) error {
	result, err := s.db.Exec("DELETE FROM device_assignments WHERE ip = ?", ip)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("device %s not found", ip)
	}
	return nil
}
