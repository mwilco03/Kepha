package ops

import (
	"fmt"

	"github.com/mwilco03/kepha/internal/model"
	"github.com/mwilco03/kepha/internal/validate"
)

// ListDevices returns all device assignments. Read-only.
func (o *Ops) ListDevices() ([]model.DeviceAssignment, error) {
	return o.store.ListDevices()
}

// AssignDevice validates and creates a device-to-profile assignment.
// If Profile (name) is given instead of ProfileID, it resolves the ID.
func (o *Ops) AssignDevice(actor Actor, ip, mac, hostname, profileName string, profileID int64) (*model.DeviceAssignment, error) {
	ip = validate.Sanitize(ip)
	mac = validate.Sanitize(mac)
	hostname = validate.Sanitize(hostname)
	profileName = validate.Sanitize(profileName)

	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if err := validate.IP(ip); err != nil {
		return nil, err
	}
	if err := validate.MAC(mac); err != nil {
		return nil, err
	}
	if err := validate.Hostname(hostname); err != nil {
		return nil, err
	}

	// Resolve profile name to ID if needed.
	if profileID == 0 && profileName != "" {
		p, err := o.store.GetProfile(profileName)
		if err != nil || p == nil {
			return nil, fmt.Errorf("profile not found")
		}
		profileID = p.ID
	}
	if profileID == 0 {
		return nil, fmt.Errorf("profile or profile_id is required")
	}

	d := &model.DeviceAssignment{
		IP:        ip,
		MAC:       mac,
		Hostname:  hostname,
		ProfileID: profileID,
	}
	if err := o.store.AssignDevice(d); err != nil {
		return nil, err
	}
	o.audit(actor, "assign", "device", d.IP, d)
	return d, nil
}

// UnassignDevice removes a device assignment by IP.
func (o *Ops) UnassignDevice(actor Actor, ip string) error {
	if ip == "" {
		return fmt.Errorf("ip is required")
	}
	if err := o.store.UnassignDevice(ip); err != nil {
		return err
	}
	o.audit(actor, "unassign", "device", ip, nil)
	return nil
}
