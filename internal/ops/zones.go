package ops

import (
	"fmt"

	"github.com/mwilco03/kepha/internal/model"
	"github.com/mwilco03/kepha/internal/validate"
)

// ListZones returns all zones. Read-only, no audit needed.
func (o *Ops) ListZones() ([]model.Zone, error) {
	return o.store.ListZones()
}

// GetZone returns a single zone by name. Read-only.
func (o *Ops) GetZone(name string) (*model.Zone, error) {
	return o.store.GetZone(name)
}

// CreateZone validates and creates a new zone, logging the mutation.
func (o *Ops) CreateZone(actor Actor, z *model.Zone) error {
	// Sanitize all string inputs before validation.
	z.Name = validate.Sanitize(z.Name)
	z.Interface = validate.Sanitize(z.Interface)
	z.NetworkCIDR = validate.Sanitize(z.NetworkCIDR)
	z.TrustLevel = model.TrustLevel(validate.Sanitize(string(z.TrustLevel)))
	z.Description = validate.Sanitize(z.Description)

	if z.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := validate.Name(z.Name); err != nil {
		return err
	}
	if err := validate.Interface(z.Interface); err != nil {
		return err
	}
	if err := validate.CIDR(z.NetworkCIDR); err != nil {
		return err
	}
	if z.TrustLevel != "" {
		if err := validate.TrustLevel(string(z.TrustLevel)); err != nil {
			return err
		}
	}
	if err := o.store.CreateZone(z); err != nil {
		return err
	}
	o.audit(actor, "create", "zone", z.Name, z)
	return nil
}

// UpdateZone validates and updates an existing zone.
func (o *Ops) UpdateZone(actor Actor, z *model.Zone) error {
	z.Interface = validate.Sanitize(z.Interface)
	z.NetworkCIDR = validate.Sanitize(z.NetworkCIDR)
	z.TrustLevel = model.TrustLevel(validate.Sanitize(string(z.TrustLevel)))
	z.Description = validate.Sanitize(z.Description)

	if err := validate.Interface(z.Interface); err != nil {
		return err
	}
	if err := validate.CIDR(z.NetworkCIDR); err != nil {
		return err
	}
	if z.TrustLevel != "" {
		if err := validate.TrustLevel(string(z.TrustLevel)); err != nil {
			return err
		}
	}
	if err := o.store.UpdateZone(z); err != nil {
		return err
	}
	o.audit(actor, "update", "zone", z.Name, z)
	return nil
}

// DeleteZone removes a zone by name.
func (o *Ops) DeleteZone(actor Actor, name string) error {
	if err := o.store.DeleteZone(name); err != nil {
		return err
	}
	o.audit(actor, "delete", "zone", name, nil)
	return nil
}
