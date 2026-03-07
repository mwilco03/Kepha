package ops

import (
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// ListProfiles returns all profiles. Read-only.
func (o *Ops) ListProfiles() ([]model.Profile, error) {
	return o.store.ListProfiles()
}

// GetProfile returns a single profile by name. Read-only.
func (o *Ops) GetProfile(name string) (*model.Profile, error) {
	return o.store.GetProfile(name)
}

// CreateProfile validates and creates a new profile.
func (o *Ops) CreateProfile(actor Actor, p *model.Profile) error {
	p.Name = validate.Sanitize(p.Name)
	p.Description = validate.Sanitize(p.Description)
	p.PolicyName = validate.Sanitize(p.PolicyName)

	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := validate.Name(p.Name); err != nil {
		return err
	}
	if err := o.store.CreateProfile(p); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "create", "profile", p.Name, p)
	return nil
}

// UpdateProfile sanitizes and updates an existing profile.
func (o *Ops) UpdateProfile(actor Actor, p *model.Profile) error {
	p.Description = validate.Sanitize(p.Description)
	p.PolicyName = validate.Sanitize(p.PolicyName)

	if err := o.store.UpdateProfile(p); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "update", "profile", p.Name, p)
	return nil
}

// DeleteProfile removes a profile by name.
func (o *Ops) DeleteProfile(actor Actor, name string) error {
	if err := o.store.DeleteProfile(name); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "delete", "profile", name, nil)
	return nil
}
