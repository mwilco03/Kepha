package ops

import (
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// ListAliases returns all aliases. Read-only.
func (o *Ops) ListAliases() ([]model.Alias, error) {
	return o.store.ListAliases()
}

// GetAlias returns a single alias by name. Read-only.
func (o *Ops) GetAlias(name string) (*model.Alias, error) {
	return o.store.GetAlias(name)
}

// CreateAlias validates and creates a new alias, checking for nested cycles.
func (o *Ops) CreateAlias(actor Actor, a *model.Alias) error {
	if a.Name == "" || a.Type == "" {
		return fmt.Errorf("name and type are required")
	}
	if err := validate.Name(a.Name); err != nil {
		return err
	}
	if err := validate.AliasType(string(a.Type)); err != nil {
		return err
	}
	for _, m := range a.Members {
		if err := validate.AliasMember(m, string(a.Type)); err != nil {
			return err
		}
	}
	if err := o.store.CreateAlias(a); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "create", "alias", a.Name, a)
	// Check for nested alias cycles — rollback on detection.
	if a.Type == model.AliasTypeNested {
		if err := o.store.CheckAliasCycles(a.Name); err != nil {
			_ = o.store.DeleteAlias(a.Name)
			return err
		}
	}
	return nil
}

// UpdateAlias updates an existing alias.
func (o *Ops) UpdateAlias(actor Actor, a *model.Alias) error {
	if err := o.store.UpdateAlias(a); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "update", "alias", a.Name, a)
	return nil
}

// DeleteAlias removes an alias by name.
func (o *Ops) DeleteAlias(actor Actor, name string) error {
	if err := o.store.DeleteAlias(name); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "delete", "alias", name, nil)
	return nil
}

// AddAliasMember validates and adds a member to an alias.
func (o *Ops) AddAliasMember(actor Actor, aliasName, member string) error {
	if member == "" {
		return fmt.Errorf("member is required")
	}
	alias, err := o.store.GetAlias(aliasName)
	if err != nil {
		return err
	}
	if alias == nil {
		return fmt.Errorf("alias not found")
	}
	if err := validate.AliasMember(member, string(alias.Type)); err != nil {
		return err
	}
	return o.store.AddAliasMember(aliasName, member)
}

// RemoveAliasMember removes a member from an alias.
func (o *Ops) RemoveAliasMember(aliasName, member string) error {
	if member == "" {
		return fmt.Errorf("member is required")
	}
	return o.store.RemoveAliasMember(aliasName, member)
}
