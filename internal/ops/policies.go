package ops

import (
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// ListPolicies returns all policies. Read-only.
func (o *Ops) ListPolicies() ([]model.Policy, error) {
	return o.store.ListPolicies()
}

// GetPolicy returns a single policy by name. Read-only.
func (o *Ops) GetPolicy(name string) (*model.Policy, error) {
	return o.store.GetPolicy(name)
}

// CreatePolicy validates and creates a new policy.
func (o *Ops) CreatePolicy(actor Actor, p *model.Policy) error {
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := validate.Name(p.Name); err != nil {
		return err
	}
	if err := o.store.CreatePolicy(p); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "create", "policy", p.Name, p)
	return nil
}

// UpdatePolicy updates an existing policy.
func (o *Ops) UpdatePolicy(actor Actor, p *model.Policy) error {
	if err := o.store.UpdatePolicy(p); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "update", "policy", p.Name, p)
	return nil
}

// DeletePolicy removes a policy by name.
func (o *Ops) DeletePolicy(actor Actor, name string) error {
	if err := o.store.DeletePolicy(name); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "delete", "policy", name, nil)
	return nil
}

// CreateRule validates and creates a rule within a policy.
func (o *Ops) CreateRule(actor Actor, policyName string, rule *model.Rule) error {
	if err := validate.Protocol(rule.Protocol); err != nil {
		return err
	}
	if err := validate.Ports(rule.Ports); err != nil {
		return err
	}
	if err := validate.Action(string(rule.Action)); err != nil {
		return err
	}
	if err := o.store.CreateRule(policyName, rule); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "create", "rule", policyName, rule)
	return nil
}

// DeleteRule removes a rule by ID.
func (o *Ops) DeleteRule(actor Actor, id int64) error {
	if err := o.store.DeleteRule(id); err != nil {
		return err
	}
	_ = o.store.LogAudit(actor.Source, "delete", "rule", fmt.Sprintf("%d", id), nil)
	return nil
}
