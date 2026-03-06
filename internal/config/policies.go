package config

import (
	"database/sql"
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func (s *Store) ListPolicies() ([]model.Policy, error) {
	rows, err := s.db.Query("SELECT id, name, description, default_action FROM policies ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []model.Policy
	for rows.Next() {
		var p model.Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.DefaultAction); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range policies {
		rules, err := s.getRules(policies[i].ID)
		if err != nil {
			return nil, err
		}
		policies[i].Rules = rules
	}
	return policies, nil
}

func (s *Store) GetPolicy(name string) (*model.Policy, error) {
	var p model.Policy
	err := s.db.QueryRow("SELECT id, name, description, default_action FROM policies WHERE name = ?", name).
		Scan(&p.ID, &p.Name, &p.Description, &p.DefaultAction)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rules, err := s.getRules(p.ID)
	if err != nil {
		return nil, err
	}
	p.Rules = rules
	return &p, nil
}

func (s *Store) CreatePolicy(p *model.Policy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO policies (name, description, default_action) VALUES (?, ?, ?)",
		p.Name, p.Description, p.DefaultAction)
	if err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}
	p.ID, _ = res.LastInsertId()

	for i := range p.Rules {
		p.Rules[i].PolicyID = p.ID
		if err := insertRule(tx, &p.Rules[i]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpdatePolicy(p *model.Policy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var id int64
	if err := tx.QueryRow("SELECT id FROM policies WHERE name = ?", p.Name).Scan(&id); err != nil {
		return err
	}

	if _, err := tx.Exec("UPDATE policies SET description = ?, default_action = ? WHERE id = ?",
		p.Description, p.DefaultAction, id); err != nil {
		return err
	}

	if _, err := tx.Exec("DELETE FROM rules WHERE policy_id = ?", id); err != nil {
		return err
	}
	for i := range p.Rules {
		p.Rules[i].PolicyID = id
		if err := insertRule(tx, &p.Rules[i]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeletePolicy(name string) error {
	_, err := s.db.Exec("DELETE FROM policies WHERE name = ?", name)
	return err
}

func (s *Store) CreateRule(policyName string, r *model.Rule) error {
	var policyID int64
	if err := s.db.QueryRow("SELECT id FROM policies WHERE name = ?", policyName).Scan(&policyID); err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}
	r.PolicyID = policyID

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := insertRule(tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteRule(id int64) error {
	_, err := s.db.Exec("DELETE FROM rules WHERE id = ?", id)
	return err
}

func insertRule(tx *sql.Tx, r *model.Rule) error {
	res, err := tx.Exec(
		`INSERT INTO rules (policy_id, "order", src_alias, dst_alias, protocol, ports, action, log, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.PolicyID, r.Order, r.SrcAlias, r.DstAlias, r.Protocol, r.Ports, r.Action, r.Log, r.Description,
	)
	if err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) getRules(policyID int64) ([]model.Rule, error) {
	rows, err := s.db.Query(
		`SELECT id, policy_id, "order", src_alias, dst_alias, protocol, ports, action, log, description FROM rules WHERE policy_id = ? ORDER BY "order"`,
		policyID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []model.Rule
	for rows.Next() {
		var r model.Rule
		if err := rows.Scan(&r.ID, &r.PolicyID, &r.Order, &r.SrcAlias, &r.DstAlias, &r.Protocol, &r.Ports, &r.Action, &r.Log, &r.Description); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}
