package config

import (
	"database/sql"
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

func (s *Store) ListAliases() ([]model.Alias, error) {
	rows, err := s.db.Query("SELECT id, name, type, description FROM aliases ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var aliases []model.Alias
	for rows.Next() {
		var a model.Alias
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Description); err != nil {
			return nil, err
		}
		aliases = append(aliases, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range aliases {
		members, err := s.getAliasMembers(aliases[i].ID)
		if err != nil {
			return nil, err
		}
		aliases[i].Members = members
	}
	return aliases, nil
}

func (s *Store) GetAlias(name string) (*model.Alias, error) {
	var a model.Alias
	err := s.db.QueryRow("SELECT id, name, type, description FROM aliases WHERE name = ?", name).
		Scan(&a.ID, &a.Name, &a.Type, &a.Description)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	members, err := s.getAliasMembers(a.ID)
	if err != nil {
		return nil, err
	}
	a.Members = members
	return &a, nil
}

func (s *Store) CreateAlias(a *model.Alias) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO aliases (name, type, description) VALUES (?, ?, ?)",
		a.Name, a.Type, a.Description)
	if err != nil {
		return fmt.Errorf("insert alias: %w", err)
	}
	a.ID, _ = res.LastInsertId()

	for _, m := range a.Members {
		if _, err := tx.Exec("INSERT INTO alias_members (alias_id, value) VALUES (?, ?)", a.ID, m); err != nil {
			return fmt.Errorf("insert alias member: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) UpdateAlias(a *model.Alias) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("UPDATE aliases SET type = ?, description = ? WHERE name = ?",
		a.Type, a.Description, a.Name); err != nil {
		return err
	}

	var id int64
	if err := tx.QueryRow("SELECT id FROM aliases WHERE name = ?", a.Name).Scan(&id); err != nil {
		return err
	}

	if _, err := tx.Exec("DELETE FROM alias_members WHERE alias_id = ?", id); err != nil {
		return err
	}
	for _, m := range a.Members {
		if _, err := tx.Exec("INSERT INTO alias_members (alias_id, value) VALUES (?, ?)", id, m); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteAlias(name string) error {
	_, err := s.db.Exec("DELETE FROM aliases WHERE name = ?", name)
	return err
}

func (s *Store) AddAliasMember(name, member string) error {
	var id int64
	if err := s.db.QueryRow("SELECT id FROM aliases WHERE name = ?", name).Scan(&id); err != nil {
		return fmt.Errorf("alias not found: %w", err)
	}
	_, err := s.db.Exec("INSERT OR IGNORE INTO alias_members (alias_id, value) VALUES (?, ?)", id, member)
	return err
}

func (s *Store) RemoveAliasMember(name, member string) error {
	var id int64
	if err := s.db.QueryRow("SELECT id FROM aliases WHERE name = ?", name).Scan(&id); err != nil {
		return fmt.Errorf("alias not found: %w", err)
	}
	_, err := s.db.Exec("DELETE FROM alias_members WHERE alias_id = ? AND value = ?", id, member)
	return err
}

// CheckAliasCycles detects cycles in nested aliases.
func (s *Store) CheckAliasCycles(name string) error {
	return s.checkCyclesDFS(name, make(map[string]bool))
}

func (s *Store) checkCyclesDFS(name string, visited map[string]bool) error {
	if visited[name] {
		return fmt.Errorf("alias cycle detected involving %q", name)
	}
	visited[name] = true

	a, err := s.GetAlias(name)
	if err != nil || a == nil {
		return err
	}
	if a.Type != model.AliasTypeNested {
		return nil
	}
	for _, member := range a.Members {
		if err := s.checkCyclesDFS(member, visited); err != nil {
			return err
		}
	}
	delete(visited, name)
	return nil
}

func (s *Store) getAliasMembers(aliasID int64) ([]string, error) {
	rows, err := s.db.Query("SELECT value FROM alias_members WHERE alias_id = ? ORDER BY id", aliasID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		members = append(members, v)
	}
	return members, rows.Err()
}
