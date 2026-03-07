package config

import "encoding/json"

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	ResourceID string `json:"resource_id,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Source     string `json:"source"`
}

// LogAudit records a mutation in the audit log.
// The source parameter identifies the origin of the mutation ("api", "cli", etc.).
func (s *Store) LogAudit(source, action, resource, resourceID string, detail any) error {
	detailStr := ""
	if detail != nil {
		b, _ := json.Marshal(detail)
		detailStr = string(b)
	}
	_, err := s.db.Exec(
		"INSERT INTO audit_log (source, action, resource, resource_id, detail) VALUES (?, ?, ?, ?, ?)",
		source, action, resource, resourceID, detailStr,
	)
	return err
}

// ListAuditLog returns the most recent audit entries, up to limit.
func (s *Store) ListAuditLog(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(
		"SELECT id, timestamp, action, resource, resource_id, detail, source FROM audit_log ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &e.Resource, &e.ResourceID, &e.Detail, &e.Source); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
