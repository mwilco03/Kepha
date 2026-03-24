package config

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/mwilco03/kepha/internal/model"
)

// --- Content Filters ---

func (s *Store) ListContentFilters() ([]model.ContentFilter, error) {
	rows, err := s.db.Query(`
		SELECT id, name, zone_id, profile_id, blocked_categories, blocked_domains,
		       allowed_domains, enabled, description, created_at, updated_at
		FROM content_filters ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanContentFilters(rows)
}

func (s *Store) GetContentFilter(name string) (*model.ContentFilter, error) {
	row := s.db.QueryRow(`
		SELECT id, name, zone_id, profile_id, blocked_categories, blocked_domains,
		       allowed_domains, enabled, description, created_at, updated_at
		FROM content_filters WHERE name = ?
	`, name)

	cf, err := scanContentFilter(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return cf, nil
}

func (s *Store) CreateContentFilter(cf *model.ContentFilter) error {
	now := time.Now()
	cf.CreatedAt = now
	cf.UpdatedAt = now
	res, err := s.db.Exec(`
		INSERT INTO content_filters (name, zone_id, profile_id, blocked_categories,
			blocked_domains, allowed_domains, enabled, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cf.Name, cf.ZoneID, cf.ProfileID,
		joinCategories(cf.BlockedCategories), joinStrings(cf.BlockedDomains),
		joinStrings(cf.AllowedDomains), cf.Enabled, cf.Description, now, now)
	if err != nil {
		return fmt.Errorf("insert content filter: %w", err)
	}
	cf.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateContentFilter(cf *model.ContentFilter) error {
	cf.UpdatedAt = time.Now()
	_, err := s.db.Exec(`
		UPDATE content_filters SET zone_id = ?, profile_id = ?, blocked_categories = ?,
			blocked_domains = ?, allowed_domains = ?, enabled = ?, description = ?, updated_at = ?
		WHERE name = ?
	`, cf.ZoneID, cf.ProfileID,
		joinCategories(cf.BlockedCategories), joinStrings(cf.BlockedDomains),
		joinStrings(cf.AllowedDomains), cf.Enabled, cf.Description, cf.UpdatedAt, cf.Name)
	return err
}

func (s *Store) DeleteContentFilter(name string) error {
	_, err := s.db.Exec("DELETE FROM content_filters WHERE name = ?", name)
	return err
}

// --- Filter Exceptions ---

func (s *Store) CreateFilterException(ex *model.FilterException) error {
	now := time.Now()
	ex.CreatedAt = now
	ex.Status = model.ExceptionPending
	res, err := s.db.Exec(`
		INSERT INTO filter_exceptions (filter_id, domain, category, justification,
			requested_by, status, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, ex.FilterID, ex.Domain, ex.Category, ex.Justification,
		ex.RequestedBy, ex.Status, ex.ExpiresAt, now)
	if err != nil {
		return fmt.Errorf("insert exception: %w", err)
	}
	ex.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListFilterExceptions(filterID int64, status model.ExceptionStatus) ([]model.FilterException, error) {
	query := `SELECT id, filter_id, domain, category, justification, requested_by,
	                 status, approved_by, approval_note, expires_at, created_at, reviewed_at
	          FROM filter_exceptions WHERE 1=1`
	var args []any
	if filterID > 0 {
		query += " AND filter_id = ?"
		args = append(args, filterID)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, string(status))
	}
	query += " ORDER BY created_at DESC LIMIT 500"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanExceptions(rows)
}

func (s *Store) GetFilterException(id int64) (*model.FilterException, error) {
	row := s.db.QueryRow(`
		SELECT id, filter_id, domain, category, justification, requested_by,
		       status, approved_by, approval_note, expires_at, created_at, reviewed_at
		FROM filter_exceptions WHERE id = ?
	`, id)
	return scanException(row)
}

// ReviewFilterException approves or denies an exception. Only pending exceptions
// can be reviewed. This is the sole path to activating an exception — there is
// no auto-approve mechanism.
func (s *Store) ReviewFilterException(id int64, approved bool, reviewerID, note string) error {
	now := time.Now()
	status := model.ExceptionApproved
	if !approved {
		status = model.ExceptionDenied
	}

	res, err := s.db.Exec(`
		UPDATE filter_exceptions SET status = ?, approved_by = ?, approval_note = ?, reviewed_at = ?
		WHERE id = ? AND status = 'pending'
	`, status, reviewerID, note, now, id)
	if err != nil {
		return fmt.Errorf("review exception: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("exception %d not found or not pending", id)
	}
	return nil
}

// RevokeFilterException revokes a previously approved exception.
func (s *Store) RevokeFilterException(id int64, revokerID string) error {
	res, err := s.db.Exec(`
		UPDATE filter_exceptions SET status = 'revoked', approved_by = ?, reviewed_at = ?
		WHERE id = ? AND status = 'approved'
	`, revokerID, time.Now(), id)
	if err != nil {
		return fmt.Errorf("revoke exception: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("exception %d not found or not approved", id)
	}
	return nil
}

// ExpireFilterExceptions marks all approved exceptions past their expiry as expired.
func (s *Store) ExpireFilterExceptions() (int64, error) {
	res, err := s.db.Exec(`
		UPDATE filter_exceptions SET status = 'expired'
		WHERE status = 'approved' AND expires_at < ?
	`, time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ActiveExceptionsForFilter returns all approved, non-expired exceptions for a filter.
func (s *Store) ActiveExceptionsForFilter(filterID int64) ([]model.FilterException, error) {
	rows, err := s.db.Query(`
		SELECT id, filter_id, domain, category, justification, requested_by,
		       status, approved_by, approval_note, expires_at, created_at, reviewed_at
		FROM filter_exceptions
		WHERE filter_id = ? AND status = 'approved' AND expires_at > ?
		ORDER BY domain
	`, filterID, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanExceptions(rows)
}

// --- Scan helpers ---

func scanContentFilters(rows *sql.Rows) ([]model.ContentFilter, error) {
	var result []model.ContentFilter
	for rows.Next() {
		var cf model.ContentFilter
		var cats, blocked, allowed string
		var enabled int
		if err := rows.Scan(&cf.ID, &cf.Name, &cf.ZoneID, &cf.ProfileID,
			&cats, &blocked, &allowed, &enabled, &cf.Description,
			&cf.CreatedAt, &cf.UpdatedAt); err != nil {
			return nil, err
		}
		cf.Enabled = enabled != 0
		cf.BlockedCategories = splitCategories(cats)
		cf.BlockedDomains = splitStrings(blocked)
		cf.AllowedDomains = splitStrings(allowed)
		result = append(result, cf)
	}
	return result, rows.Err()
}

func scanContentFilter(row *sql.Row) (*model.ContentFilter, error) {
	var cf model.ContentFilter
	var cats, blocked, allowed string
	var enabled int
	err := row.Scan(&cf.ID, &cf.Name, &cf.ZoneID, &cf.ProfileID,
		&cats, &blocked, &allowed, &enabled, &cf.Description,
		&cf.CreatedAt, &cf.UpdatedAt)
	if err != nil {
		return nil, err
	}
	cf.Enabled = enabled != 0
	cf.BlockedCategories = splitCategories(cats)
	cf.BlockedDomains = splitStrings(blocked)
	cf.AllowedDomains = splitStrings(allowed)
	return &cf, nil
}

func scanExceptions(rows *sql.Rows) ([]model.FilterException, error) {
	var result []model.FilterException
	for rows.Next() {
		var ex model.FilterException
		var reviewedAt sql.NullTime
		if err := rows.Scan(&ex.ID, &ex.FilterID, &ex.Domain, &ex.Category,
			&ex.Justification, &ex.RequestedBy, &ex.Status, &ex.ApprovedBy,
			&ex.ApprovalNote, &ex.ExpiresAt, &ex.CreatedAt, &reviewedAt); err != nil {
			return nil, err
		}
		if reviewedAt.Valid {
			ex.ReviewedAt = reviewedAt.Time
		}
		result = append(result, ex)
	}
	return result, rows.Err()
}

func scanException(row *sql.Row) (*model.FilterException, error) {
	var ex model.FilterException
	var reviewedAt sql.NullTime
	err := row.Scan(&ex.ID, &ex.FilterID, &ex.Domain, &ex.Category,
		&ex.Justification, &ex.RequestedBy, &ex.Status, &ex.ApprovedBy,
		&ex.ApprovalNote, &ex.ExpiresAt, &ex.CreatedAt, &reviewedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if reviewedAt.Valid {
		ex.ReviewedAt = reviewedAt.Time
	}
	return &ex, nil
}

func joinCategories(cats []model.ContentCategory) string {
	s := make([]string, len(cats))
	for i, c := range cats {
		s[i] = string(c)
	}
	return strings.Join(s, ",")
}

func splitCategories(s string) []model.ContentCategory {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	cats := make([]model.ContentCategory, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cats = append(cats, model.ContentCategory(p))
		}
	}
	return cats
}

func joinStrings(ss []string) string {
	return strings.Join(ss, ",")
}

func splitStrings(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
