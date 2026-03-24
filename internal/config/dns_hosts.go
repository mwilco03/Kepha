package config

import (
	"fmt"
	"time"
)

// DNSHost represents a manual DNS host override (A, AAAA, or CNAME record).
type DNSHost struct {
	ID          int64  `json:"id"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RecordType  string `json:"record_type"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at,omitempty"`
}

func (s *Store) ListDNSHosts() ([]DNSHost, error) {
	rows, err := s.db.Query("SELECT id, hostname, domain, record_type, value, description, enabled, created_at FROM dns_hosts ORDER BY hostname")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []DNSHost
	for rows.Next() {
		var h DNSHost
		var enabled int
		if err := rows.Scan(&h.ID, &h.Hostname, &h.Domain, &h.RecordType, &h.Value, &h.Description, &enabled, &h.CreatedAt); err != nil {
			return nil, err
		}
		h.Enabled = enabled == 1
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

func (s *Store) CreateDNSHost(h *DNSHost) error {
	if h.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if h.Value == "" {
		return fmt.Errorf("value (IP or target) is required")
	}
	if h.RecordType == "" {
		h.RecordType = "A"
	}
	enabled := 0
	if h.Enabled {
		enabled = 1
	}
	res, err := s.db.Exec(
		"INSERT INTO dns_hosts (hostname, domain, record_type, value, description, enabled) VALUES (?, ?, ?, ?, ?, ?)",
		h.Hostname, h.Domain, h.RecordType, h.Value, h.Description, enabled,
	)
	if err != nil {
		return fmt.Errorf("insert dns host: %w", err)
	}
	h.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateDNSHost(h *DNSHost) error {
	enabled := 0
	if h.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		"UPDATE dns_hosts SET hostname=?, domain=?, record_type=?, value=?, description=?, enabled=? WHERE id=?",
		h.Hostname, h.Domain, h.RecordType, h.Value, h.Description, enabled, h.ID,
	)
	return err
}

func (s *Store) DeleteDNSHost(id int64) error {
	_, err := s.db.Exec("DELETE FROM dns_hosts WHERE id=?", id)
	return err
}

// DNSFeed represents a blocklist feed subscription.
type DNSFeed struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Category        string `json:"category"`
	Enabled         bool   `json:"enabled"`
	EntryCount      int    `json:"entry_count"`
	LastUpdated     string `json:"last_updated,omitempty"`
	UpdateInterval  int    `json:"update_interval_sec"`
	Description     string `json:"description"`
	CreatedAt       string `json:"created_at,omitempty"`
}

func (s *Store) ListDNSFeeds() ([]DNSFeed, error) {
	rows, err := s.db.Query("SELECT id, name, url, category, enabled, entry_count, last_updated, update_interval_sec, description, created_at FROM dns_feeds ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feeds []DNSFeed
	for rows.Next() {
		var f DNSFeed
		var enabled int
		var lastUpdated *string
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Category, &enabled, &f.EntryCount, &lastUpdated, &f.UpdateInterval, &f.Description, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.Enabled = enabled == 1
		if lastUpdated != nil {
			f.LastUpdated = *lastUpdated
		}
		feeds = append(feeds, f)
	}
	return feeds, rows.Err()
}

func (s *Store) GetDNSFeed(name string) (*DNSFeed, error) {
	var f DNSFeed
	var enabled int
	var lastUpdated *string
	err := s.db.QueryRow(
		"SELECT id, name, url, category, enabled, entry_count, last_updated, update_interval_sec, description, created_at FROM dns_feeds WHERE name=?", name,
	).Scan(&f.ID, &f.Name, &f.URL, &f.Category, &enabled, &f.EntryCount, &lastUpdated, &f.UpdateInterval, &f.Description, &f.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("feed %q: %w", name, err)
	}
	f.Enabled = enabled == 1
	if lastUpdated != nil {
		f.LastUpdated = *lastUpdated
	}
	return &f, nil
}

func (s *Store) EnableDNSFeed(name string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec("UPDATE dns_feeds SET enabled=? WHERE name=?", v, name)
	return err
}

func (s *Store) UpdateDNSFeedStats(name string, entryCount int) error {
	_, err := s.db.Exec(
		"UPDATE dns_feeds SET entry_count=?, last_updated=? WHERE name=?",
		entryCount, time.Now().UTC().Format(time.RFC3339), name,
	)
	return err
}

// DNSBlockEntry is a single entry in the DNS block log.
type DNSBlockEntry struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	ClientIP  string `json:"client_ip"`
	FeedName  string `json:"feed_name"`
	BlockedAt string `json:"blocked_at"`
}

func (s *Store) LogDNSBlock(domain, clientIP, feedName string) error {
	_, err := s.db.Exec(
		"INSERT INTO dns_block_log (domain, client_ip, feed_name) VALUES (?, ?, ?)",
		domain, clientIP, feedName,
	)
	return err
}

// ListBlockedDomains returns the most frequently blocked domains, most recent first.
func (s *Store) ListBlockedDomains(limit int) ([]struct {
	Domain    string `json:"domain"`
	Count     int    `json:"count"`
	FeedName  string `json:"feed_name"`
	LastSeen  string `json:"last_seen"`
}, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(`
		SELECT domain, COUNT(*) as cnt, feed_name, MAX(blocked_at) as last_seen
		FROM dns_block_log
		GROUP BY domain
		ORDER BY cnt DESC, last_seen DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []struct {
		Domain    string `json:"domain"`
		Count     int    `json:"count"`
		FeedName  string `json:"feed_name"`
		LastSeen  string `json:"last_seen"`
	}
	for rows.Next() {
		var r struct {
			Domain    string `json:"domain"`
			Count     int    `json:"count"`
			FeedName  string `json:"feed_name"`
			LastSeen  string `json:"last_seen"`
		}
		if err := rows.Scan(&r.Domain, &r.Count, &r.FeedName, &r.LastSeen); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// AllowBlockedDomain adds a domain to the DNS allowlist by creating
// a disabled dns_host entry that the filter engine can check.
func (s *Store) AllowBlockedDomain(domain string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO dns_hosts (hostname, domain, record_type, value, description, enabled)
		 VALUES (?, '', 'ALLOW', 'passthrough', 'Unblocked from block log', 1)`,
		domain,
	)
	return err
}

// PruneDNSBlockLog removes entries older than the given number of days.
func (s *Store) PruneDNSBlockLog(retentionDays int) error {
	_, err := s.db.Exec(
		"DELETE FROM dns_block_log WHERE blocked_at < datetime('now', '-' || ? || ' days')",
		retentionDays,
	)
	return err
}
