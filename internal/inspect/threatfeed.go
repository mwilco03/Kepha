package inspect

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FeedScheduler manages automatic downloading and refreshing of threat
// intelligence feeds. It handles:
//
//   - Periodic feed updates based on configurable TTL
//   - Last-known-good caching: if a download fails, the previous version is kept
//   - Hash pinning: optionally validate feed SHA256 to detect tampering
//   - Graceful degradation: feed failures never crash the engine
//
// Pre-populated with the top 5 public threat intelligence feeds:
//  1. abuse.ch SSLBL (JA3 fingerprints of known malware C2)
//  2. abuse.ch Feodo Tracker (Feodo/Emotet/Dridex C2 IPs)
//  3. Proofpoint ET (Emerging Threats) compromised IPs
//  4. Blocklist.de (brute-force attackers)
//  5. CINS Army (Sentinel IPS bad actors)
type FeedScheduler struct {
	mu       sync.RWMutex
	engine   *Engine
	feeds    []*ManagedFeed
	cacheDir string
	client   *http.Client
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
}

// ManagedFeed wraps a ThreatFeed with scheduling and caching metadata.
type ManagedFeed struct {
	Feed       ThreatFeed    `json:"feed"`
	TTL        time.Duration `json:"ttl"`           // How often to refresh
	LastFetch  time.Time     `json:"last_fetch"`
	LastHash   string        `json:"last_hash"`     // SHA256 of last downloaded data
	PinHash    string        `json:"pin_hash"`      // If set, reject data that doesn't match
	LastError  string        `json:"last_error"`
	RetryCount int           `json:"retry_count"`
	CachePath  string        `json:"cache_path"`    // Local cache file
}

// FeedTemplate is a user-friendly description of a feed for adding custom feeds.
type FeedTemplate struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Format      string `json:"format"`       // "csv", "json", "line" (one hash per line)
	Description string `json:"description"`
	TTLMinutes  int    `json:"ttl_minutes"`
	HashColumn  int    `json:"hash_column"`  // For CSV: which column contains the hash (0-indexed)
	TypeColumn  int    `json:"type_column"`  // For CSV: which column contains the threat type
	NameColumn  int    `json:"name_column"`  // For CSV: which column contains the threat name
	SkipLines   int    `json:"skip_lines"`   // Number of header lines to skip
	Comment     string `json:"comment_char"` // Comment line prefix (e.g. "#")
}

// DefaultFeeds returns the top 5 pre-configured public threat feeds.
func DefaultFeeds() []*ManagedFeed {
	return []*ManagedFeed{
		{
			Feed: ThreatFeed{
				Name:    "abuse-ch-sslbl",
				URL:     "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
				Format:  "csv",
				Enabled: true,
				Hashes:  make(map[string]ThreatEntry),
			},
			TTL: 1 * time.Hour,
		},
		{
			Feed: ThreatFeed{
				Name:    "abuse-ch-feodo",
				URL:     "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
				Format:  "line",
				Enabled: true,
				Hashes:  make(map[string]ThreatEntry),
			},
			TTL: 30 * time.Minute,
		},
		{
			Feed: ThreatFeed{
				Name:    "et-compromised",
				URL:     "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
				Format:  "line",
				Enabled: true,
				Hashes:  make(map[string]ThreatEntry),
			},
			TTL: 4 * time.Hour,
		},
		{
			Feed: ThreatFeed{
				Name:    "blocklist-de",
				URL:     "https://lists.blocklist.de/lists/all.txt",
				Format:  "line",
				Enabled: true,
				Hashes:  make(map[string]ThreatEntry),
			},
			TTL: 2 * time.Hour,
		},
		{
			Feed: ThreatFeed{
				Name:    "cins-army",
				URL:     "https://cinsscore.com/list/ci-badguys.txt",
				Format:  "line",
				Enabled: true,
				Hashes:  make(map[string]ThreatEntry),
			},
			TTL: 6 * time.Hour,
		},
	}
}

// StubFeedTemplate returns a template for users to add custom feeds.
// This serves as documentation and a starting point for custom feed config.
func StubFeedTemplate() FeedTemplate {
	return FeedTemplate{
		Name:        "my-custom-feed",
		URL:         "https://example.com/threat-hashes.csv",
		Format:      "csv",
		Description: "Custom threat intelligence feed. Modify URL, format, and column mappings to match your feed provider.",
		TTLMinutes:  60,
		HashColumn:  0,
		TypeColumn:  1,
		NameColumn:  2,
		SkipLines:   1,
		Comment:     "#",
	}
}

// NewFeedScheduler creates a threat feed scheduler.
func NewFeedScheduler(engine *Engine, cacheDir string) *FeedScheduler {
	return &FeedScheduler{
		engine:   engine,
		feeds:    DefaultFeeds(),
		cacheDir: cacheDir,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		stopCh: make(chan struct{}),
	}
}

// AddFeed adds a custom feed from a template.
func (s *FeedScheduler) AddFeed(tmpl FeedTemplate) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ttl := time.Duration(tmpl.TTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	s.feeds = append(s.feeds, &ManagedFeed{
		Feed: ThreatFeed{
			Name:    tmpl.Name,
			URL:     tmpl.URL,
			Format:  tmpl.Format,
			Enabled: true,
			Hashes:  make(map[string]ThreatEntry),
		},
		TTL: ttl,
	})
}

// RemoveFeed removes a feed by name.
func (s *FeedScheduler) RemoveFeed(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, f := range s.feeds {
		if f.Feed.Name == name {
			s.feeds = append(s.feeds[:i], s.feeds[i+1:]...)
			return true
		}
	}
	return false
}

// ListFeeds returns metadata for all configured feeds.
func (s *FeedScheduler) ListFeeds() []ManagedFeed {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ManagedFeed, len(s.feeds))
	for i, f := range s.feeds {
		result[i] = *f
		result[i].Feed.Hashes = nil // Don't return full hash maps.
		result[i].Feed.EntryCount = len(f.Feed.Hashes)
	}
	return result
}

// Start begins the background feed update loop.
func (s *FeedScheduler) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	// Ensure cache directory exists.
	if s.cacheDir != "" {
		os.MkdirAll(s.cacheDir, 0750)
	}

	// Initial load from cache.
	s.loadAllFromCache()

	// Initial fetch of all feeds.
	s.refreshAll()

	// Background update loop.
	s.wg.Add(1)
	go s.updateLoop()

	return nil
}

// Stop halts the background update loop.
func (s *FeedScheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()
	s.wg.Wait()
}

// ForceRefresh triggers an immediate refresh of all feeds.
func (s *FeedScheduler) ForceRefresh() {
	s.refreshAll()
}

func (s *FeedScheduler) updateLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndRefresh()
		}
	}
}

// checkAndRefresh refreshes feeds whose TTL has expired.
func (s *FeedScheduler) checkAndRefresh() {
	s.mu.RLock()
	feeds := make([]*ManagedFeed, len(s.feeds))
	copy(feeds, s.feeds)
	s.mu.RUnlock()

	now := time.Now()
	for _, feed := range feeds {
		if !feed.Feed.Enabled {
			continue
		}
		if now.Sub(feed.LastFetch) >= feed.TTL {
			s.fetchFeed(feed)
		}
	}
}

func (s *FeedScheduler) refreshAll() {
	s.mu.RLock()
	feeds := make([]*ManagedFeed, len(s.feeds))
	copy(feeds, s.feeds)
	s.mu.RUnlock()

	for _, feed := range feeds {
		if feed.Feed.Enabled {
			s.fetchFeed(feed)
		}
	}
}

// fetchFeed downloads and parses a single threat feed.
func (s *FeedScheduler) fetchFeed(mf *ManagedFeed) {
	slog.Info("fetching threat feed", "name", mf.Feed.Name)

	resp, err := s.client.Get(mf.Feed.URL)
	if err != nil {
		mf.LastError = "download failed"
		mf.RetryCount++
		slog.Warn("threat feed download failed — keeping last-known-good",
			"name", mf.Feed.Name, "retries", mf.RetryCount)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		mf.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		mf.RetryCount++
		slog.Warn("threat feed HTTP error — keeping last-known-good",
			"name", mf.Feed.Name, "status", resp.StatusCode)
		return
	}

	// Read body with size limit (50 MB).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		mf.LastError = fmt.Sprintf("read failed: %v", err)
		mf.RetryCount++
		return
	}

	// Hash check for integrity / pinning.
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	if mf.PinHash != "" && hash != mf.PinHash {
		mf.LastError = fmt.Sprintf("hash mismatch: got %s, pinned %s", hash, mf.PinHash)
		mf.RetryCount++
		slog.Error("threat feed hash pin violation — rejecting update",
			"name", mf.Feed.Name, "got", hash, "pinned", mf.PinHash)
		return
	}

	// Skip update if content hasn't changed.
	if hash == mf.LastHash {
		mf.LastFetch = time.Now()
		mf.RetryCount = 0
		return
	}

	// Parse the feed.
	entries, err := s.parseFeed(mf.Feed.Format, body, mf.Feed.Name)
	if err != nil {
		mf.LastError = fmt.Sprintf("parse failed: %v", err)
		mf.RetryCount++
		slog.Warn("threat feed parse failed — keeping last-known-good",
			"name", mf.Feed.Name, "error", err)
		return
	}

	// Apply to engine — atomically replace the feed's hash map.
	s.mu.Lock()
	mf.Feed.Hashes = entries
	mf.Feed.EntryCount = len(entries)
	mf.Feed.LastUpdate = time.Now()
	mf.LastFetch = time.Now()
	mf.LastHash = hash
	mf.LastError = ""
	mf.RetryCount = 0
	s.mu.Unlock()

	// Update the engine's threat feeds.
	s.syncToEngine()

	// Cache to disk.
	s.cacheFeed(mf, body)

	slog.Info("threat feed updated",
		"name", mf.Feed.Name,
		"entries", len(entries),
		"hash", hash[:12],
	)
}

// maxFeedEntries caps the number of entries a single feed can contribute
// to prevent memory exhaustion from a poisoned or oversized feed.
const maxFeedEntries = 500000

// parseFeed parses feed data based on format.
func (s *FeedScheduler) parseFeed(format string, data []byte, feedName string) (map[string]ThreatEntry, error) {
	entries := make(map[string]ThreatEntry)

	switch format {
	case "csv":
		return s.parseCSV(data, feedName)
	case "json":
		return s.parseJSON(data, feedName)
	case "line":
		return s.parseLine(data, feedName)
	default:
		return entries, fmt.Errorf("unknown feed format: %q", format)
	}
}

// parseCSV parses abuse.ch-style CSV: hash,threat_type,threat_name
func (s *FeedScheduler) parseCSV(data []byte, feedName string) (map[string]ThreatEntry, error) {
	entries := make(map[string]ThreatEntry)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 1 {
			continue
		}

		hash := strings.TrimSpace(parts[0])
		if hash == "" || hash == "Listingdate" { // Skip header.
			continue
		}

		entry := ThreatEntry{
			Hash:       hash,
			ThreatType: "malware",
			Severity:   "high",
		}

		if len(parts) >= 2 {
			entry.ThreatType = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 {
			entry.ThreatName = strings.TrimSpace(parts[2])
		}

		entries[hash] = entry
		if len(entries) >= maxFeedEntries {
			slog.Warn("feed entry limit reached, truncating", "name", feedName, "limit", maxFeedEntries)
			break
		}
	}

	return entries, scanner.Err()
}

// parseJSON parses JSON array feeds.
func (s *FeedScheduler) parseJSON(data []byte, feedName string) (map[string]ThreatEntry, error) {
	entries := make(map[string]ThreatEntry)

	var records []struct {
		Hash       string `json:"hash"`
		JA3        string `json:"ja3"`        // Some feeds use "ja3" key.
		Fingerprint string `json:"fingerprint"` // Others use "fingerprint".
		ThreatType string `json:"threat_type"`
		ThreatName string `json:"threat_name"`
		Malware    string `json:"malware"`
		Severity   string `json:"severity"`
	}

	if err := json.Unmarshal(data, &records); err != nil {
		return entries, fmt.Errorf("JSON parse: %w", err)
	}

	for _, r := range records {
		hash := r.Hash
		if hash == "" {
			hash = r.JA3
		}
		if hash == "" {
			hash = r.Fingerprint
		}
		if hash == "" {
			continue
		}

		threatName := r.ThreatName
		if threatName == "" {
			threatName = r.Malware
		}

		entries[hash] = ThreatEntry{
			Hash:       hash,
			ThreatType: r.ThreatType,
			ThreatName: threatName,
			Severity:   r.Severity,
		}
		if len(entries) >= maxFeedEntries {
			slog.Warn("feed entry limit reached, truncating", "name", feedName, "limit", maxFeedEntries)
			break
		}
	}

	return entries, nil
}

// parseLine parses one-entry-per-line feeds (IPs or hashes).
func (s *FeedScheduler) parseLine(data []byte, feedName string) (map[string]ThreatEntry, error) {
	entries := make(map[string]ThreatEntry)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Some feeds have comments after a semicolon.
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		// Basic validation: skip entries that don't look like IPs or hashes.
		if net.ParseIP(line) == nil && !isHexString(line) {
			continue
		}

		entries[line] = ThreatEntry{
			Hash:       line,
			ThreatType: "blocklist",
			ThreatName: feedName,
			Severity:   "medium",
		}
		if len(entries) >= maxFeedEntries {
			slog.Warn("feed entry limit reached, truncating", "name", feedName, "limit", maxFeedEntries)
			break
		}
	}

	return entries, scanner.Err()
}

// isHexString returns true if s looks like a hex-encoded hash (32-128 hex chars).
func isHexString(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// syncToEngine pushes all enabled feeds into the engine.
func (s *FeedScheduler) syncToEngine() {
	s.mu.RLock()
	var feeds []ThreatFeed
	for _, mf := range s.feeds {
		if mf.Feed.Enabled && len(mf.Feed.Hashes) > 0 {
			feeds = append(feeds, mf.Feed)
		}
	}
	s.mu.RUnlock()

	if s.engine != nil {
		s.engine.SetThreatFeeds(feeds)
	}
}

// cacheFeed writes feed data to disk for last-known-good caching.
func (s *FeedScheduler) cacheFeed(mf *ManagedFeed, data []byte) {
	if s.cacheDir == "" {
		return
	}

	path := filepath.Join(s.cacheDir, mf.Feed.Name+".dat")
	if err := os.WriteFile(path, data, 0640); err != nil {
		slog.Warn("failed to cache threat feed", "name", mf.Feed.Name, "error", err)
		return
	}
	mf.CachePath = path

	// Also write metadata.
	meta := struct {
		Name       string    `json:"name"`
		URL        string    `json:"url"`
		Format     string    `json:"format"`
		LastFetch  time.Time `json:"last_fetch"`
		LastHash   string    `json:"last_hash"`
		EntryCount int       `json:"entry_count"`
	}{
		Name:       mf.Feed.Name,
		URL:        mf.Feed.URL,
		Format:     mf.Feed.Format,
		LastFetch:  mf.LastFetch,
		LastHash:   mf.LastHash,
		EntryCount: len(mf.Feed.Hashes),
	}
	metaData, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(s.cacheDir, mf.Feed.Name+".meta.json"), metaData, 0640)
}

// loadAllFromCache restores feeds from last-known-good cache files.
func (s *FeedScheduler) loadAllFromCache() {
	if s.cacheDir == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, mf := range s.feeds {
		path := filepath.Join(s.cacheDir, mf.Feed.Name+".dat")
		data, err := os.ReadFile(path)
		if err != nil {
			continue // No cache file — will be fetched.
		}

		// Read metadata first so we can verify cache integrity.
		metaPath := filepath.Join(s.cacheDir, mf.Feed.Name+".meta.json")
		var meta struct {
			LastFetch time.Time `json:"last_fetch"`
			LastHash  string    `json:"last_hash"`
		}
		if metaData, err := os.ReadFile(metaPath); err == nil {
			json.Unmarshal(metaData, &meta)
		}

		// Verify cache integrity: if we have a stored hash, validate it.
		if meta.LastHash != "" {
			cacheHash := fmt.Sprintf("%x", sha256.Sum256(data))
			if cacheHash != meta.LastHash {
				slog.Warn("cached feed integrity check failed — discarding",
					"name", mf.Feed.Name, "expected", meta.LastHash, "got", cacheHash)
				continue
			}
		}

		entries, err := s.parseFeed(mf.Feed.Format, data, mf.Feed.Name)
		if err != nil {
			slog.Warn("cached feed parse failed", "name", mf.Feed.Name, "error", err)
			continue
		}

		mf.Feed.Hashes = entries
		mf.Feed.EntryCount = len(entries)
		mf.CachePath = path
		mf.LastFetch = meta.LastFetch
		mf.LastHash = meta.LastHash

		slog.Info("loaded threat feed from cache",
			"name", mf.Feed.Name,
			"entries", len(entries),
		)
	}
}
