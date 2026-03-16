package inspect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MMDBUpdater manages automatic downloading and updating of ASN mmdb files.
// It follows the same lifecycle pattern as FeedScheduler:
//
//   - Periodic updates based on configurable TTL
//   - Last-known-good caching: failed downloads keep previous mmdb in place
//   - Hash-based skip: don't reload if the file hasn't changed
//   - Hot-reload: swaps the ASN resolver on the IOCStore without restart
//   - Graceful degradation: if download fails, ASN resolution stays on old data
//
// # Sources (in priority order)
//
// 1. MaxMind GeoLite2-ASN (requires free license key)
//   - Higher quality, weekly updates, ~7MB
//   - Register: https://www.maxmind.com/en/geolite2/signup
//   - Set GK_MAXMIND_LICENSE_KEY or pass via API
//
// 2. DB-IP Lite ASN (no key required, CC BY 4.0)
//   - Free, monthly updates, ~7MB
//   - https://db-ip.com/db/download/ip-to-asn-lite
//   - Works out of the box — this is the default
//
// When no license key is configured, the updater automatically uses DB-IP.
// When a license key is set, it switches to MaxMind.
type MMDBUpdater struct {
	mu sync.RWMutex

	// licenseKey is the MaxMind license key (optional).
	// When empty, uses the free DB-IP source instead.
	licenseKey string
	// dataDir is where mmdb files are stored.
	dataDir string
	// mmdbPath is the full path to the current mmdb file.
	mmdbPath string
	// store is the IOCStore to hot-reload the resolver into.
	store *IOCStore

	// Scheduling state.
	ttl       time.Duration
	lastFetch time.Time
	lastHash  string
	lastError string
	source    string // "dbip" or "maxmind"
	client    *http.Client
	stopCh    chan struct{}
	wg        sync.WaitGroup
	running   bool
}

// MMDBConfig holds configuration for the mmdb updater.
type MMDBConfig struct {
	// LicenseKey is the MaxMind license key (optional).
	// If empty, checks GK_MAXMIND_LICENSE_KEY environment variable.
	// If still empty, uses the free DB-IP source (no key needed).
	LicenseKey string `json:"license_key,omitempty"`
	// DataDir is the directory to store mmdb files. Default: /var/lib/gatekeeper/mmdb
	DataDir string `json:"data_dir,omitempty"`
	// TTL is how often to check for updates.
	// Default: 7 days for MaxMind, 30 days for DB-IP (matches their update cadence).
	TTL time.Duration `json:"ttl,omitempty"`
}

// MMDBStatus reports the current state of the mmdb updater.
type MMDBStatus struct {
	Source     string    `json:"source"`      // "dbip", "maxmind", or "none"
	Available  bool      `json:"available"`   // mmdb file exists and is loaded
	Path       string    `json:"path"`
	LastFetch  time.Time `json:"last_fetch,omitempty"`
	LastHash   string    `json:"last_hash,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	NextUpdate time.Time `json:"next_update,omitempty"`
	FileSize   int64     `json:"file_size,omitempty"`
	Running    bool      `json:"running"`
}

// DB-IP free ASN database URL.
// Updated monthly on the 1st. Format: plain .mmdb.gz (not tar.gz).
// License: CC BY 4.0 — attribution required but no key needed.
const dbipASNURL = "https://download.db-ip.com/free/dbip-asn-lite-%s.mmdb.gz"

// NewMMDBUpdater creates an mmdb updater.
// Works out of the box with no configuration — uses DB-IP free source by default.
func NewMMDBUpdater(cfg MMDBConfig, store *IOCStore) *MMDBUpdater {
	licenseKey := cfg.LicenseKey
	if licenseKey == "" {
		licenseKey = os.Getenv("GK_MAXMIND_LICENSE_KEY")
	}

	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/gatekeeper/mmdb"
	}

	source := "dbip"
	ttl := cfg.TTL
	mmdbName := "dbip-asn-lite.mmdb"

	if licenseKey != "" {
		source = "maxmind"
		mmdbName = "GeoLite2-ASN.mmdb"
		if ttl <= 0 {
			ttl = 7 * 24 * time.Hour // MaxMind updates weekly.
		}
	} else if ttl <= 0 {
		ttl = 30 * 24 * time.Hour // DB-IP updates monthly.
	}

	return &MMDBUpdater{
		licenseKey: licenseKey,
		dataDir:    dataDir,
		mmdbPath:   filepath.Join(dataDir, mmdbName),
		store:      store,
		ttl:        ttl,
		source:     source,
		client: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		stopCh: make(chan struct{}),
	}
}

// Start loads the existing mmdb from disk (if present) and begins
// the background update loop.
func (u *MMDBUpdater) Start() error {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return nil
	}
	u.running = true
	u.mu.Unlock()

	// Ensure data directory exists.
	os.MkdirAll(u.dataDir, 0750)

	// Load existing mmdb from disk.
	u.loadExisting()

	// Start background update loop.
	u.wg.Add(1)
	go u.updateLoop()

	slog.Info("mmdb updater started",
		"source", u.source,
		"ttl", u.ttl,
		"path", u.mmdbPath,
	)

	return nil
}

// Stop halts the background update loop.
func (u *MMDBUpdater) Stop() {
	u.mu.Lock()
	if !u.running {
		u.mu.Unlock()
		return
	}
	u.running = false
	close(u.stopCh)
	u.mu.Unlock()
	u.wg.Wait()
}

// SetLicenseKey sets a MaxMind license key and switches from DB-IP to MaxMind.
// Triggers an immediate download from MaxMind.
func (u *MMDBUpdater) SetLicenseKey(key string) {
	u.mu.Lock()
	u.licenseKey = key
	if key != "" {
		u.source = "maxmind"
		u.mmdbPath = filepath.Join(u.dataDir, "GeoLite2-ASN.mmdb")
		if u.ttl > 7*24*time.Hour {
			u.ttl = 7 * 24 * time.Hour // MaxMind has a faster cadence.
		}
	} else {
		u.source = "dbip"
		u.mmdbPath = filepath.Join(u.dataDir, "dbip-asn-lite.mmdb")
	}
	u.mu.Unlock()

	if key != "" {
		go u.doDownload()
	}
}

// ForceRefresh triggers an immediate download regardless of TTL.
func (u *MMDBUpdater) ForceRefresh() error {
	return u.doDownload()
}

// Status returns the current updater state.
func (u *MMDBUpdater) Status() MMDBStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()

	status := MMDBStatus{
		Source:    u.source,
		Path:     u.mmdbPath,
		LastFetch: u.lastFetch,
		LastHash:  u.lastHash,
		LastError: u.lastError,
		Running:  u.running,
	}

	if info, err := os.Stat(u.mmdbPath); err == nil {
		status.Available = true
		status.FileSize = info.Size()
	}

	if !u.lastFetch.IsZero() {
		status.NextUpdate = u.lastFetch.Add(u.ttl)
	}

	return status
}

// LoadFromPath loads an mmdb file from a specific path (manual placement).
func (u *MMDBUpdater) LoadFromPath(path string) error {
	resolver, err := NewMaxMindASNResolver(path)
	if err != nil {
		return fmt.Errorf("load mmdb: %w", err)
	}
	if resolver == nil {
		return fmt.Errorf("mmdb file not found: %s", path)
	}

	u.store.SetASNResolver(resolver)

	u.mu.Lock()
	u.mmdbPath = path
	u.mu.Unlock()

	slog.Info("mmdb loaded from path", "path", path)
	return nil
}

// --- Internal ---

func (u *MMDBUpdater) loadExisting() {
	resolver, err := NewMaxMindASNResolver(u.mmdbPath)
	if err != nil {
		slog.Warn("failed to load existing mmdb", "path", u.mmdbPath, "error", err)
		return
	}
	if resolver == nil {
		return
	}

	u.store.SetASNResolver(resolver)

	data, err := os.ReadFile(u.mmdbPath)
	if err == nil {
		u.lastHash = fmt.Sprintf("%x", sha256.Sum256(data))
	}

	slog.Info("loaded existing mmdb", "path", u.mmdbPath)
}

func (u *MMDBUpdater) updateLoop() {
	defer u.wg.Done()

	// Download immediately if no file exists.
	u.checkAndDownload()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-u.stopCh:
			return
		case <-ticker.C:
			u.checkAndDownload()
		}
	}
}

func (u *MMDBUpdater) checkAndDownload() {
	u.mu.RLock()
	lastFetch := u.lastFetch
	ttl := u.ttl
	u.mu.RUnlock()

	if time.Since(lastFetch) >= ttl {
		if err := u.doDownload(); err != nil {
			slog.Warn("mmdb download failed — keeping last-known-good",
				"error", err)
		}
	}
}

// doDownload dispatches to the correct download method based on source.
func (u *MMDBUpdater) doDownload() error {
	u.mu.RLock()
	source := u.source
	u.mu.RUnlock()

	switch source {
	case "maxmind":
		return u.downloadMaxMind()
	default:
		return u.downloadDBIP()
	}
}

// downloadDBIP fetches the free DB-IP ASN lite database.
// No license key required. File is a gzipped mmdb (not tar.gz).
func (u *MMDBUpdater) downloadDBIP() error {
	// DB-IP URL includes year-month: dbip-asn-lite-2026-03.mmdb.gz
	now := time.Now()
	url := fmt.Sprintf(dbipASNURL, now.Format("2006-01"))

	slog.Info("downloading DB-IP ASN lite", "url", url)

	body, err := u.fetchURL(url)
	if err != nil {
		return err
	}

	// Hash check — skip if unchanged.
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	u.mu.RLock()
	prevHash := u.lastHash
	u.mu.RUnlock()

	if hash == prevHash {
		u.mu.Lock()
		u.lastFetch = now
		u.lastError = ""
		u.mu.Unlock()
		slog.Info("mmdb unchanged, skipping reload", "hash", hash[:12])
		return nil
	}

	// Decompress gzip → raw mmdb.
	mmdbData, err := decompressGzip(body)
	if err != nil {
		u.setError(fmt.Sprintf("decompress failed: %v", err))
		return fmt.Errorf("decompress: %w", err)
	}

	return u.installMMDB(mmdbData, hash)
}

// downloadMaxMind fetches from MaxMind GeoLite2 (requires license key).
// File is a tar.gz containing the mmdb.
func (u *MMDBUpdater) downloadMaxMind() error {
	u.mu.RLock()
	key := u.licenseKey
	u.mu.RUnlock()

	if key == "" {
		return fmt.Errorf("no MaxMind license key")
	}

	edition := "GeoLite2-ASN"
	// Use query params for edition/suffix only; license key goes in the
	// Authorization header to avoid logging/caching credential exposure.
	url := fmt.Sprintf(
		"https://download.maxmind.com/app/geoip_download?edition_id=%s&suffix=tar.gz",
		edition,
	)

	slog.Info("downloading MaxMind GeoLite2-ASN")

	body, err := u.fetchURLWithAuth(url, key)
	if err != nil {
		return err
	}

	// Hash check.
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	u.mu.RLock()
	prevHash := u.lastHash
	u.mu.RUnlock()

	if hash == prevHash {
		u.mu.Lock()
		u.lastFetch = time.Now()
		u.lastError = ""
		u.mu.Unlock()
		slog.Info("mmdb unchanged, skipping reload", "hash", hash[:12])
		return nil
	}

	// Extract .mmdb from tar.gz.
	mmdbData, err := extractMMDB(body, edition)
	if err != nil {
		u.setError(fmt.Sprintf("extract failed: %v", err))
		return fmt.Errorf("extract: %w", err)
	}

	return u.installMMDB(mmdbData, hash)
}

// fetchURLWithAuth downloads a URL with a Basic auth header for the license key.
func (u *MMDBUpdater) fetchURLWithAuth(url, licenseKey string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		u.setError(fmt.Sprintf("create request failed: %v", err))
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth("", licenseKey)
	return u.doFetch(req)
}

// fetchURL downloads a URL with error handling common to both sources.
func (u *MMDBUpdater) fetchURL(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		u.setError(fmt.Sprintf("create request failed: %v", err))
		return nil, fmt.Errorf("create request: %w", err)
	}
	return u.doFetch(req)
}

func (u *MMDBUpdater) doFetch(req *http.Request) ([]byte, error) {
	resp, err := u.client.Do(req)
	if err != nil {
		u.setError(fmt.Sprintf("download failed: %v", err))
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		u.setError("invalid license key (HTTP 401)")
		return nil, fmt.Errorf("invalid license key (HTTP 401)")
	}

	if resp.StatusCode != http.StatusOK {
		u.setError(fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 100MB limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
	if err != nil {
		u.setError(fmt.Sprintf("read failed: %v", err))
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

// installMMDB validates the raw mmdb data, writes it to disk, and hot-reloads.
func (u *MMDBUpdater) installMMDB(mmdbData []byte, archiveHash string) error {
	u.mu.RLock()
	mmdbPath := u.mmdbPath
	u.mu.RUnlock()

	// Write to temp file.
	tmpPath := mmdbPath + ".tmp"
	if err := os.WriteFile(tmpPath, mmdbData, 0640); err != nil {
		u.setError(fmt.Sprintf("write failed: %v", err))
		return fmt.Errorf("write tmp: %w", err)
	}

	// Validate by loading.
	resolver, err := NewMaxMindASNResolver(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		u.setError(fmt.Sprintf("validation failed: %v", err))
		return fmt.Errorf("validate: %w", err)
	}
	if resolver == nil {
		os.Remove(tmpPath)
		u.setError("validation failed: resolver returned nil")
		return fmt.Errorf("validate: resolver nil")
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, mmdbPath); err != nil {
		os.Remove(tmpPath)
		u.setError(fmt.Sprintf("rename failed: %v", err))
		return fmt.Errorf("rename: %w", err)
	}

	// Hot-reload.
	u.store.SetASNResolver(resolver)

	u.mu.Lock()
	u.lastFetch = time.Now()
	u.lastHash = archiveHash
	u.lastError = ""
	u.mu.Unlock()

	slog.Info("mmdb updated and reloaded",
		"source", u.source,
		"size", len(mmdbData),
		"hash", archiveHash[:12],
	)

	return nil
}

func (u *MMDBUpdater) setError(msg string) {
	u.mu.Lock()
	u.lastError = msg
	u.mu.Unlock()
}

// decompressGzip decompresses a gzip-compressed byte slice.
// Used for DB-IP downloads which are plain .mmdb.gz files.
func decompressGzip(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gr.Close()

	// 100MB limit for the decompressed mmdb.
	out, err := io.ReadAll(io.LimitReader(gr, 100*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}
	return out, nil
}

// extractMMDB pulls the .mmdb file out of a MaxMind tar.gz archive.
// MaxMind packages the mmdb inside a directory like "GeoLite2-ASN_20240101/GeoLite2-ASN.mmdb".
func extractMMDB(tgzData []byte, edition string) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(tgzData))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	target := edition + ".mmdb"

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}

		base := filepath.Base(header.Name)
		if base == target && header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(io.LimitReader(tr, 100*1024*1024))
			if err != nil {
				return nil, fmt.Errorf("read mmdb: %w", err)
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("%s not found in archive", target)
}
