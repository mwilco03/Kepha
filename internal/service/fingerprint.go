package service

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/mwilco03/kepha/internal/inspect"
)

// FingerprintService provides passive TLS fingerprinting and device profiling.
//
// When enabled, it captures TLS ClientHello packets on configured interfaces,
// extracts JA4/JA4S/JA4T/JA4H fingerprints, and stores observations in
// the fingerprint database. It can match fingerprints against known device
// profiles and threat intelligence feeds.
//
// Architecture for scale:
//   - Threat feeds use a merged index: O(1) lookup regardless of feed count
//   - Feed updates rebuild the index in background, swap atomically
//   - AF_PACKET capture with kernel-level BPF filter: only TLS packets cross user/kernel boundary
//   - Anomaly detection uses in-memory history with SQLite persistence
//
// This service is entirely opt-in. When disabled, zero CPU overhead.
type FingerprintService struct {
	mu        sync.Mutex
	state     State
	cfg       map[string]string
	engine    *inspect.Engine
	store     *inspect.SQLiteStore
	db        *sql.DB
	capturer  *inspect.Capturer
	feedSched *inspect.FeedScheduler
	anomaly   *inspect.AnomalyDetector
	stopCh    chan struct{}
}

// NewFingerprintService creates a new fingerprint service.
// The db parameter is used to persist observed fingerprints.
func NewFingerprintService(db *sql.DB) *FingerprintService {
	return &FingerprintService{
		state: StateStopped,
		db:    db,
	}
}

func (f *FingerprintService) Name() string        { return "fingerprint" }
func (f *FingerprintService) DisplayName() string  { return "TLS Fingerprint Engine" }
func (f *FingerprintService) Category() string     { return "security" }
func (f *FingerprintService) Dependencies() []string { return nil }

func (f *FingerprintService) Description() string {
	return "Passive JA4+ TLS fingerprinting and device profiling. Extracts JA4/JA4S/JA4T/JA4H fingerprints from network traffic for device identification and threat detection. Includes AF_PACKET live capture, threat feed auto-download, and fingerprint change anomaly detection."
}

func (f *FingerprintService) DefaultConfig() map[string]string {
	return map[string]string{
		"interfaces":       "",     // Comma-separated interfaces to monitor (empty = all non-loopback)
		"capture_method":   "auto", // "auto", "af_packet", "pcap"
		"bpf_filter":       "tcp port 443", // BPF filter for capture
		"threat_feeds":     "",     // Comma-separated threat feed URLs
		"auto_block":       "false", // Auto-block connections matching threat feeds
		"max_entries":      "100000", // Max fingerprint entries to store
		"anomaly_detection": "true",  // Enable fingerprint change detection
		"feed_cache_dir":   "/var/lib/gatekeeper/cache/feeds", // Cache dir for last-known-good feeds
		"live_capture":     "true",  // Enable AF_PACKET live capture
	}
}

func (f *FingerprintService) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"interfaces": {
			Description: "Comma-separated list of interfaces to monitor for TLS traffic. Empty = all non-loopback interfaces.",
			Default:     "",
			Type:        "string",
		},
		"capture_method": {
			Description: "Packet capture method: auto (best available), af_packet (Linux raw socket), pcap (libpcap).",
			Default:     "auto",
			Type:        "string",
		},
		"bpf_filter": {
			Description: "BPF filter expression for packet capture. Default captures TLS on port 443.",
			Default:     "tcp port 443",
			Type:        "string",
		},
		"threat_feeds": {
			Description: "Comma-separated URLs of JA4/JA3 threat intelligence feeds (abuse.ch, Proofpoint ET format).",
			Default:     "",
			Type:        "string",
		},
		"auto_block": {
			Description: "Automatically block connections matching threat feed fingerprints.",
			Default:     "false",
			Type:        "bool",
		},
		"max_entries": {
			Description: "Maximum number of fingerprint entries to store in the database.",
			Default:     "100000",
			Type:        "int",
		},
		"anomaly_detection": {
			Description: "Enable fingerprint change anomaly detection. Alerts when a device's TLS fingerprint changes unexpectedly.",
			Default:     "true",
			Type:        "bool",
		},
		"feed_cache_dir": {
			Description: "Directory for caching threat feed data. Enables last-known-good fallback on download failure.",
			Default:     "/var/lib/gatekeeper/cache/feeds",
			Type:        "path",
		},
		"live_capture": {
			Description: "Enable AF_PACKET live packet capture for real-time fingerprinting.",
			Default:     "true",
			Type:        "bool",
		},
	}
}

func (f *FingerprintService) Validate(cfg map[string]string) error {
	if method, ok := cfg["capture_method"]; ok {
		switch method {
		case "auto", "af_packet", "pcap":
		default:
			return fmt.Errorf("invalid capture_method: %q (must be auto, af_packet, or pcap)", method)
		}
	}
	if autoBlock, ok := cfg["auto_block"]; ok {
		if autoBlock != "true" && autoBlock != "false" {
			return fmt.Errorf("auto_block must be true or false")
		}
	}
	return nil
}

func (f *FingerprintService) Start(cfg map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.state == StateRunning {
		return nil
	}

	f.cfg = cfg

	// Initialize fingerprint store.
	if f.db != nil {
		store, err := inspect.NewSQLiteStore(f.db)
		if err != nil {
			return fmt.Errorf("fingerprint store: %w", err)
		}
		f.store = store
		f.engine = inspect.NewEngine(store)
	} else {
		f.engine = inspect.NewEngine(nil)
	}

	f.stopCh = make(chan struct{})

	// Start threat feed scheduler with pre-populated feeds.
	cacheDir := cfg["feed_cache_dir"]
	if cacheDir == "" {
		cacheDir = "/var/lib/gatekeeper/cache/feeds"
	}
	f.feedSched = inspect.NewFeedScheduler(f.engine, cacheDir)
	if err := f.feedSched.Start(); err != nil {
		slog.Warn("threat feed scheduler failed to start", "error", err)
		// Non-fatal — fingerprinting works without feeds.
	}

	// Initialize anomaly detection.
	if cfg["anomaly_detection"] != "false" {
		anomaly, err := inspect.NewAnomalyDetector(f.db)
		if err != nil {
			slog.Warn("anomaly detector failed to initialize", "error", err)
		} else {
			f.anomaly = anomaly
		}
	}

	// Start live AF_PACKET capture.
	if cfg["live_capture"] != "false" {
		ifaces := parseIfaceList(cfg["interfaces"])
		if len(ifaces) == 0 {
			ifaces = detectUpInterfaces()
		}
		if len(ifaces) > 0 {
			f.capturer = inspect.NewCapturer(f.engine, ifaces, cfg["bpf_filter"])
			if err := f.capturer.Start(); err != nil {
				slog.Warn("AF_PACKET capture failed to start", "error", err)
				// Non-fatal — API-based fingerprinting still works.
				f.capturer = nil
			}
		}
	}

	slog.Info("fingerprint engine started",
		"interfaces", cfg["interfaces"],
		"capture_method", cfg["capture_method"],
		"anomaly_detection", cfg["anomaly_detection"] != "false",
		"live_capture", cfg["live_capture"] != "false",
	)

	f.state = StateRunning
	return nil
}

func (f *FingerprintService) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.state != StateRunning {
		return nil
	}

	// Stop capture first.
	if f.capturer != nil {
		f.capturer.Stop()
		f.capturer = nil
	}

	// Stop feed scheduler.
	if f.feedSched != nil {
		f.feedSched.Stop()
		f.feedSched = nil
	}

	if f.stopCh != nil {
		close(f.stopCh)
	}

	slog.Info("fingerprint engine stopped")
	f.state = StateStopped
	return nil
}

func (f *FingerprintService) Reload(cfg map[string]string) error {
	if err := f.Stop(); err != nil {
		return err
	}
	return f.Start(cfg)
}

func (f *FingerprintService) Status() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// Engine returns the fingerprint engine for direct access (e.g. from API handlers).
func (f *FingerprintService) Engine() *inspect.Engine {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.engine
}

// Store returns the fingerprint store for direct access.
func (f *FingerprintService) Store() *inspect.SQLiteStore {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.store
}

// AnomalyDetector returns the anomaly detector for direct access.
func (f *FingerprintService) AnomalyDetector() *inspect.AnomalyDetector {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.anomaly
}

// FeedScheduler returns the feed scheduler for direct access.
func (f *FingerprintService) FeedScheduler() *inspect.FeedScheduler {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.feedSched
}

// CaptureStats returns live capture statistics.
func (f *FingerprintService) CaptureStats() *inspect.CaptureStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.capturer == nil {
		return nil
	}
	stats := f.capturer.Stats()
	return &stats
}

func parseIfaceList(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name != "" {
			result = append(result, name)
		}
	}
	return result
}

func detectUpInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		result = append(result, iface.Name)
	}
	return result
}
