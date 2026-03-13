package service

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gatekeeper-firewall/gatekeeper/internal/inspect"
)

// FingerprintService provides passive TLS fingerprinting and device profiling.
//
// When enabled, it captures TLS ClientHello packets on configured interfaces,
// extracts JA4/JA4S/JA4T/JA4H fingerprints, and stores observations in
// the fingerprint database. It can match fingerprints against known device
// profiles and threat intelligence feeds.
//
// This service is entirely opt-in. When disabled, zero CPU overhead.
type FingerprintService struct {
	mu     sync.Mutex
	state  State
	cfg    map[string]string
	engine *inspect.Engine
	store  *inspect.SQLiteStore
	db     *sql.DB
	stopCh chan struct{}
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
	return "Passive JA4+ TLS fingerprinting and device profiling. Extracts JA4/JA4S/JA4T/JA4H fingerprints from network traffic for device identification and threat detection."
}

func (f *FingerprintService) DefaultConfig() map[string]string {
	return map[string]string{
		"interfaces":     "",     // Comma-separated interfaces to monitor (empty = all non-loopback)
		"capture_method": "auto", // "auto", "af_packet", "pcap"
		"bpf_filter":     "tcp port 443", // BPF filter for capture
		"threat_feeds":   "",     // Comma-separated threat feed URLs
		"auto_block":     "false", // Auto-block connections matching threat feeds
		"max_entries":    "100000", // Max fingerprint entries to store
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

	slog.Info("fingerprint engine started",
		"interfaces", cfg["interfaces"],
		"capture_method", cfg["capture_method"],
		"bpf_filter", cfg["bpf_filter"],
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
