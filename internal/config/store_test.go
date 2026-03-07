package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if store.DB() == nil {
		t.Fatal("DB() returned nil")
	}
}

func TestMigrate(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Running migrate again should be idempotent.
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate (idempotent): %v", err)
	}

	// Verify tables exist.
	tables := []string{"zones", "aliases", "alias_members", "policies", "rules", "profiles", "device_assignments", "config_revisions"}
	for _, table := range tables {
		var name string
		err := store.DB().QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestSeed(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if err := store.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	// Verify zones.
	var zoneCount int
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM zones").Scan(&zoneCount); err != nil {
		t.Fatalf("count zones: %v", err)
	}
	if zoneCount != 2 {
		t.Errorf("expected 2 zones, got %d", zoneCount)
	}

	// Verify policies.
	var policyCount int
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM policies").Scan(&policyCount); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policyCount != 2 {
		t.Errorf("expected 2 policies, got %d", policyCount)
	}

	// Verify profiles.
	var profileCount int
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM profiles").Scan(&profileCount); err != nil {
		t.Fatalf("count profiles: %v", err)
	}
	if profileCount != 2 {
		t.Errorf("expected 2 profiles, got %d", profileCount)
	}

	// Seed again should be no-op.
	if err := store.Seed(); err != nil {
		t.Fatalf("Seed (idempotent): %v", err)
	}
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM zones").Scan(&zoneCount); err != nil {
		t.Fatalf("count zones: %v", err)
	}
	if zoneCount != 2 {
		t.Errorf("expected 2 zones after re-seed, got %d", zoneCount)
	}
}

func TestNewStoreCreatesDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	dbPath := filepath.Join(nested, "test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(nested); err != nil {
		t.Errorf("directory not created: %v", err)
	}
}
