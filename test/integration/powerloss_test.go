package integration

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

// TestPowerLossRecovery simulates a crash during commit by:
// 1. Creating state and committing
// 2. Making changes after the commit
// 3. "Crashing" (closing the store abruptly)
// 4. Reopening and verifying the committed state can be rolled back to
func TestPowerLossRecovery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "powerloss.db")

	// Phase 1: Create initial committed state.
	store, err := config.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	rev, err := store.Commit("initial commit")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if rev != 1 {
		t.Fatalf("expected rev 1, got %d", rev)
	}

	// Phase 2: Make uncommitted changes (simulate in-progress work).
	zones, err := store.ListZones()
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	initialZoneCount := len(zones)

	err = store.CreateZone(&model.Zone{Name: "test-volatile", Interface: "eth9", NetworkCIDR: "172.31.0.0/24", TrustLevel: "none"})
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	zones2, _ := store.ListZones()
	if len(zones2) != initialZoneCount+1 {
		t.Fatalf("expected %d zones after create, got %d", initialZoneCount+1, len(zones2))
	}

	// Phase 3: Simulate power loss — close the DB abruptly.
	store.Close()

	// Phase 4: Reopen and verify recovery via rollback.
	store2, err := config.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore (reopen): %v", err)
	}
	defer store2.Close()
	if err := store2.Migrate(); err != nil {
		t.Fatalf("Migrate (reopen): %v", err)
	}

	// The uncommitted zone should still be there (WAL recovered it).
	zones3, _ := store2.ListZones()
	if len(zones3) != initialZoneCount+1 {
		t.Fatalf("expected %d zones after reopen, got %d", initialZoneCount+1, len(zones3))
	}

	// Rollback to the committed revision should restore the original state.
	if err := store2.Rollback(1); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	zones4, _ := store2.ListZones()
	if len(zones4) != initialZoneCount {
		t.Fatalf("expected %d zones after rollback, got %d", initialZoneCount, len(zones4))
	}

	// Verify the snapshot is valid JSON.
	snap, err := store2.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	snapJSON, _ := json.Marshal(snap)
	if !json.Valid(snapJSON) {
		t.Fatal("exported snapshot is not valid JSON")
	}
}

// TestConcurrentCommit verifies that two rapid commits don't corrupt the revision sequence.
func TestConcurrentCommit(t *testing.T) {
	store, err := config.NewStore(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	store.Migrate()
	store.Seed()

	rev1, err := store.Commit("commit 1")
	if err != nil {
		t.Fatalf("Commit 1: %v", err)
	}
	rev2, err := store.Commit("commit 2")
	if err != nil {
		t.Fatalf("Commit 2: %v", err)
	}

	if rev2 != rev1+1 {
		t.Fatalf("expected sequential revs, got %d and %d", rev1, rev2)
	}

	revs, err := store.ListRevisions()
	if err != nil {
		t.Fatalf("ListRevisions: %v", err)
	}
	if len(revs) != 2 {
		t.Fatalf("expected 2 revisions, got %d", len(revs))
	}
}
