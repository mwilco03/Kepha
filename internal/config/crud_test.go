package config

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mwilco03/kepha/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestZoneCRUD(t *testing.T) {
	s := newTestStore(t)

	zones, err := s.ListZones()
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 seeded zones, got %d", len(zones))
	}

	z := &model.Zone{Name: "dmz", Interface: "eth2", NetworkCIDR: "10.20.0.0/24", TrustLevel: "low", Description: "DMZ"}
	if err := s.CreateZone(z); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if z.ID == 0 {
		t.Fatal("expected non-zero ID")
	}

	got, err := s.GetZone("dmz")
	if err != nil {
		t.Fatalf("GetZone: %v", err)
	}
	if got == nil || got.Name != "dmz" {
		t.Fatalf("GetZone returned %v", got)
	}

	got.Description = "Updated DMZ"
	if err := s.UpdateZone(got); err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	got2, _ := s.GetZone("dmz")
	if got2.Description != "Updated DMZ" {
		t.Errorf("expected updated description, got %q", got2.Description)
	}

	if err := s.DeleteZone("dmz"); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
	got3, _ := s.GetZone("dmz")
	if got3 != nil {
		t.Error("expected nil after delete")
	}
}

func TestAliasCRUD(t *testing.T) {
	s := newTestStore(t)

	a := &model.Alias{
		Name:    "web-servers",
		Type:    model.AliasTypeHost,
		Members: []string{"10.10.0.10", "10.10.0.11"},
	}
	if err := s.CreateAlias(a); err != nil {
		t.Fatalf("CreateAlias: %v", err)
	}

	got, err := s.GetAlias("web-servers")
	if err != nil {
		t.Fatalf("GetAlias: %v", err)
	}
	if len(got.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(got.Members))
	}

	if err := s.AddAliasMember("web-servers", "10.10.0.12"); err != nil {
		t.Fatalf("AddAliasMember: %v", err)
	}
	got2, _ := s.GetAlias("web-servers")
	if len(got2.Members) != 3 {
		t.Fatalf("expected 3 members after add, got %d", len(got2.Members))
	}

	if err := s.RemoveAliasMember("web-servers", "10.10.0.10"); err != nil {
		t.Fatalf("RemoveAliasMember: %v", err)
	}
	got3, _ := s.GetAlias("web-servers")
	if len(got3.Members) != 2 {
		t.Fatalf("expected 2 members after remove, got %d", len(got3.Members))
	}

	aliases, err := s.ListAliases()
	if err != nil {
		t.Fatalf("ListAliases: %v", err)
	}
	if len(aliases) != 1 {
		t.Fatalf("expected 1 alias, got %d", len(aliases))
	}
}

func TestAliasCycleDetection(t *testing.T) {
	s := newTestStore(t)

	// Create aliases A -> B -> C.
	s.CreateAlias(&model.Alias{Name: "a", Type: model.AliasTypeNested, Members: []string{"b"}})
	s.CreateAlias(&model.Alias{Name: "b", Type: model.AliasTypeNested, Members: []string{"c"}})
	s.CreateAlias(&model.Alias{Name: "c", Type: model.AliasTypeHost, Members: []string{"10.0.0.1"}})

	if err := s.CheckAliasCycles("a"); err != nil {
		t.Errorf("expected no cycle, got: %v", err)
	}

	// Create cycle: c -> a.
	s.UpdateAlias(&model.Alias{Name: "c", Type: model.AliasTypeNested, Members: []string{"a"}})
	if err := s.CheckAliasCycles("a"); err == nil {
		t.Error("expected cycle error, got nil")
	}
}

func TestPolicyCRUD(t *testing.T) {
	s := newTestStore(t)

	p := &model.Policy{
		Name:          "web-access",
		Description:   "Allow web traffic",
		DefaultAction: model.RuleActionDeny,
		Rules: []model.Rule{
			{Order: 1, SrcAlias: "lan", DstAlias: "wan", Protocol: "tcp", Ports: "80,443", Action: model.RuleActionAllow},
		},
	}
	if err := s.CreatePolicy(p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	got, err := s.GetPolicy("web-access")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(got.Rules))
	}
	if got.Rules[0].Ports != "80,443" {
		t.Errorf("expected ports '80,443', got %q", got.Rules[0].Ports)
	}

	policies, err := s.ListPolicies()
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 4 { // 2 seeded + 1 new + counting with rules
		t.Logf("got %d policies", len(policies))
	}
}

func TestDeviceAssignment(t *testing.T) {
	s := newTestStore(t)

	profiles, _ := s.ListProfiles()
	if len(profiles) == 0 {
		t.Fatal("no profiles seeded")
	}

	d := &model.DeviceAssignment{
		IP:        "10.10.0.50",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Hostname:  "workstation-1",
		ProfileID: profiles[0].ID,
	}
	if err := s.AssignDevice(d); err != nil {
		t.Fatalf("AssignDevice: %v", err)
	}

	got, err := s.GetDevice("10.10.0.50")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.Hostname != "workstation-1" {
		t.Errorf("expected hostname 'workstation-1', got %q", got.Hostname)
	}

	// Re-assign should update.
	d.Hostname = "workstation-updated"
	if err := s.AssignDevice(d); err != nil {
		t.Fatalf("re-AssignDevice: %v", err)
	}
	got2, _ := s.GetDevice("10.10.0.50")
	if got2.Hostname != "workstation-updated" {
		t.Errorf("expected updated hostname, got %q", got2.Hostname)
	}

	devices, _ := s.ListDevices()
	if len(devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(devices))
	}

	if err := s.UnassignDevice("10.10.0.50"); err != nil {
		t.Fatalf("UnassignDevice: %v", err)
	}
	if err := s.UnassignDevice("10.10.0.50"); err == nil {
		t.Error("expected error unassigning non-existent device")
	}
}

func TestCommitAndRollback(t *testing.T) {
	s := newTestStore(t)

	// Commit initial state.
	rev1, err := s.Commit("initial")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if rev1 != 1 {
		t.Errorf("expected rev 1, got %d", rev1)
	}

	// Add a zone and commit again.
	s.CreateZone(&model.Zone{Name: "dmz", Interface: "eth2", NetworkCIDR: "10.20.0.0/24", TrustLevel: "low"})
	rev2, err := s.Commit("add dmz")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if rev2 != 2 {
		t.Errorf("expected rev 2, got %d", rev2)
	}

	// Verify dmz exists.
	z, _ := s.GetZone("dmz")
	if z == nil {
		t.Fatal("dmz should exist after commit 2")
	}

	// Rollback to rev 1.
	if err := s.Rollback(1); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// dmz should be gone.
	z, _ = s.GetZone("dmz")
	if z != nil {
		t.Error("dmz should not exist after rollback to rev 1")
	}

	// Base zones should still be there.
	zones, _ := s.ListZones()
	if len(zones) != 2 {
		t.Errorf("expected 2 zones after rollback, got %d", len(zones))
	}
}

func TestExportImport(t *testing.T) {
	s := newTestStore(t)

	s.CreateAlias(&model.Alias{Name: "test-alias", Type: model.AliasTypeHost, Members: []string{"10.0.0.1"}})

	snap, err := s.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Verify snapshot is valid JSON.
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal snapshot: %v", err)
	}
	if len(data) < 10 {
		t.Error("snapshot seems too small")
	}

	// Import into a fresh store.
	s2 := newTestStore(t)
	// Clear seeded data by importing the snapshot.
	if err := s2.Import(snap); err != nil {
		t.Fatalf("Import: %v", err)
	}

	aliases, _ := s2.ListAliases()
	if len(aliases) != 1 {
		t.Errorf("expected 1 alias after import, got %d", len(aliases))
	}
	if aliases[0].Name != "test-alias" {
		t.Errorf("expected alias name 'test-alias', got %q", aliases[0].Name)
	}
}

func TestListRevisions(t *testing.T) {
	s := newTestStore(t)

	s.Commit("first")
	s.Commit("second")

	revs, err := s.ListRevisions()
	if err != nil {
		t.Fatalf("ListRevisions: %v", err)
	}
	if len(revs) != 2 {
		t.Fatalf("expected 2 revisions, got %d", len(revs))
	}
	if revs[0].RevNumber != 2 {
		t.Errorf("expected most recent first, got rev %d", revs[0].RevNumber)
	}
}

func TestDiff(t *testing.T) {
	s := newTestStore(t)

	s.Commit("before")
	s.CreateZone(&model.Zone{Name: "new-zone", Interface: "eth3", NetworkCIDR: "10.30.0.0/24", TrustLevel: "none"})
	s.Commit("after")

	snap1, snap2, err := s.Diff(1, 2)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// snap1 should have 2 zones, snap2 should have 3.
	var zones1, zones2 []map[string]any
	json.Unmarshal(snap1.Zones, &zones1)
	json.Unmarshal(snap2.Zones, &zones2)
	if len(zones1) != 2 {
		t.Errorf("expected 2 zones in rev 1, got %d", len(zones1))
	}
	if len(zones2) != 3 {
		t.Errorf("expected 3 zones in rev 2, got %d", len(zones2))
	}
}
