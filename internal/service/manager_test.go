package service

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

// mockService is a minimal Service implementation for testing.
type mockService struct {
	name     string
	state    State
	started  bool
	stopped  bool
	reloaded bool
	deps     []string
	startErr error
}

func (m *mockService) Name() string           { return m.name }
func (m *mockService) DisplayName() string    { return m.name }
func (m *mockService) Description() string    { return "test service" }
func (m *mockService) Category() string       { return "test" }
func (m *mockService) Dependencies() []string { return m.deps }

func (m *mockService) Start(cfg map[string]string) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	m.state = StateRunning
	return nil
}

func (m *mockService) Stop() error {
	m.stopped = true
	m.state = StateStopped
	return nil
}

func (m *mockService) Reload(cfg map[string]string) error {
	m.reloaded = true
	return nil
}

func (m *mockService) Status() State {
	return m.state
}

func (m *mockService) Validate(cfg map[string]string) error {
	return nil
}

func (m *mockService) DefaultConfig() map[string]string {
	return map[string]string{"key": "value"}
}

func (m *mockService) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"key": {Description: "test key", Default: "value", Type: "string"},
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	path := t.TempDir() + "/test.db"
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(path)
	})
	return db
}

func TestManagerRegisterAndList(t *testing.T) {
	db := testDB(t)
	mgr, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}

	svc := &mockService{name: "test-svc"}
	mgr.Register(svc)

	services := mgr.List()
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Name != "test-svc" {
		t.Fatalf("expected service name test-svc, got %s", services[0].Name)
	}
	if services[0].State != StateStopped {
		t.Fatalf("expected state stopped, got %s", services[0].State)
	}
}

func TestManagerEnableDisable(t *testing.T) {
	db := testDB(t)
	mgr, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}

	svc := &mockService{name: "test-svc"}
	mgr.Register(svc)

	// Enable.
	if err := mgr.Enable("test-svc"); err != nil {
		t.Fatal(err)
	}
	if !svc.started {
		t.Fatal("service not started")
	}

	info, err := mgr.Get("test-svc")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Enabled {
		t.Fatal("expected enabled")
	}
	if info.State != StateRunning {
		t.Fatalf("expected running, got %s", info.State)
	}

	// Disable.
	if err := mgr.Disable("test-svc"); err != nil {
		t.Fatal(err)
	}
	if !svc.stopped {
		t.Fatal("service not stopped")
	}

	info, err = mgr.Get("test-svc")
	if err != nil {
		t.Fatal(err)
	}
	if info.Enabled {
		t.Fatal("expected disabled")
	}
}

func TestManagerConfigure(t *testing.T) {
	db := testDB(t)
	mgr, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}

	svc := &mockService{name: "test-svc"}
	mgr.Register(svc)

	// Configure when stopped — should save but not reload.
	cfg := map[string]string{"key": "newvalue"}
	if err := mgr.Configure("test-svc", cfg); err != nil {
		t.Fatal(err)
	}
	if svc.reloaded {
		t.Fatal("should not reload when stopped")
	}

	// Enable, then configure — should reload.
	if err := mgr.Enable("test-svc"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Configure("test-svc", cfg); err != nil {
		t.Fatal(err)
	}
	if !svc.reloaded {
		t.Fatal("should reload when running")
	}
}

func TestManagerUnknownService(t *testing.T) {
	db := testDB(t)
	mgr, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}

	if err := mgr.Enable("nonexistent"); err == nil {
		t.Fatal("expected error for unknown service")
	}
}

func TestManagerGetSchema(t *testing.T) {
	db := testDB(t)
	mgr, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}

	svc := &mockService{name: "test-svc"}
	mgr.Register(svc)

	schema, err := mgr.Schema("test-svc")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := schema["key"]; !ok {
		t.Fatal("expected 'key' in schema")
	}
}

func TestManagerDependencyCheck(t *testing.T) {
	db := testDB(t)
	mgr, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}

	dep := &mockService{name: "dep-svc"}
	svc := &mockService{name: "test-svc", deps: []string{"dep-svc"}}
	mgr.Register(dep)
	mgr.Register(svc)

	// Enabling svc should fail because dep is not running.
	if err := mgr.Enable("test-svc"); err == nil {
		t.Fatal("expected error for unmet dependency")
	}

	// Enable dep first.
	if err := mgr.Enable("dep-svc"); err != nil {
		t.Fatal(err)
	}

	// Now enabling svc should succeed.
	if err := mgr.Enable("test-svc"); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestManagerStartEnabled(t *testing.T) {
	db := testDB(t)

	// First manager: enable a service.
	mgr1, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}
	svc1 := &mockService{name: "persisted-svc"}
	mgr1.Register(svc1)
	if err := mgr1.Enable("persisted-svc"); err != nil {
		t.Fatal(err)
	}

	// Second manager: simulate daemon restart.
	mgr2, err := NewManager(db)
	if err != nil {
		t.Fatal(err)
	}
	svc2 := &mockService{name: "persisted-svc"}
	mgr2.Register(svc2)
	mgr2.StartEnabled()

	if !svc2.started {
		t.Fatal("service should have been started on boot")
	}
}
