package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mwilco03/kepha/internal/config"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	store, err := config.NewStore(filepath.Join(t.TempDir(), "test.db"))
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
	return Handler(store)
}

func TestDashboardPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Error("missing Dashboard title")
	}
	if !strings.Contains(body, "Gatekeeper") {
		t.Error("missing Gatekeeper branding")
	}
}

func TestZonesPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/zones", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "wan") {
		t.Error("missing wan zone")
	}
	if !strings.Contains(body, "lan") {
		t.Error("missing lan zone")
	}
}

func TestZoneDetailPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/zones/lan", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "10.10.0.0/24") {
		t.Error("missing LAN CIDR")
	}
}

func TestZoneDetailNotFound(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/zones/nonexistent", nil))
	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestAliasesPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/aliases", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestDevicesPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/devices", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestPoliciesPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/policies", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "lan-outbound") {
		t.Error("missing seeded policy")
	}
}

func TestConfigPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/config", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAssignPage(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assign", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "desktop") {
		t.Error("missing profile option")
	}
}

func Test404Page(t *testing.T) {
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nonexistent", nil))
	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
