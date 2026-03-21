package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

func newTestRouter(t *testing.T) (http.Handler, *config.Store) {
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
	return NewRouter(store), store
}

func doJSON(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestStatusEndpoint(t *testing.T) {
	router, _ := newTestRouter(t)
	rec := doJSON(t, router, "GET", "/api/v1/status", nil)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestZoneEndpoints(t *testing.T) {
	router, _ := newTestRouter(t)

	// List zones.
	rec := doJSON(t, router, "GET", "/api/v1/zones", nil)
	if rec.Code != 200 {
		t.Fatalf("list zones: expected 200, got %d", rec.Code)
	}
	var zones []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &zones); err != nil {
		t.Fatalf("unmarshal zones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}

	// Create zone.
	rec = doJSON(t, router, "POST", "/api/v1/zones", map[string]string{
		"name": "dmz", "interface": "eth2", "network_cidr": "10.20.0.0/24", "trust_level": "low",
	})
	if rec.Code != 201 {
		t.Fatalf("create zone: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Get zone.
	rec = doJSON(t, router, "GET", "/api/v1/zones/dmz", nil)
	if rec.Code != 200 {
		t.Fatalf("get zone: expected 200, got %d", rec.Code)
	}

	// Get non-existent zone.
	rec = doJSON(t, router, "GET", "/api/v1/zones/nonexistent", nil)
	if rec.Code != 404 {
		t.Fatalf("get missing zone: expected 404, got %d", rec.Code)
	}

	// Delete zone.
	rec = doJSON(t, router, "DELETE", "/api/v1/zones/dmz", nil)
	if rec.Code != 200 {
		t.Fatalf("delete zone: expected 200, got %d", rec.Code)
	}
}

func TestAliasEndpoints(t *testing.T) {
	router, _ := newTestRouter(t)

	// Create alias.
	rec := doJSON(t, router, "POST", "/api/v1/aliases", map[string]any{
		"name": "web-servers", "type": "host", "members": []string{"10.10.0.10"},
	})
	if rec.Code != 201 {
		t.Fatalf("create alias: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// List aliases.
	rec = doJSON(t, router, "GET", "/api/v1/aliases", nil)
	if rec.Code != 200 {
		t.Fatalf("list aliases: expected 200, got %d", rec.Code)
	}

	// Add member.
	rec = doJSON(t, router, "POST", "/api/v1/aliases/web-servers/members", map[string]string{"member": "10.10.0.11"})
	if rec.Code != 200 {
		t.Fatalf("add member: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Get alias.
	rec = doJSON(t, router, "GET", "/api/v1/aliases/web-servers", nil)
	if rec.Code != 200 {
		t.Fatalf("get alias: expected 200, got %d", rec.Code)
	}
	var alias map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &alias); err != nil {
		t.Fatalf("unmarshal alias: %v", err)
	}
	members := alias["members"].([]any)
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

func TestDeviceAssignmentEndpoints(t *testing.T) {
	router, _ := newTestRouter(t)

	// Assign device.
	rec := doJSON(t, router, "POST", "/api/v1/assign", map[string]any{
		"ip": "10.10.0.50", "hostname": "test-pc", "profile": "desktop",
	})
	if rec.Code != 201 {
		t.Fatalf("assign: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// List devices.
	rec = doJSON(t, router, "GET", "/api/v1/devices", nil)
	if rec.Code != 200 {
		t.Fatalf("list devices: expected 200, got %d", rec.Code)
	}
	var devices []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &devices); err != nil {
		t.Fatalf("unmarshal devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	// Unassign device.
	rec = doJSON(t, router, "DELETE", "/api/v1/unassign", map[string]string{"ip": "10.10.0.50"})
	if rec.Code != 200 {
		t.Fatalf("unassign: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestConfigEndpoints(t *testing.T) {
	router, _ := newTestRouter(t)

	// Commit.
	rec := doJSON(t, router, "POST", "/api/v1/config/commit", map[string]string{"message": "test commit"})
	if rec.Code != 200 {
		t.Fatalf("commit: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// List revisions.
	rec = doJSON(t, router, "GET", "/api/v1/config/revisions", nil)
	if rec.Code != 200 {
		t.Fatalf("list revisions: expected 200, got %d", rec.Code)
	}

	// Export.
	rec = doJSON(t, router, "GET", "/api/v1/config/export", nil)
	if rec.Code != 200 {
		t.Fatalf("export: expected 200, got %d", rec.Code)
	}

	// Confirm.
	rec = doJSON(t, router, "POST", "/api/v1/config/confirm", nil)
	if rec.Code != 200 {
		t.Fatalf("confirm: expected 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware(t *testing.T) {
	store, err := config.NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	store.Migrate()
	store.Seed()

	router := NewRouterWithDriver(store, nil, "secret-key")

	// Without key.
	rec := doJSON(t, router, "GET", "/api/v1/zones", nil)
	if rec.Code != 401 {
		t.Fatalf("expected 401 without key, got %d", rec.Code)
	}

	// With wrong key.
	req := httptest.NewRequest("GET", "/api/v1/zones", nil)
	req.Header.Set("X-API-Key", "wrong")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 with wrong key, got %d", rec.Code)
	}

	// With correct key.
	req = httptest.NewRequest("GET", "/api/v1/zones", nil)
	req.Header.Set("X-API-Key", "secret-key")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200 with correct key, got %d", rec.Code)
	}
}

func TestPolicyEndpoints(t *testing.T) {
	router, _ := newTestRouter(t)

	rec := doJSON(t, router, "POST", "/api/v1/policies", map[string]any{
		"name": "test-policy", "default_action": "deny",
		"rules": []map[string]any{
			{"order": 1, "protocol": "tcp", "ports": "443", "action": "allow"},
		},
	})
	if rec.Code != 201 {
		t.Fatalf("create policy: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, router, "GET", "/api/v1/policies/test-policy", nil)
	if rec.Code != 200 {
		t.Fatalf("get policy: expected 200, got %d", rec.Code)
	}
}

func TestDiagEndpoints(t *testing.T) {
	router, _ := newTestRouter(t)

	rec := doJSON(t, router, "GET", "/api/v1/diag/interfaces", nil)
	if rec.Code != 200 {
		t.Fatalf("interfaces: expected 200, got %d", rec.Code)
	}
}

// --- M-CR9: Tests for invalid/malicious API input ---

func TestInvalidInput(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("oversized_body", func(t *testing.T) {
		// Send a 2MB body to a zone creation endpoint.
		bigBody := bytes.Repeat([]byte("A"), 2*1024*1024)
		req := httptest.NewRequest("POST", "/api/v1/zones", bytes.NewReader(bigBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		// Should reject — either 400 (bad JSON) or 413 (too large).
		if rec.Code == 200 || rec.Code == 201 {
			t.Errorf("expected rejection for 2MB body, got %d", rec.Code)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/zones", bytes.NewBufferString("{not valid json"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code == 200 || rec.Code == 201 {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("empty_zone_name", func(t *testing.T) {
		rec := doJSON(t, router, "POST", "/api/v1/zones", map[string]string{
			"name":      "",
			"interface": "eth0",
		})
		if rec.Code == 200 || rec.Code == 201 {
			t.Error("expected rejection for empty zone name")
		}
	})

	t.Run("xss_in_zone_name", func(t *testing.T) {
		rec := doJSON(t, router, "POST", "/api/v1/zones", map[string]string{
			"name":        "<script>alert(1)</script>",
			"interface":   "eth0",
			"trust_level": "none",
		})
		// Should either reject or sanitize — must not return 201.
		if rec.Code == 201 {
			t.Error("should not accept HTML/script in zone name")
		}
	})

	t.Run("sql_injection_attempt", func(t *testing.T) {
		rec := doJSON(t, router, "GET", "/api/v1/zones/'+OR+1%3D1--", nil)
		// Should return 404 (zone not found), not crash or drop the table.
		if rec.Code == 500 {
			t.Error("SQL injection attempt caused server error")
		}
	})
}
