package rbac

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newTestDB creates an in-memory SQLite database for testing.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestEnforcer creates an Enforcer backed by an in-memory SQLite database.
func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	db := newTestDB(t)
	e, err := NewEnforcer(db)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	return e
}

// ---------------------------------------------------------------------------
// Can
// ---------------------------------------------------------------------------

func TestCan(t *testing.T) {
	// All actions in the system.
	allActions := []string{
		ActionZonesRead, ActionZonesWrite,
		ActionAliasesRead, ActionAliasesWrite,
		ActionProfilesRead, ActionProfilesWrite,
		ActionPoliciesRead, ActionPoliciesWrite,
		ActionDevicesRead, ActionDevicesWrite,
		ActionConfigCommit, ActionConfigRollback,
		ActionConfigExport, ActionConfigImport,
		ActionWGRead, ActionWGWrite,
		ActionDiagRead, ActionDiagActive,
		ActionAuditRead,
		ActionServicesRead, ActionServicesWrite,
		ActionMCPConnect,
	}

	// Admin can do everything.
	t.Run("admin_has_all_permissions", func(t *testing.T) {
		for _, action := range allActions {
			if !Can(RoleAdmin, action) {
				t.Errorf("admin should be allowed %s", action)
			}
		}
	})

	// Operator has everything except mcp:connect.
	t.Run("operator_permissions", func(t *testing.T) {
		for _, action := range allActions {
			got := Can(RoleOperator, action)
			if action == ActionMCPConnect {
				if got {
					t.Errorf("operator should NOT be allowed %s", action)
				}
			} else {
				if !got {
					t.Errorf("operator should be allowed %s", action)
				}
			}
		}
	})

	// Auditor is read-only (plus config:export).
	t.Run("auditor_read_only", func(t *testing.T) {
		allowed := map[string]bool{
			ActionZonesRead:    true,
			ActionAliasesRead:  true,
			ActionProfilesRead: true,
			ActionPoliciesRead: true,
			ActionDevicesRead:  true,
			ActionConfigExport: true,
			ActionWGRead:       true,
			ActionDiagRead:     true,
			ActionAuditRead:    true,
			ActionServicesRead: true,
		}
		for _, action := range allActions {
			got := Can(RoleAuditor, action)
			if allowed[action] && !got {
				t.Errorf("auditor should be allowed %s", action)
			}
			if !allowed[action] && got {
				t.Errorf("auditor should NOT be allowed %s", action)
			}
		}
	})

	// Diagnostics: read + diag:active.
	t.Run("diagnostics_permissions", func(t *testing.T) {
		allowed := map[string]bool{
			ActionZonesRead:    true,
			ActionAliasesRead:  true,
			ActionProfilesRead: true,
			ActionPoliciesRead: true,
			ActionDevicesRead:  true,
			ActionConfigExport: true,
			ActionWGRead:       true,
			ActionDiagRead:     true,
			ActionDiagActive:   true,
			ActionAuditRead:    true,
			ActionServicesRead: true,
		}
		for _, action := range allActions {
			got := Can(RoleDiagnostics, action)
			if allowed[action] && !got {
				t.Errorf("diagnostics should be allowed %s", action)
			}
			if !allowed[action] && got {
				t.Errorf("diagnostics should NOT be allowed %s", action)
			}
		}
	})

	// MCP-agent: read + devices:write + mcp:connect (no audit:read).
	t.Run("mcp_agent_permissions", func(t *testing.T) {
		allowed := map[string]bool{
			ActionZonesRead:    true,
			ActionAliasesRead:  true,
			ActionProfilesRead: true,
			ActionPoliciesRead: true,
			ActionDevicesRead:  true,
			ActionDevicesWrite: true,
			ActionConfigExport: true,
			ActionWGRead:       true,
			ActionDiagRead:     true,
			ActionServicesRead: true,
			ActionMCPConnect:   true,
		}
		for _, action := range allActions {
			got := Can(RoleMCPAgent, action)
			if allowed[action] && !got {
				t.Errorf("mcp-agent should be allowed %s", action)
			}
			if !allowed[action] && got {
				t.Errorf("mcp-agent should NOT be allowed %s", action)
			}
		}
	})

	// Unknown role gets nothing.
	t.Run("unknown_role", func(t *testing.T) {
		for _, action := range allActions {
			if Can("nonexistent", action) {
				t.Errorf("unknown role should not have permission for %s", action)
			}
		}
	})

	// Unknown action for a valid role.
	t.Run("unknown_action", func(t *testing.T) {
		if Can(RoleAdmin, "bogus:action") {
			t.Error("admin should not have permission for a non-existent action")
		}
	})
}

// ---------------------------------------------------------------------------
// CanForZone
// ---------------------------------------------------------------------------

func TestCanForZone(t *testing.T) {
	tests := []struct {
		name   string
		role   string
		action string
		zone   string
		scopes []string
		want   bool
	}{
		{
			name:   "admin_no_scopes",
			role:   RoleAdmin,
			action: ActionZonesRead,
			zone:   "dmz",
			scopes: nil,
			want:   true,
		},
		{
			name:   "admin_empty_scopes",
			role:   RoleAdmin,
			action: ActionZonesWrite,
			zone:   "dmz",
			scopes: []string{},
			want:   true,
		},
		{
			name:   "admin_zone_in_scope",
			role:   RoleAdmin,
			action: ActionZonesWrite,
			zone:   "dmz",
			scopes: []string{"lan", "dmz"},
			want:   true,
		},
		{
			name:   "admin_zone_not_in_scope",
			role:   RoleAdmin,
			action: ActionZonesWrite,
			zone:   "wan",
			scopes: []string{"lan", "dmz"},
			want:   false,
		},
		{
			name:   "auditor_write_denied",
			role:   RoleAuditor,
			action: ActionZonesWrite,
			zone:   "lan",
			scopes: nil,
			want:   false,
		},
		{
			name:   "auditor_read_allowed_no_scope",
			role:   RoleAuditor,
			action: ActionZonesRead,
			zone:   "lan",
			scopes: nil,
			want:   true,
		},
		{
			name:   "auditor_read_zone_not_in_scope",
			role:   RoleAuditor,
			action: ActionZonesRead,
			zone:   "wan",
			scopes: []string{"lan"},
			want:   false,
		},
		{
			name:   "unknown_role",
			role:   "nobody",
			action: ActionZonesRead,
			zone:   "lan",
			scopes: nil,
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CanForZone(tc.role, tc.action, tc.zone, tc.scopes)
			if got != tc.want {
				t.Errorf("CanForZone(%q, %q, %q, %v) = %v, want %v",
					tc.role, tc.action, tc.zone, tc.scopes, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CanForProfile
// ---------------------------------------------------------------------------

func TestCanForProfile(t *testing.T) {
	tests := []struct {
		name    string
		role    string
		action  string
		profile string
		scopes  []string
		want    bool
	}{
		{
			name:    "admin_no_scopes",
			role:    RoleAdmin,
			action:  ActionProfilesRead,
			profile: "default",
			scopes:  nil,
			want:    true,
		},
		{
			name:    "admin_profile_in_scope",
			role:    RoleAdmin,
			action:  ActionProfilesWrite,
			profile: "strict",
			scopes:  []string{"default", "strict"},
			want:    true,
		},
		{
			name:    "admin_profile_not_in_scope",
			role:    RoleAdmin,
			action:  ActionProfilesWrite,
			profile: "custom",
			scopes:  []string{"default", "strict"},
			want:    false,
		},
		{
			name:    "auditor_write_denied",
			role:    RoleAuditor,
			action:  ActionProfilesWrite,
			profile: "default",
			scopes:  nil,
			want:    false,
		},
		{
			name:    "operator_read_profile_in_scope",
			role:    RoleOperator,
			action:  ActionProfilesRead,
			profile: "strict",
			scopes:  []string{"strict"},
			want:    true,
		},
		{
			name:    "unknown_role",
			role:    "nobody",
			action:  ActionProfilesRead,
			profile: "default",
			scopes:  nil,
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CanForProfile(tc.role, tc.action, tc.profile, tc.scopes)
			if got != tc.want {
				t.Errorf("CanForProfile(%q, %q, %q, %v) = %v, want %v",
					tc.role, tc.action, tc.profile, tc.scopes, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// routeAction
// ---------------------------------------------------------------------------

func TestRouteAction(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   string
	}{
		// Unauthenticated endpoints return "".
		{"status", "GET", "/api/v1/status", ""},
		{"healthz", "GET", "/api/v1/healthz", ""},
		{"readyz", "GET", "/api/v1/readyz", ""},
		{"metrics", "GET", "/api/v1/metrics", ""},
		{"status_trailing_slash", "GET", "/api/v1/status/", ""},

		// Config management.
		{"config_commit", "POST", "/api/v1/config/commit", ActionConfigCommit},
		{"config_rollback", "POST", "/api/v1/config/rollback", ActionConfigRollback},
		{"config_rollback_id", "POST", "/api/v1/config/rollback/abc123", ActionConfigRollback},
		{"config_import", "POST", "/api/v1/config/import", ActionConfigImport},
		{"config_export", "GET", "/api/v1/config/export", ActionConfigExport},
		{"config_get", "GET", "/api/v1/config", ActionConfigExport},
		{"config_post", "POST", "/api/v1/config", ActionConfigCommit},

		// Zones.
		{"zones_get", "GET", "/api/v1/zones", ActionZonesRead},
		{"zones_get_id", "GET", "/api/v1/zones/dmz", ActionZonesRead},
		{"zones_post", "POST", "/api/v1/zones", ActionZonesWrite},
		{"zones_put", "PUT", "/api/v1/zones/dmz", ActionZonesWrite},
		{"zones_delete", "DELETE", "/api/v1/zones/dmz", ActionZonesWrite},

		// Aliases.
		{"aliases_get", "GET", "/api/v1/aliases", ActionAliasesRead},
		{"aliases_post", "POST", "/api/v1/aliases", ActionAliasesWrite},

		// Profiles.
		{"profiles_get", "GET", "/api/v1/profiles", ActionProfilesRead},
		{"profiles_put", "PUT", "/api/v1/profiles/default", ActionProfilesWrite},

		// Policies and rules.
		{"policies_get", "GET", "/api/v1/policies", ActionPoliciesRead},
		{"policies_post", "POST", "/api/v1/policies", ActionPoliciesWrite},
		{"rules_get", "GET", "/api/v1/rules", ActionPoliciesRead},
		{"rules_post", "POST", "/api/v1/rules", ActionPoliciesWrite},

		// Devices.
		{"devices_get", "GET", "/api/v1/devices", ActionDevicesRead},
		{"devices_post", "POST", "/api/v1/devices", ActionDevicesWrite},
		{"assign", "POST", "/api/v1/assign", ActionDevicesWrite},
		{"unassign", "POST", "/api/v1/unassign", ActionDevicesWrite},

		// WireGuard.
		{"wg_get", "GET", "/api/v1/wg", ActionWGRead},
		{"wg_post", "POST", "/api/v1/wg", ActionWGWrite},
		{"wg_peers", "GET", "/api/v1/wg/peers", ActionWGRead},

		// Diagnostics.
		{"diag_ping", "POST", "/api/v1/diag/ping", ActionDiagActive},
		{"diag_ping_get", "GET", "/api/v1/diag/ping", ActionDiagActive},
		{"diag_connections", "GET", "/api/v1/diag/connections", ActionDiagActive},
		{"diag_read", "GET", "/api/v1/diag", ActionDiagRead},
		{"diag_general", "GET", "/api/v1/diag/stats", ActionDiagRead},

		// Path test / explain.
		{"test", "POST", "/api/v1/test", ActionDiagRead},
		{"explain", "GET", "/api/v1/explain", ActionDiagRead},

		// Audit.
		{"audit", "GET", "/api/v1/audit", ActionAuditRead},

		// Services.
		{"services_get", "GET", "/api/v1/services", ActionServicesRead},
		{"services_post", "POST", "/api/v1/services", ActionServicesWrite},
		{"services_delete", "DELETE", "/api/v1/services/svc1", ActionServicesWrite},

		// MCP.
		{"mcp", "GET", "/api/v1/mcp", ActionMCPConnect},
		{"mcp_ws", "GET", "/api/v1/mcp/ws", ActionMCPConnect},

		// Unknown path.
		{"unknown", "GET", "/api/v1/nonexistent", "unknown:unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := routeAction(tc.method, tc.path)
			if got != tc.want {
				t.Errorf("routeAction(%q, %q) = %q, want %q", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractKey
// ---------------------------------------------------------------------------

func TestExtractKey(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(r *http.Request)
		want    string
	}{
		{
			name:  "bearer_token",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc123") },
			want:  "abc123",
		},
		{
			name:  "bearer_token_with_spaces",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer  abc123 ") },
			want:  "abc123",
		},
		{
			name:  "x_api_key",
			setup: func(r *http.Request) { r.Header.Set("X-API-Key", "mykey") },
			want:  "mykey",
		},
		{
			name: "basic_auth",
			setup: func(r *http.Request) {
				creds := base64.StdEncoding.EncodeToString([]byte("user:secretpw"))
				r.Header.Set("Authorization", "Basic "+creds)
			},
			want: "secretpw",
		},
		{
			name:  "bearer_takes_priority",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer bearerkey")
				r.Header.Set("X-API-Key", "xapikey")
			},
			want: "bearerkey",
		},
		{
			name:  "x_api_key_over_basic",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", "xapikey")
				// No Authorization header, so Basic auth won't be checked.
			},
			want: "xapikey",
		},
		{
			name:  "no_key",
			setup: func(r *http.Request) {},
			want:  "",
		},
		{
			name:  "authorization_non_bearer",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Token abc123") },
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/zones", nil)
			tc.setup(r)
			got := extractKey(r)
			if got != tc.want {
				t.Errorf("extractKey() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Enforcer: CreateKey, ValidateKey, RevokeKey, ListKeys, RotateKey
// ---------------------------------------------------------------------------

func TestEnforcerCreateKey(t *testing.T) {
	e := newTestEnforcer(t)

	t.Run("valid_creation", func(t *testing.T) {
		key, id, err := e.CreateKey("test-key", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if key == "" {
			t.Error("key should not be empty")
		}
		if id == "" {
			t.Error("id should not be empty")
		}
		// Key should be 64 hex chars (32 bytes).
		if len(key) != 64 {
			t.Errorf("key length = %d, want 64", len(key))
		}
		// ID should be 32 hex chars (16 bytes).
		if len(id) != 32 {
			t.Errorf("id length = %d, want 32", len(id))
		}
	})

	t.Run("with_scopes", func(t *testing.T) {
		key, id, err := e.CreateKey("scoped-key", RoleOperator, []string{"lan", "dmz"}, []string{"default"})
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if key == "" || id == "" {
			t.Error("key and id should not be empty")
		}
	})

	t.Run("invalid_role", func(t *testing.T) {
		_, _, err := e.CreateKey("bad-key", "superuser", nil, nil)
		if err != ErrInvalidRole {
			t.Errorf("expected ErrInvalidRole, got %v", err)
		}
	})

	t.Run("all_valid_roles", func(t *testing.T) {
		for role := range ValidRoles {
			_, _, err := e.CreateKey("key-"+role, role, nil, nil)
			if err != nil {
				t.Errorf("CreateKey for role %q: %v", role, err)
			}
		}
	})
}

func TestEnforcerValidateKey(t *testing.T) {
	e := newTestEnforcer(t)

	t.Run("valid_key_from_cache", func(t *testing.T) {
		key, _, err := e.CreateKey("cached", RoleAdmin, []string{"lan"}, []string{"default"})
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		ak, err := e.ValidateKey(key)
		if err != nil {
			t.Fatalf("ValidateKey: %v", err)
		}
		if ak.Role != RoleAdmin {
			t.Errorf("role = %q, want %q", ak.Role, RoleAdmin)
		}
		if ak.Name != "cached" {
			t.Errorf("name = %q, want %q", ak.Name, "cached")
		}
		if !ak.Active {
			t.Error("key should be active")
		}
		if len(ak.ZoneScope) != 1 || ak.ZoneScope[0] != "lan" {
			t.Errorf("zone_scope = %v, want [lan]", ak.ZoneScope)
		}
		if len(ak.ProfileScope) != 1 || ak.ProfileScope[0] != "default" {
			t.Errorf("profile_scope = %v, want [default]", ak.ProfileScope)
		}
	})

	t.Run("valid_key_from_db_fallback", func(t *testing.T) {
		key, _, err := e.CreateKey("db-fallback", RoleAuditor, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		// Remove from cache to force DB fallback.
		e.mu.Lock()
		delete(e.cache, key)
		e.mu.Unlock()

		ak, err := e.ValidateKey(key)
		if err != nil {
			t.Fatalf("ValidateKey: %v", err)
		}
		if ak.Role != RoleAuditor {
			t.Errorf("role = %q, want %q", ak.Role, RoleAuditor)
		}
	})

	t.Run("empty_key", func(t *testing.T) {
		_, err := e.ValidateKey("")
		if err != ErrInvalidKey {
			t.Errorf("expected ErrInvalidKey, got %v", err)
		}
	})

	t.Run("bogus_key", func(t *testing.T) {
		_, err := e.ValidateKey("nonexistentkeyvalue1234567890abcdef")
		if err != ErrInvalidKey {
			t.Errorf("expected ErrInvalidKey, got %v", err)
		}
	})

	t.Run("inactive_key_from_cache", func(t *testing.T) {
		key, id, err := e.CreateKey("inactive-test", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		err = e.RevokeKey(id)
		if err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		_, err = e.ValidateKey(key)
		if err != ErrKeyInactive {
			t.Errorf("expected ErrKeyInactive, got %v", err)
		}
	})

	t.Run("expired_key_from_cache", func(t *testing.T) {
		key, _, err := e.CreateKey("expired-test", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		// Manually set expiration in the past in cache.
		e.mu.Lock()
		past := time.Now().Add(-1 * time.Hour)
		e.cache[key].ExpiresAt = &past
		e.mu.Unlock()

		_, err = e.ValidateKey(key)
		if err != ErrKeyExpired {
			t.Errorf("expected ErrKeyExpired, got %v", err)
		}
	})
}

func TestEnforcerRevokeKey(t *testing.T) {
	e := newTestEnforcer(t)

	t.Run("revoke_existing", func(t *testing.T) {
		key, id, err := e.CreateKey("revoke-me", RoleOperator, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		err = e.RevokeKey(id)
		if err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		// Validate should fail.
		_, err = e.ValidateKey(key)
		if err != ErrKeyInactive {
			t.Errorf("expected ErrKeyInactive after revoke, got %v", err)
		}
	})

	t.Run("revoke_nonexistent", func(t *testing.T) {
		err := e.RevokeKey("nonexistent-id-1234567890abcdef")
		if err != ErrKeyNotFound {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("revoke_idempotent", func(t *testing.T) {
		_, id, err := e.CreateKey("revoke-twice", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("first RevokeKey: %v", err)
		}
		// Second revoke still finds the row (active=0 but row exists).
		if err := e.RevokeKey(id); err != nil {
			t.Errorf("second RevokeKey should not error, got %v", err)
		}
	})
}

func TestEnforcerListKeys(t *testing.T) {
	e := newTestEnforcer(t)

	t.Run("empty_list", func(t *testing.T) {
		keys, err := e.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})

	t.Run("multiple_keys", func(t *testing.T) {
		_, _, err := e.CreateKey("key-1", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey 1: %v", err)
		}
		_, _, err = e.CreateKey("key-2", RoleAuditor, []string{"lan"}, nil)
		if err != nil {
			t.Fatalf("CreateKey 2: %v", err)
		}
		_, _, err = e.CreateKey("key-3", RoleMCPAgent, nil, []string{"default"})
		if err != nil {
			t.Fatalf("CreateKey 3: %v", err)
		}

		keys, err := e.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 3 {
			t.Fatalf("expected 3 keys, got %d", len(keys))
		}

		// Verify fields are populated (no hash exposed).
		for _, k := range keys {
			if k.ID == "" {
				t.Error("key ID should not be empty")
			}
			if k.Name == "" {
				t.Error("key Name should not be empty")
			}
			if k.Role == "" {
				t.Error("key Role should not be empty")
			}
		}
	})

	t.Run("list_includes_revoked", func(t *testing.T) {
		e2 := newTestEnforcer(t)
		_, id, err := e2.CreateKey("will-revoke", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if err := e2.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}

		keys, err := e2.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		if keys[0].Active {
			t.Error("revoked key should have Active=false")
		}
	})
}

func TestEnforcerRotateKey(t *testing.T) {
	e := newTestEnforcer(t)

	t.Run("rotate_existing", func(t *testing.T) {
		oldKey, id, err := e.CreateKey("rotate-me", RoleOperator, []string{"lan"}, []string{"strict"})
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}

		newKey, err := e.RotateKey(id)
		if err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		if newKey == "" {
			t.Error("new key should not be empty")
		}
		if newKey == oldKey {
			t.Error("new key should differ from old key")
		}
		if len(newKey) != 64 {
			t.Errorf("new key length = %d, want 64", len(newKey))
		}

		// Old key should be invalid now.
		_, err = e.ValidateKey(oldKey)
		if err != ErrInvalidKey {
			t.Errorf("old key should be invalid after rotation, got %v", err)
		}

		// New key should work.
		ak, err := e.ValidateKey(newKey)
		if err != nil {
			t.Fatalf("ValidateKey new key: %v", err)
		}
		if ak.Role != RoleOperator {
			t.Errorf("role = %q, want %q", ak.Role, RoleOperator)
		}
		if ak.ID != id {
			t.Errorf("id = %q, want %q", ak.ID, id)
		}
	})

	t.Run("rotate_nonexistent", func(t *testing.T) {
		_, err := e.RotateKey("nonexistent-id-1234567890abcdef")
		if err != ErrKeyNotFound {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

func TestContextHelpers(t *testing.T) {
	t.Run("api_key_from_context_empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		ak := APIKeyFromContext(r.Context())
		if ak != nil {
			t.Error("expected nil from empty context")
		}
	})

	t.Run("role_from_context_empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		role := RoleFromContext(r.Context())
		if role != "" {
			t.Errorf("expected empty string, got %q", role)
		}
	})
}

// ---------------------------------------------------------------------------
// RBACMiddleware
// ---------------------------------------------------------------------------

func TestRBACMiddleware(t *testing.T) {
	e := newTestEnforcer(t)
	adminKey, _, err := e.CreateKey("admin-key", RoleAdmin, nil, nil)
	if err != nil {
		t.Fatalf("CreateKey admin: %v", err)
	}
	auditorKey, _, err := e.CreateKey("auditor-key", RoleAuditor, nil, nil)
	if err != nil {
		t.Fatalf("CreateKey auditor: %v", err)
	}

	// A simple handler that records it was called and writes context values.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := RoleFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("role=" + role))
	})

	mw := RBACMiddleware(e)(handler)

	t.Run("unauthenticated_endpoint_no_key", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/healthz", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("missing_key", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid_key", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer invalidkey")
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("admin_read_zones", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer "+adminKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if w.Body.String() != "role=admin" {
			t.Errorf("body = %q, want %q", w.Body.String(), "role=admin")
		}
	})

	t.Run("admin_write_zones", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer "+adminKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("auditor_read_zones_allowed", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer "+auditorKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if w.Body.String() != "role=auditor" {
			t.Errorf("body = %q, want %q", w.Body.String(), "role=auditor")
		}
	})

	t.Run("auditor_write_zones_forbidden", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer "+auditorKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
		}
	})

	t.Run("revoked_key", func(t *testing.T) {
		key, id, err := e.CreateKey("revoked-mw", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("x_api_key_header", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("X-API-Key", adminKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("unknown_path_denied", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		r.Header.Set("Authorization", "Bearer "+adminKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
		}
	})

	t.Run("mcp_agent_mcp_connect", func(t *testing.T) {
		mcpKey, _, err := e.CreateKey("mcp-key", RoleMCPAgent, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		r := httptest.NewRequest("GET", "/api/v1/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+mcpKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("auditor_mcp_connect_denied", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+auditorKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
		}
	})
}

// ---------------------------------------------------------------------------
// Helper functions (joinScopes / splitScopes)
// ---------------------------------------------------------------------------

func TestJoinSplitScopes(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		joined string
		split  []string
	}{
		{"nil", nil, "", nil},
		{"empty", []string{}, "", nil},
		{"single", []string{"lan"}, "lan", []string{"lan"}},
		{"multiple", []string{"lan", "dmz", "wan"}, "lan,dmz,wan", []string{"lan", "dmz", "wan"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := joinScopes(tc.input)
			if j != tc.joined {
				t.Errorf("joinScopes(%v) = %q, want %q", tc.input, j, tc.joined)
			}
			s := splitScopes(j)
			if len(s) != len(tc.split) {
				t.Fatalf("splitScopes(%q) len = %d, want %d", j, len(s), len(tc.split))
			}
			for i := range s {
				if s[i] != tc.split[i] {
					t.Errorf("splitScopes(%q)[%d] = %q, want %q", j, i, s[i], tc.split[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidRoles map
// ---------------------------------------------------------------------------

func TestValidRoles(t *testing.T) {
	expected := []string{RoleAdmin, RoleOperator, RoleAuditor, RoleDiagnostics, RoleMCPAgent}
	for _, r := range expected {
		if !ValidRoles[r] {
			t.Errorf("role %q should be in ValidRoles", r)
		}
	}
	if ValidRoles["nonexistent"] {
		t.Error("nonexistent role should not be valid")
	}
}

// ---------------------------------------------------------------------------
// writeJSONError
// ---------------------------------------------------------------------------

func TestWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusForbidden, "access denied")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	body := w.Body.String()
	if body != `{"error":"access denied"}` {
		t.Errorf("body = %q, want %q", body, `{"error":"access denied"}`)
	}
}
