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

	// Empty role and empty action.
	t.Run("empty_role", func(t *testing.T) {
		if Can("", ActionZonesRead) {
			t.Error("empty role should not have any permissions")
		}
	})

	t.Run("empty_action", func(t *testing.T) {
		if Can(RoleAdmin, "") {
			t.Error("empty action should return false")
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
		{
			name:   "operator_zone_first_in_scope",
			role:   RoleOperator,
			action: ActionZonesWrite,
			zone:   "lan",
			scopes: []string{"lan", "dmz", "wan"},
			want:   true,
		},
		{
			name:   "operator_zone_last_in_scope",
			role:   RoleOperator,
			action: ActionZonesWrite,
			zone:   "wan",
			scopes: []string{"lan", "dmz", "wan"},
			want:   true,
		},
		{
			name:   "diagnostics_write_denied_even_in_scope",
			role:   RoleDiagnostics,
			action: ActionZonesWrite,
			zone:   "lan",
			scopes: []string{"lan"},
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
		{
			name:    "mcp_agent_profiles_read_no_scope",
			role:    RoleMCPAgent,
			action:  ActionProfilesRead,
			profile: "any",
			scopes:  nil,
			want:    true,
		},
		{
			name:    "mcp_agent_profiles_write_denied",
			role:    RoleMCPAgent,
			action:  ActionProfilesWrite,
			profile: "any",
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
		{"healthz_trailing_slash", "GET", "/api/v1/healthz/", ""},

		// Config management.
		{"config_commit", "POST", "/api/v1/config/commit", ActionConfigCommit},
		{"config_rollback", "POST", "/api/v1/config/rollback", ActionConfigRollback},
		{"config_rollback_id", "POST", "/api/v1/config/rollback/abc123", ActionConfigRollback},
		{"config_import", "POST", "/api/v1/config/import", ActionConfigImport},
		{"config_export", "GET", "/api/v1/config/export", ActionConfigExport},
		{"config_get", "GET", "/api/v1/config", ActionConfigExport},
		{"config_post", "POST", "/api/v1/config", ActionConfigCommit},
		{"config_put", "PUT", "/api/v1/config", ActionConfigCommit},
		{"config_delete", "DELETE", "/api/v1/config", ActionConfigCommit},

		// Zones.
		{"zones_get", "GET", "/api/v1/zones", ActionZonesRead},
		{"zones_get_id", "GET", "/api/v1/zones/dmz", ActionZonesRead},
		{"zones_post", "POST", "/api/v1/zones", ActionZonesWrite},
		{"zones_put", "PUT", "/api/v1/zones/dmz", ActionZonesWrite},
		{"zones_delete", "DELETE", "/api/v1/zones/dmz", ActionZonesWrite},

		// Aliases.
		{"aliases_get", "GET", "/api/v1/aliases", ActionAliasesRead},
		{"aliases_post", "POST", "/api/v1/aliases", ActionAliasesWrite},
		{"aliases_delete", "DELETE", "/api/v1/aliases/myalias", ActionAliasesWrite},

		// Profiles.
		{"profiles_get", "GET", "/api/v1/profiles", ActionProfilesRead},
		{"profiles_get_id", "GET", "/api/v1/profiles/default", ActionProfilesRead},
		{"profiles_put", "PUT", "/api/v1/profiles/default", ActionProfilesWrite},
		{"profiles_post", "POST", "/api/v1/profiles", ActionProfilesWrite},

		// Policies and rules.
		{"policies_get", "GET", "/api/v1/policies", ActionPoliciesRead},
		{"policies_post", "POST", "/api/v1/policies", ActionPoliciesWrite},
		{"policies_delete", "DELETE", "/api/v1/policies/p1", ActionPoliciesWrite},
		{"rules_get", "GET", "/api/v1/rules", ActionPoliciesRead},
		{"rules_post", "POST", "/api/v1/rules", ActionPoliciesWrite},

		// Devices.
		{"devices_get", "GET", "/api/v1/devices", ActionDevicesRead},
		{"devices_get_id", "GET", "/api/v1/devices/dev1", ActionDevicesRead},
		{"devices_post", "POST", "/api/v1/devices", ActionDevicesWrite},
		{"assign_post", "POST", "/api/v1/assign", ActionDevicesWrite},
		{"assign_get", "GET", "/api/v1/assign", ActionDevicesRead},
		{"unassign_post", "POST", "/api/v1/unassign", ActionDevicesWrite},

		// WireGuard.
		{"wg_get", "GET", "/api/v1/wg", ActionWGRead},
		{"wg_post", "POST", "/api/v1/wg", ActionWGWrite},
		{"wg_peers", "GET", "/api/v1/wg/peers", ActionWGRead},
		{"wg_put", "PUT", "/api/v1/wg/peer1", ActionWGWrite},

		// Diagnostics.
		{"diag_ping_post", "POST", "/api/v1/diag/ping", ActionDiagActive},
		{"diag_ping_get", "GET", "/api/v1/diag/ping", ActionDiagActive},
		{"diag_ping_subpath", "GET", "/api/v1/diag/ping/10.0.0.1", ActionDiagActive},
		{"diag_connections", "GET", "/api/v1/diag/connections", ActionDiagActive},
		{"diag_read", "GET", "/api/v1/diag", ActionDiagRead},
		{"diag_stats", "GET", "/api/v1/diag/stats", ActionDiagRead},

		// Path test / explain.
		{"test_post", "POST", "/api/v1/test", ActionDiagRead},
		{"test_get", "GET", "/api/v1/test", ActionDiagRead},
		{"explain", "GET", "/api/v1/explain", ActionDiagRead},

		// Audit.
		{"audit", "GET", "/api/v1/audit", ActionAuditRead},

		// Services.
		{"services_get", "GET", "/api/v1/services", ActionServicesRead},
		{"services_get_id", "GET", "/api/v1/services/dns", ActionServicesRead},
		{"services_post", "POST", "/api/v1/services", ActionServicesWrite},
		{"services_delete", "DELETE", "/api/v1/services/svc1", ActionServicesWrite},

		// MCP.
		{"mcp_get", "GET", "/api/v1/mcp", ActionMCPConnect},
		{"mcp_ws", "GET", "/api/v1/mcp/ws", ActionMCPConnect},
		{"mcp_sse", "GET", "/api/v1/mcp/sse", ActionMCPConnect},

		// Unknown path.
		{"unknown", "GET", "/api/v1/nonexistent", "unknown:unknown"},
		{"unknown_deep", "POST", "/api/v1/something/else", "unknown:unknown"},
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
		name  string
		setup func(r *http.Request)
		want  string
	}{
		{
			name:  "bearer_token",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc123") },
			want:  "abc123",
		},
		{
			name:  "bearer_token_with_trailing_space",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer  abc123 ") },
			want:  "abc123",
		},
		{
			name:  "x_api_key",
			setup: func(r *http.Request) { r.Header.Set("X-API-Key", "mykey") },
			want:  "mykey",
		},
		{
			name: "basic_auth_password",
			setup: func(r *http.Request) {
				creds := base64.StdEncoding.EncodeToString([]byte("user:secretpw"))
				r.Header.Set("Authorization", "Basic "+creds)
			},
			want: "secretpw",
		},
		{
			name: "basic_auth_empty_password",
			setup: func(r *http.Request) {
				creds := base64.StdEncoding.EncodeToString([]byte("user:"))
				r.Header.Set("Authorization", "Basic "+creds)
			},
			want: "",
		},
		{
			name: "bearer_takes_priority_over_x_api_key",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer bearerkey")
				r.Header.Set("X-API-Key", "xapikey")
			},
			want: "bearerkey",
		},
		{
			name: "x_api_key_when_no_authorization",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", "xapikey")
			},
			want: "xapikey",
		},
		{
			name:  "no_key_at_all",
			setup: func(r *http.Request) {},
			want:  "",
		},
		{
			name:  "authorization_non_bearer_non_basic",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Token abc123") },
			want:  "",
		},
		{
			name:  "bearer_empty_token",
			setup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
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
// Enforcer: CreateKey
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
		// Validate the key and check scopes are stored.
		ak, err := e.ValidateKey(key)
		if err != nil {
			t.Fatalf("ValidateKey: %v", err)
		}
		if len(ak.ZoneScope) != 2 || ak.ZoneScope[0] != "lan" || ak.ZoneScope[1] != "dmz" {
			t.Errorf("zone_scope = %v, want [lan dmz]", ak.ZoneScope)
		}
		if len(ak.ProfileScope) != 1 || ak.ProfileScope[0] != "default" {
			t.Errorf("profile_scope = %v, want [default]", ak.ProfileScope)
		}
	})

	t.Run("invalid_role", func(t *testing.T) {
		_, _, err := e.CreateKey("bad-key", "superuser", nil, nil)
		if err != ErrInvalidRole {
			t.Errorf("expected ErrInvalidRole, got %v", err)
		}
	})

	t.Run("empty_role", func(t *testing.T) {
		_, _, err := e.CreateKey("bad-key", "", nil, nil)
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

	t.Run("unique_ids", func(t *testing.T) {
		ids := make(map[string]bool)
		for i := 0; i < 10; i++ {
			_, id, err := e.CreateKey("unique-test", RoleAdmin, nil, nil)
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			if ids[id] {
				t.Fatalf("duplicate id generated: %s", id)
			}
			ids[id] = true
		}
	})

	t.Run("unique_keys", func(t *testing.T) {
		keys := make(map[string]bool)
		for i := 0; i < 10; i++ {
			key, _, err := e.CreateKey("unique-test", RoleAdmin, nil, nil)
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			if keys[key] {
				t.Fatalf("duplicate key generated: %s", key)
			}
			keys[key] = true
		}
	})
}

// ---------------------------------------------------------------------------
// Enforcer: ValidateKey
// ---------------------------------------------------------------------------

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
		if ak.Name != "db-fallback" {
			t.Errorf("name = %q, want %q", ak.Name, "db-fallback")
		}
	})

	t.Run("db_fallback_populates_cache", func(t *testing.T) {
		key, _, err := e.CreateKey("cache-populate", RoleDiagnostics, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		// Remove from cache.
		e.mu.Lock()
		delete(e.cache, key)
		e.mu.Unlock()

		// First validate goes through DB.
		_, err = e.ValidateKey(key)
		if err != nil {
			t.Fatalf("first ValidateKey: %v", err)
		}

		// Second validate should hit cache (verify by checking cache).
		e.mu.RLock()
		_, inCache := e.cache[key]
		e.mu.RUnlock()
		if !inCache {
			t.Error("key should be in cache after DB fallback validation")
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
		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		_, err = e.ValidateKey(key)
		if err != ErrKeyInactive {
			t.Errorf("expected ErrKeyInactive, got %v", err)
		}
	})

	t.Run("inactive_key_from_db", func(t *testing.T) {
		key, id, err := e.CreateKey("inactive-db", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		// Clear cache to force DB path.
		e.mu.Lock()
		delete(e.cache, key)
		e.mu.Unlock()

		_, err = e.ValidateKey(key)
		if err != ErrKeyInactive {
			t.Errorf("expected ErrKeyInactive via DB path, got %v", err)
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

	t.Run("not_expired_key", func(t *testing.T) {
		key, _, err := e.CreateKey("future-expiry", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		// Set expiration in the future.
		e.mu.Lock()
		future := time.Now().Add(24 * time.Hour)
		e.cache[key].ExpiresAt = &future
		e.mu.Unlock()

		ak, err := e.ValidateKey(key)
		if err != nil {
			t.Fatalf("ValidateKey: %v", err)
		}
		if ak.Role != RoleAdmin {
			t.Errorf("role = %q, want %q", ak.Role, RoleAdmin)
		}
	})

	t.Run("validate_same_key_twice", func(t *testing.T) {
		key, _, err := e.CreateKey("twice", RoleOperator, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		ak1, err := e.ValidateKey(key)
		if err != nil {
			t.Fatalf("first ValidateKey: %v", err)
		}
		ak2, err := e.ValidateKey(key)
		if err != nil {
			t.Fatalf("second ValidateKey: %v", err)
		}
		if ak1.ID != ak2.ID {
			t.Errorf("IDs should match: %q != %q", ak1.ID, ak2.ID)
		}
	})
}

// ---------------------------------------------------------------------------
// Enforcer: RevokeKey
// ---------------------------------------------------------------------------

func TestEnforcerRevokeKey(t *testing.T) {
	e := newTestEnforcer(t)

	t.Run("revoke_existing", func(t *testing.T) {
		key, id, err := e.CreateKey("revoke-me", RoleOperator, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		// Validate should fail with inactive.
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

	t.Run("revoke_updates_cache", func(t *testing.T) {
		key, id, err := e.CreateKey("cache-revoke", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		// Verify key is active in cache.
		e.mu.RLock()
		cached := e.cache[key]
		e.mu.RUnlock()
		if cached == nil || !cached.Active {
			t.Fatal("key should be active in cache before revoke")
		}

		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}

		// Verify key is inactive in cache.
		e.mu.RLock()
		cached = e.cache[key]
		e.mu.RUnlock()
		if cached == nil {
			t.Fatal("key should still be in cache after revoke")
		}
		if cached.Active {
			t.Error("key should be inactive in cache after revoke")
		}
	})
}

// ---------------------------------------------------------------------------
// Enforcer: ListKeys
// ---------------------------------------------------------------------------

func TestEnforcerListKeys(t *testing.T) {
	t.Run("empty_list", func(t *testing.T) {
		e := newTestEnforcer(t)
		keys, err := e.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})

	t.Run("multiple_keys", func(t *testing.T) {
		e := newTestEnforcer(t)
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

		// Verify fields are populated.
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
			if !ValidRoles[k.Role] {
				t.Errorf("key Role %q should be valid", k.Role)
			}
		}
	})

	t.Run("list_includes_revoked", func(t *testing.T) {
		e := newTestEnforcer(t)
		_, id, err := e.CreateKey("will-revoke", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		if err := e.RevokeKey(id); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}

		keys, err := e.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		if keys[0].Active {
			t.Error("revoked key should have Active=false")
		}
		if keys[0].ID != id {
			t.Errorf("listed key ID = %q, want %q", keys[0].ID, id)
		}
	})

	t.Run("list_preserves_scopes", func(t *testing.T) {
		e := newTestEnforcer(t)
		_, _, err := e.CreateKey("scoped", RoleOperator, []string{"lan", "wan"}, []string{"strict", "default"})
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		keys, err := e.ListKeys()
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		k := keys[0]
		if len(k.ZoneScope) != 2 || k.ZoneScope[0] != "lan" || k.ZoneScope[1] != "wan" {
			t.Errorf("zone_scope = %v, want [lan wan]", k.ZoneScope)
		}
		if len(k.ProfileScope) != 2 || k.ProfileScope[0] != "strict" || k.ProfileScope[1] != "default" {
			t.Errorf("profile_scope = %v, want [strict default]", k.ProfileScope)
		}
	})
}

// ---------------------------------------------------------------------------
// Enforcer: RotateKey
// ---------------------------------------------------------------------------

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

		// New key should work (via DB fallback since it's not cached yet).
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

	t.Run("rotate_clears_old_cache", func(t *testing.T) {
		oldKey, id, err := e.CreateKey("rotate-cache", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}

		// Verify old key is in cache.
		e.mu.RLock()
		_, inCache := e.cache[oldKey]
		e.mu.RUnlock()
		if !inCache {
			t.Fatal("old key should be in cache before rotation")
		}

		_, err = e.RotateKey(id)
		if err != nil {
			t.Fatalf("RotateKey: %v", err)
		}

		// Verify old key is removed from cache.
		e.mu.RLock()
		_, inCache = e.cache[oldKey]
		e.mu.RUnlock()
		if inCache {
			t.Error("old key should be removed from cache after rotation")
		}
	})

	t.Run("rotate_preserves_metadata", func(t *testing.T) {
		_, id, err := e.CreateKey("rotate-meta", RoleDiagnostics, []string{"dmz"}, []string{"custom"})
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}

		newKey, err := e.RotateKey(id)
		if err != nil {
			t.Fatalf("RotateKey: %v", err)
		}

		ak, err := e.ValidateKey(newKey)
		if err != nil {
			t.Fatalf("ValidateKey: %v", err)
		}
		if ak.Name != "rotate-meta" {
			t.Errorf("name = %q, want %q", ak.Name, "rotate-meta")
		}
		if ak.Role != RoleDiagnostics {
			t.Errorf("role = %q, want %q", ak.Role, RoleDiagnostics)
		}
	})

	t.Run("double_rotate", func(t *testing.T) {
		key1, id, err := e.CreateKey("double-rotate", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}

		key2, err := e.RotateKey(id)
		if err != nil {
			t.Fatalf("first RotateKey: %v", err)
		}

		key3, err := e.RotateKey(id)
		if err != nil {
			t.Fatalf("second RotateKey: %v", err)
		}

		// All three keys should be different.
		if key1 == key2 || key2 == key3 || key1 == key3 {
			t.Error("all rotated keys should be unique")
		}

		// Only key3 should work.
		if _, err := e.ValidateKey(key1); err != ErrInvalidKey {
			t.Errorf("key1 should be invalid, got %v", err)
		}
		if _, err := e.ValidateKey(key2); err != ErrInvalidKey {
			t.Errorf("key2 should be invalid, got %v", err)
		}
		if _, err := e.ValidateKey(key3); err != nil {
			t.Errorf("key3 should be valid, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// NewEnforcer
// ---------------------------------------------------------------------------

func TestNewEnforcer(t *testing.T) {
	t.Run("creates_table", func(t *testing.T) {
		db := newTestDB(t)
		e, err := NewEnforcer(db)
		if err != nil {
			t.Fatalf("NewEnforcer: %v", err)
		}
		if e == nil {
			t.Fatal("enforcer should not be nil")
		}
		// Table should exist: we can create a key.
		_, _, err = e.CreateKey("test", RoleAdmin, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey after NewEnforcer: %v", err)
		}
	})

	t.Run("idempotent_table_creation", func(t *testing.T) {
		db := newTestDB(t)
		_, err := NewEnforcer(db)
		if err != nil {
			t.Fatalf("first NewEnforcer: %v", err)
		}
		// Creating a second enforcer on the same DB should not fail.
		e2, err := NewEnforcer(db)
		if err != nil {
			t.Fatalf("second NewEnforcer: %v", err)
		}
		if e2 == nil {
			t.Fatal("second enforcer should not be nil")
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
	operatorKey, _, err := e.CreateKey("operator-key", RoleOperator, nil, nil)
	if err != nil {
		t.Fatalf("CreateKey operator: %v", err)
	}

	// A simple handler that writes context values.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := RoleFromContext(r.Context())
		ak := APIKeyFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		if ak != nil {
			w.Write([]byte("role=" + role + ",id=" + ak.ID))
		} else {
			w.Write([]byte("role=" + role))
		}
	})

	mw := RBACMiddleware(e)(handler)

	t.Run("unauthenticated_endpoint_no_key", func(t *testing.T) {
		for _, path := range []string{"/api/v1/healthz", "/api/v1/status", "/api/v1/readyz", "/api/v1/metrics"} {
			r := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("path %s: status = %d, want %d", path, w.Code, http.StatusOK)
			}
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

	t.Run("operator_mcp_connect_denied", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+operatorKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
		}
	})

	t.Run("revoked_key_unauthorized", func(t *testing.T) {
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

	t.Run("mcp_agent_mcp_connect_allowed", func(t *testing.T) {
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

	t.Run("context_contains_api_key_and_role", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Bearer "+adminKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}
		body := w.Body.String()
		if body == "" {
			t.Error("response body should not be empty")
		}
		// The handler writes "role=admin,id=<id>".
		if !contains(body, "role=admin") {
			t.Errorf("body %q should contain role=admin", body)
		}
		if !contains(body, "id=") {
			t.Errorf("body %q should contain id=", body)
		}
	})

	t.Run("diagnostics_diag_active_allowed", func(t *testing.T) {
		diagKey, _, err := e.CreateKey("diag-key", RoleDiagnostics, nil, nil)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		r := httptest.NewRequest("POST", "/api/v1/diag/ping", nil)
		r.Header.Set("Authorization", "Bearer "+diagKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("auditor_diag_active_denied", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/v1/diag/ping", nil)
		r.Header.Set("Authorization", "Bearer "+auditorKey)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
		}
	})

	t.Run("basic_auth_password_as_key", func(t *testing.T) {
		creds := base64.StdEncoding.EncodeToString([]byte("user:" + adminKey))
		r := httptest.NewRequest("GET", "/api/v1/zones", nil)
		r.Header.Set("Authorization", "Basic "+creds)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// contains is a small helper since strings.Contains is in "strings"
// which is not imported; we keep the test file imports minimal.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
	if ValidRoles[""] {
		t.Error("empty string should not be a valid role")
	}
}

// ---------------------------------------------------------------------------
// writeJSONError
// ---------------------------------------------------------------------------

func TestWriteJSONError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		msg    string
	}{
		{"forbidden", http.StatusForbidden, "access denied"},
		{"unauthorized", http.StatusUnauthorized, "invalid api key"},
		{"internal", http.StatusInternalServerError, "internal error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeJSONError(w, tc.status, tc.msg)
			if w.Code != tc.status {
				t.Errorf("status = %d, want %d", w.Code, tc.status)
			}
			ct := w.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}
			body := w.Body.String()
			expected := `{"error":` + `"` + tc.msg + `"` + `}`
			if body != expected {
				t.Errorf("body = %q, want %q", body, expected)
			}
		})
	}
}
