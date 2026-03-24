// Package rbac implements Role-Based Access Control for the Gatekeeper API.
//
// It provides predefined roles (admin, operator, auditor, diagnostics, mcp-agent),
// scoped API key management with bcrypt-hashed storage, permission checking,
// and HTTP middleware for authorization enforcement.
package rbac

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// cacheKey returns a SHA-256 hex digest of the plaintext API key.
// The cache must never store raw keys — if memory is dumped, only
// the irreversible hash is exposed.
func cacheKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// Predefined role names.
const (
	RoleAdmin       = "admin"
	RoleOperator    = "operator"
	RoleAuditor     = "auditor"
	RoleDiagnostics = "diagnostics"
	RoleMCPAgent    = "mcp-agent"
)

// Action constants for permission checks.
const (
	ActionZonesRead     = "zones:read"
	ActionZonesWrite    = "zones:write"
	ActionAliasesRead   = "aliases:read"
	ActionAliasesWrite  = "aliases:write"
	ActionProfilesRead  = "profiles:read"
	ActionProfilesWrite = "profiles:write"
	ActionPoliciesRead  = "policies:read"
	ActionPoliciesWrite = "policies:write"
	ActionDevicesRead   = "devices:read"
	ActionDevicesWrite  = "devices:write"
	ActionConfigCommit  = "config:commit"
	ActionConfigRollback = "config:rollback"
	ActionConfigExport  = "config:export"
	ActionConfigImport  = "config:import"
	ActionWGRead        = "wg:read"
	ActionWGWrite       = "wg:write"
	ActionDiagRead      = "diag:read"
	ActionDiagActive    = "diag:active"
	ActionAuditRead     = "audit:read"
	ActionServicesRead  = "services:read"
	ActionServicesWrite = "services:write"
	ActionMCPConnect    = "mcp:connect"

	// Content filtering.
	ActionContentFilterRead     = "content_filter:read"
	ActionContentFilterWrite    = "content_filter:write"
	ActionExceptionRequest      = "content_filter:exception_request"
	ActionExceptionApprove      = "content_filter:exception_approve" // Admin-only: approve/deny/revoke exceptions.
)

// ValidRoles contains all recognized role names.
var ValidRoles = map[string]bool{
	RoleAdmin:       true,
	RoleOperator:    true,
	RoleAuditor:     true,
	RoleDiagnostics: true,
	RoleMCPAgent:    true,
}

// rolePermissions defines the set of actions each role is allowed to perform.
var rolePermissions = map[string]map[string]bool{
	RoleAdmin: {
		ActionZonesRead: true, ActionZonesWrite: true,
		ActionAliasesRead: true, ActionAliasesWrite: true,
		ActionProfilesRead: true, ActionProfilesWrite: true,
		ActionPoliciesRead: true, ActionPoliciesWrite: true,
		ActionDevicesRead: true, ActionDevicesWrite: true,
		ActionConfigCommit: true, ActionConfigRollback: true,
		ActionConfigExport: true, ActionConfigImport: true,
		ActionWGRead: true, ActionWGWrite: true,
		ActionDiagRead: true, ActionDiagActive: true,
		ActionAuditRead: true,
		ActionServicesRead: true, ActionServicesWrite: true,
		ActionMCPConnect: true,
		ActionContentFilterRead: true, ActionContentFilterWrite: true,
		ActionExceptionRequest: true, ActionExceptionApprove: true,
	},
	RoleOperator: {
		ActionZonesRead: true, ActionZonesWrite: true,
		ActionAliasesRead: true, ActionAliasesWrite: true,
		ActionProfilesRead: true, ActionProfilesWrite: true,
		ActionPoliciesRead: true, ActionPoliciesWrite: true,
		ActionDevicesRead: true, ActionDevicesWrite: true,
		ActionConfigCommit: true, ActionConfigRollback: true,
		ActionConfigExport: true, ActionConfigImport: true,
		ActionWGRead: true, ActionWGWrite: true,
		ActionDiagRead: true, ActionDiagActive: true,
		ActionAuditRead: true,
		ActionServicesRead: true, ActionServicesWrite: true,
		ActionContentFilterRead: true, ActionContentFilterWrite: true,
		ActionExceptionRequest: true,
	},
	RoleAuditor: {
		ActionZonesRead: true,
		ActionAliasesRead: true,
		ActionProfilesRead: true,
		ActionPoliciesRead: true,
		ActionDevicesRead: true,
		ActionConfigExport: true,
		ActionWGRead: true,
		ActionDiagRead: true,
		ActionAuditRead: true,
		ActionServicesRead: true,
		ActionContentFilterRead: true,
	},
	RoleDiagnostics: {
		ActionZonesRead: true,
		ActionAliasesRead: true,
		ActionProfilesRead: true,
		ActionPoliciesRead: true,
		ActionDevicesRead: true,
		ActionConfigExport: true,
		ActionWGRead: true,
		ActionDiagRead: true, ActionDiagActive: true,
		ActionAuditRead: true,
		ActionServicesRead: true,
	},
	RoleMCPAgent: {
		ActionZonesRead: true,
		ActionAliasesRead: true,
		ActionProfilesRead: true,
		ActionPoliciesRead: true,
		ActionDevicesRead: true, ActionDevicesWrite: true, // device assignment
		ActionConfigExport: true,
		ActionWGRead: true,
		ActionDiagRead: true,
		ActionServicesRead: true,
		ActionMCPConnect: true,
	},
}

// Context keys for storing RBAC info in request context.
type contextKey int

const (
	contextKeyAPIKey contextKey = iota
	contextKeyRole
)

// APIKey represents a stored API key with its metadata.
type APIKey struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	KeyHash      string    `json:"-"`
	Role         string    `json:"role"`
	ZoneScope    []string  `json:"zone_scope,omitempty"`
	ProfileScope []string  `json:"profile_scope,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Active       bool      `json:"active"`
}

// APIKeyInfo is the safe-to-display subset of APIKey (no hash).
type APIKeyInfo struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Role         string     `json:"role"`
	ZoneScope    []string   `json:"zone_scope,omitempty"`
	ProfileScope []string   `json:"profile_scope,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Active       bool       `json:"active"`
}

// Errors returned by the RBAC package.
var (
	ErrInvalidRole    = errors.New("rbac: invalid role")
	ErrKeyNotFound    = errors.New("rbac: api key not found")
	ErrKeyInactive    = errors.New("rbac: api key is inactive")
	ErrKeyExpired     = errors.New("rbac: api key has expired")
	ErrInvalidKey     = errors.New("rbac: invalid api key")
	ErrPermission     = errors.New("rbac: permission denied")
)

// Can reports whether the given role is allowed to perform the specified action.
func Can(role, action string) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms[action]
}

// CanForZone checks whether a role can perform an action, constrained to zone scopes.
// If scopes is nil or empty, the action is allowed (no restriction). Otherwise the
// zone must appear in the scopes list.
func CanForZone(role, action, zone string, scopes []string) bool {
	if !Can(role, action) {
		return false
	}
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == zone {
			return true
		}
	}
	return false
}

// CanForProfile checks whether a role can perform an action, constrained to profile scopes.
// If scopes is nil or empty, the action is allowed (no restriction). Otherwise the
// profile must appear in the scopes list.
func CanForProfile(role, action, profile string, scopes []string) bool {
	if !Can(role, action) {
		return false
	}
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == profile {
			return true
		}
	}
	return false
}

// Enforcer manages API keys and permission enforcement backed by a SQL database.
type Enforcer struct {
	db *sql.DB

	// mu protects the key cache for concurrent access.
	mu    sync.RWMutex
	cache map[string]*APIKey // keyed by raw key (hex) for fast lookup
}

// NewEnforcer creates a new RBAC enforcer backed by the given database.
// It creates the api_keys table if it does not exist and loads existing keys
// into an in-memory cache for fast validation.
func NewEnforcer(db *sql.DB) (*Enforcer, error) {
	if err := createTable(db); err != nil {
		return nil, fmt.Errorf("rbac: create table: %w", err)
	}
	e := &Enforcer{
		db:    db,
		cache: make(map[string]*APIKey),
	}
	return e, nil
}

// createTable ensures the api_keys table exists.
func createTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			key_hash     TEXT NOT NULL,
			role         TEXT NOT NULL,
			zone_scope   TEXT NOT NULL DEFAULT '',
			profile_scope TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL,
			expires_at   TEXT NOT NULL DEFAULT '',
			active       INTEGER NOT NULL DEFAULT 1
		)
	`)
	return err
}

// generateID produces a 16-byte hex-encoded random identifier.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rbac: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateRawKey produces a 32-byte hex-encoded random API key (64 hex chars).
func generateRawKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rbac: generate key: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// joinScopes encodes a string slice as a comma-separated string for storage.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, ",")
}

// splitScopes decodes a comma-separated string back into a string slice.
func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// CreateKey generates a new API key with the given name and role. It returns the
// plaintext key (shown only once) and the key's unique ID. Optional zone and
// profile scopes restrict the key's access to the named resources.
func (e *Enforcer) CreateKey(name, role string, zoneScope, profileScope []string) (key string, id string, err error) {
	if !ValidRoles[role] {
		return "", "", ErrInvalidRole
	}

	// Reject scope values containing the delimiter to prevent parsing ambiguity.
	for _, s := range zoneScope {
		if strings.Contains(s, ",") {
			return "", "", fmt.Errorf("rbac: zone scope %q contains invalid comma", s)
		}
	}
	for _, s := range profileScope {
		if strings.Contains(s, ",") {
			return "", "", fmt.Errorf("rbac: profile scope %q contains invalid comma", s)
		}
	}

	id, err = generateID()
	if err != nil {
		return "", "", err
	}

	key, err = generateRawKey()
	if err != nil {
		return "", "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("rbac: hash key: %w", err)
	}

	now := time.Now().UTC()
	_, err = e.db.Exec(`
		INSERT INTO api_keys (id, name, key_hash, role, zone_scope, profile_scope, created_at, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)
	`, id, name, string(hash), role, joinScopes(zoneScope), joinScopes(profileScope), now.Format(time.RFC3339))
	if err != nil {
		return "", "", fmt.Errorf("rbac: insert key: %w", err)
	}

	// Cache the key for fast validation (keyed by SHA-256, not plaintext).
	e.mu.Lock()
	e.cache[cacheKey(key)] = &APIKey{
		ID:           id,
		Name:         name,
		KeyHash:      string(hash),
		Role:         role,
		ZoneScope:    zoneScope,
		ProfileScope: profileScope,
		CreatedAt:    now,
		Active:       true,
	}
	e.mu.Unlock()

	slog.Info("rbac: api key created", "id", id, "name", name, "role", role)
	return key, id, nil
}

// ValidateKey checks a plaintext API key and returns the associated APIKey record.
// It first checks the in-memory cache, then falls back to scanning all keys
// in the database.
func (e *Enforcer) ValidateKey(key string) (*APIKey, error) {
	if key == "" {
		return nil, ErrInvalidKey
	}

	// Fast path: check cache (keyed by SHA-256 of plaintext).
	ck := cacheKey(key)
	e.mu.RLock()
	if cached, ok := e.cache[ck]; ok {
		e.mu.RUnlock()
		if !cached.Active {
			return nil, ErrKeyInactive
		}
		if cached.ExpiresAt != nil && time.Now().After(*cached.ExpiresAt) {
			return nil, ErrKeyExpired
		}
		return cached, nil
	}
	e.mu.RUnlock()

	// Slow path: scan all keys in the database. This handles keys created
	// by other processes or keys not yet in cache after a restart.
	rows, err := e.db.Query(`
		SELECT id, name, key_hash, role, zone_scope, profile_scope, created_at, expires_at, active
		FROM api_keys
	`)
	if err != nil {
		return nil, fmt.Errorf("rbac: query keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		ak, rawKey, err := scanAPIKey(rows)
		if err != nil {
			slog.Warn("rbac: scan key row failed", "error", err)
			continue
		}
		_ = rawKey // rawKey is unused; we compare bcrypt hashes

		if bcrypt.CompareHashAndPassword([]byte(ak.KeyHash), []byte(key)) == nil {
			// Found a match; cache it for future fast-path hits.
			e.mu.Lock()
			e.cache[ck] = ak
			e.mu.Unlock()

			if !ak.Active {
				return nil, ErrKeyInactive
			}
			if ak.ExpiresAt != nil && time.Now().After(*ak.ExpiresAt) {
				return nil, ErrKeyExpired
			}
			return ak, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: iterate keys: %w", err)
	}
	return nil, ErrInvalidKey
}

// scanAPIKey reads an APIKey from a sql.Rows cursor. It returns the key and
// an empty rawKey string (the raw key is never stored).
func scanAPIKey(rows *sql.Rows) (*APIKey, string, error) {
	var (
		ak              APIKey
		zoneScopeStr    string
		profileScopeStr string
		createdAtStr    string
		expiresAtStr    string
		activeInt       int
	)
	err := rows.Scan(&ak.ID, &ak.Name, &ak.KeyHash, &ak.Role,
		&zoneScopeStr, &profileScopeStr, &createdAtStr, &expiresAtStr, &activeInt)
	if err != nil {
		return nil, "", err
	}
	ak.ZoneScope = splitScopes(zoneScopeStr)
	ak.ProfileScope = splitScopes(profileScopeStr)
	ak.Active = activeInt != 0

	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		ak.CreatedAt = t
	}
	if expiresAtStr != "" {
		if t, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
			ak.ExpiresAt = &t
		}
	}
	return &ak, "", nil
}

// RevokeKey deactivates an API key by ID. Revoked keys are immediately
// rejected on subsequent validation attempts.
func (e *Enforcer) RevokeKey(id string) error {
	res, err := e.db.Exec(`UPDATE api_keys SET active = 0 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("rbac: revoke key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrKeyNotFound
	}

	// Invalidate cache entries for this key.
	e.mu.Lock()
	for hash, ak := range e.cache {
		if ak.ID == id {
			ak.Active = false
			e.cache[hash] = ak
		}
	}
	e.mu.Unlock()

	slog.Info("rbac: api key revoked", "id", id)
	return nil
}

// ListKeys returns metadata for all API keys (without hashes).
func (e *Enforcer) ListKeys() ([]APIKeyInfo, error) {
	rows, err := e.db.Query(`
		SELECT id, name, key_hash, role, zone_scope, profile_scope, created_at, expires_at, active
		FROM api_keys ORDER BY created_at DESC LIMIT 1000
	`)
	if err != nil {
		return nil, fmt.Errorf("rbac: list keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKeyInfo
	for rows.Next() {
		ak, _, err := scanAPIKey(rows)
		if err != nil {
			slog.Warn("rbac: scan key row failed", "error", err)
			continue
		}
		keys = append(keys, APIKeyInfo{
			ID:           ak.ID,
			Name:         ak.Name,
			Role:         ak.Role,
			ZoneScope:    ak.ZoneScope,
			ProfileScope: ak.ProfileScope,
			CreatedAt:    ak.CreatedAt,
			ExpiresAt:    ak.ExpiresAt,
			Active:       ak.Active,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: iterate keys: %w", err)
	}
	return keys, nil
}

// RotateKey generates a new secret for an existing key, preserving the same ID,
// role, and scopes. The old key is immediately invalidated. Returns the new
// plaintext key.
func (e *Enforcer) RotateKey(id string) (string, error) {
	// Verify key exists.
	var exists int
	err := e.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE id = ?`, id).Scan(&exists)
	if err != nil {
		return "", fmt.Errorf("rbac: check key existence: %w", err)
	}
	if exists == 0 {
		return "", ErrKeyNotFound
	}

	newKey, err := generateRawKey()
	if err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newKey), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("rbac: hash key: %w", err)
	}

	_, err = e.db.Exec(`UPDATE api_keys SET key_hash = ? WHERE id = ?`, string(hash), id)
	if err != nil {
		return "", fmt.Errorf("rbac: update key hash: %w", err)
	}

	// Purge old cache entries for this key ID and reload from DB.
	e.mu.Lock()
	for hash, ak := range e.cache {
		if ak.ID == id {
			delete(e.cache, hash)
		}
	}
	e.mu.Unlock()

	slog.Info("rbac: api key rotated", "id", id)
	return newKey, nil
}

// APIKeyFromContext extracts the APIKey stored by the RBAC middleware.
func APIKeyFromContext(ctx context.Context) *APIKey {
	ak, _ := ctx.Value(contextKeyAPIKey).(*APIKey)
	return ak
}

// RoleFromContext extracts the role string stored by the RBAC middleware.
func RoleFromContext(ctx context.Context) string {
	r, _ := ctx.Value(contextKeyRole).(string)
	return r
}

// routeAction maps an HTTP method and URL path to the RBAC action required.
// It returns an empty string for paths that do not require authorization
// (health checks, metrics).
func routeAction(method, path string) string {
	// Strip trailing slash for consistent matching.
	path = strings.TrimRight(path, "/")

	// Unauthenticated endpoints.
	switch path {
	case "/api/v1/status", "/api/v1/healthz", "/api/v1/readyz":
		return ""
	}

	// Determine the resource prefix and whether it's a read or write.
	isWrite := method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete

	switch {
	// Config management.
	case path == "/api/v1/config/commit":
		return ActionConfigCommit
	case strings.HasPrefix(path, "/api/v1/config/rollback"):
		return ActionConfigRollback
	case path == "/api/v1/config/import":
		return ActionConfigImport
	case path == "/api/v1/config/export":
		return ActionConfigExport
	case strings.HasPrefix(path, "/api/v1/config"):
		if isWrite {
			return ActionConfigCommit
		}
		return ActionConfigExport

	// Zones.
	case strings.HasPrefix(path, "/api/v1/zones"):
		if isWrite {
			return ActionZonesWrite
		}
		return ActionZonesRead

	// Aliases.
	case strings.HasPrefix(path, "/api/v1/aliases"):
		if isWrite {
			return ActionAliasesWrite
		}
		return ActionAliasesRead

	// Profiles.
	case strings.HasPrefix(path, "/api/v1/profiles"):
		if isWrite {
			return ActionProfilesWrite
		}
		return ActionProfilesRead

	// Policies and rules.
	case strings.HasPrefix(path, "/api/v1/policies"), strings.HasPrefix(path, "/api/v1/rules"):
		if isWrite {
			return ActionPoliciesWrite
		}
		return ActionPoliciesRead

	// Devices and assignment.
	case strings.HasPrefix(path, "/api/v1/devices"),
		path == "/api/v1/assign", path == "/api/v1/unassign":
		if isWrite {
			return ActionDevicesWrite
		}
		return ActionDevicesRead

	// WireGuard.
	case strings.HasPrefix(path, "/api/v1/wg"):
		if isWrite {
			return ActionWGWrite
		}
		return ActionWGRead

	// Diagnostics — active endpoints (ping, connections) vs passive reads.
	case strings.HasPrefix(path, "/api/v1/diag/ping"),
		path == "/api/v1/diag/connections":
		return ActionDiagActive
	case strings.HasPrefix(path, "/api/v1/diag"):
		return ActionDiagRead

	// Path test / explain — treated as diagnostic reads for mcp-agent.
	case path == "/api/v1/test", path == "/api/v1/explain":
		return ActionDiagRead

	// Audit log.
	case path == "/api/v1/audit":
		return ActionAuditRead

	// Services.
	case strings.HasPrefix(path, "/api/v1/services"):
		if isWrite {
			return ActionServicesWrite
		}
		return ActionServicesRead

	// Content filtering.
	case strings.HasPrefix(path, "/api/v1/content-filters/exceptions") && isWrite:
		// Exception review (approve/deny/revoke) requires admin approval permission.
		if strings.Contains(path, "/approve") || strings.Contains(path, "/deny") || strings.Contains(path, "/revoke") {
			return ActionExceptionApprove
		}
		return ActionExceptionRequest
	case strings.HasPrefix(path, "/api/v1/content-filters"):
		if isWrite {
			return ActionContentFilterWrite
		}
		return ActionContentFilterRead

	// MCP websocket/SSE endpoint.
	case strings.HasPrefix(path, "/api/v1/mcp"):
		return ActionMCPConnect

	// Metrics — requires auth (exposes uptime, request counts, goroutine info).
	case path == "/api/v1/metrics":
		return ActionDiagRead

	// IOCs / threat intelligence.
	case strings.HasPrefix(path, "/api/v1/iocs"):
		if isWrite {
			return ActionServicesWrite
		}
		return ActionServicesRead

	// Fingerprints.
	case strings.HasPrefix(path, "/api/v1/fingerprints"):
		return ActionDiagRead

	// XDP / countermeasures.
	case strings.HasPrefix(path, "/api/v1/xdp"):
		if isWrite {
			return ActionServicesWrite
		}
		return ActionServicesRead

	// API keys management.
	case strings.HasPrefix(path, "/api/v1/keys"):
		if isWrite {
			return ActionConfigCommit
		}
		return ActionConfigExport

	// MTU management.
	case strings.HasPrefix(path, "/api/v1/mtu"):
		if isWrite {
			return ActionServicesWrite
		}
		return ActionServicesRead

	// Performance / NIC info.
	case strings.HasPrefix(path, "/api/v1/perf"):
		return ActionDiagRead
	}

	// Unknown path: deny by default by returning a non-existent action
	// that no role has permission for.
	return "unknown:unknown"
}

// RBACMiddleware returns HTTP middleware that enforces role-based access control.
// It extracts the API key from the Authorization header (Bearer token) or
// X-API-Key header, validates it, checks the required permission for the
// route, and stores the key and role in the request context.
//
// Requests to unauthenticated endpoints (status, healthz, readyz, metrics)
// are passed through without checks.
func RBACMiddleware(enforcer *Enforcer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			action := routeAction(r.Method, r.URL.Path)
			if action == "" {
				// Unauthenticated endpoint.
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key from request.
			rawKey := extractKey(r)
			if rawKey == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing api key")
				return
			}

			ak, err := enforcer.ValidateKey(rawKey)
			if err != nil {
				// Log the specific reason server-side for debugging,
				// but return a generic message to prevent key enumeration.
				slog.Debug("rbac: authentication failed", "error", err, "remote", r.RemoteAddr)
				writeJSONError(w, http.StatusUnauthorized, "invalid api key")
				return
			}

			// Check role permission for the action.
			if !Can(ak.Role, action) {
				slog.Warn("rbac: permission denied",
					"key_id", ak.ID,
					"role", ak.Role,
					"action", action,
					"method", r.Method,
					"path", r.URL.Path,
				)
				writeJSONError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			// Store key info in context for downstream handlers.
			ctx := context.WithValue(r.Context(), contextKeyAPIKey, ak)
			ctx = context.WithValue(ctx, contextKeyRole, ak.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractKey retrieves the API key from the request. It checks:
//  1. Authorization: Bearer <key>
//  2. X-API-Key header
//  3. Basic auth password
func extractKey(r *http.Request) string {
	// Bearer token.
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			return strings.TrimSpace(auth[len(prefix):])
		}
	}

	// X-API-Key header (legacy support).
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Basic auth (password field).
	if _, pw, ok := r.BasicAuth(); ok && pw != "" {
		return pw
	}

	return ""
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
