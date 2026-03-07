package api

import (
	"encoding/json"
	"net/http"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
)

// RouterConfig holds all dependencies for the API router.
type RouterConfig struct {
	Store   *config.Store
	NFT     *driver.NFTables
	WG      *driver.WireGuard
	Dnsmasq *driver.Dnsmasq
	APIKey  string
	Metrics *Metrics

	// RateLimit controls API rate limiting (requests/sec). 0 = default (100/s).
	RateLimit int
	// DiagRateLimit controls diagnostic endpoint rate limiting. 0 = default (5/s).
	DiagRateLimit int
}

// NewRouter creates the HTTP handler for the Gatekeeper API.
func NewRouter(store *config.Store) http.Handler {
	return NewRouterWithDriver(store, nil, "")
}

// NewRouterWithDriver creates the HTTP handler with an optional nftables driver.
func NewRouterWithDriver(store *config.Store, nft *driver.NFTables, apiKey string) http.Handler {
	return NewRouterWithConfig(&RouterConfig{
		Store:  store,
		NFT:    nft,
		APIKey: apiKey,
	})
}

// NewRouterWithConfig creates the full API router from config.
func NewRouterWithConfig(cfg *RouterConfig) http.Handler {
	o := ops.New(cfg.Store)
	h := &handlers{
		ops:     o,
		wgOps:   ops.NewWireGuardOps(cfg.WG),
		nft:     cfg.NFT,
		dnsmasq: cfg.Dnsmasq,
	}

	metrics := cfg.Metrics
	if metrics == nil {
		metrics = NewMetrics()
	}

	mux := http.NewServeMux()

	// Status (unauthenticated).
	mux.HandleFunc("GET /api/v1/status", handleStatus)

	// Metrics (unauthenticated).
	mux.HandleFunc("GET /api/v1/metrics", metrics.Handler())

	// Zones.
	mux.HandleFunc("GET /api/v1/zones", h.listZones)
	mux.HandleFunc("POST /api/v1/zones", h.createZone)
	mux.HandleFunc("GET /api/v1/zones/{name}", h.getZone)
	mux.HandleFunc("PUT /api/v1/zones/{name}", h.updateZone)
	mux.HandleFunc("DELETE /api/v1/zones/{name}", h.deleteZone)

	// Aliases.
	mux.HandleFunc("GET /api/v1/aliases", h.listAliases)
	mux.HandleFunc("POST /api/v1/aliases", h.createAlias)
	mux.HandleFunc("GET /api/v1/aliases/{name}", h.getAlias)
	mux.HandleFunc("PUT /api/v1/aliases/{name}", h.updateAlias)
	mux.HandleFunc("DELETE /api/v1/aliases/{name}", h.deleteAlias)
	mux.HandleFunc("POST /api/v1/aliases/{name}/members", h.addAliasMember)
	mux.HandleFunc("DELETE /api/v1/aliases/{name}/members", h.removeAliasMember)

	// Profiles.
	mux.HandleFunc("GET /api/v1/profiles", h.listProfiles)
	mux.HandleFunc("POST /api/v1/profiles", h.createProfile)
	mux.HandleFunc("GET /api/v1/profiles/{name}", h.getProfile)
	mux.HandleFunc("PUT /api/v1/profiles/{name}", h.updateProfile)

	mux.HandleFunc("DELETE /api/v1/profiles/{name}", h.deleteProfile)

	// Policies.
	mux.HandleFunc("GET /api/v1/policies", h.listPolicies)
	mux.HandleFunc("POST /api/v1/policies", h.createPolicy)
	mux.HandleFunc("GET /api/v1/policies/{name}", h.getPolicy)
	mux.HandleFunc("PUT /api/v1/policies/{name}", h.updatePolicy)
	mux.HandleFunc("DELETE /api/v1/policies/{name}", h.deletePolicy)

	// Rules.
	mux.HandleFunc("POST /api/v1/policies/{name}/rules", h.createRule)
	mux.HandleFunc("DELETE /api/v1/rules/{id}", h.deleteRule)

	// Devices.
	mux.HandleFunc("GET /api/v1/devices", h.listDevices)
	mux.HandleFunc("POST /api/v1/assign", h.assignDevice)
	mux.HandleFunc("DELETE /api/v1/unassign", h.unassignDevice)

	// Config management.
	mux.HandleFunc("POST /api/v1/config/commit", h.commitConfig)
	mux.HandleFunc("POST /api/v1/config/rollback/{rev}", h.rollbackConfig)
	mux.HandleFunc("GET /api/v1/config/revisions", h.listRevisions)
	mux.HandleFunc("GET /api/v1/config/diff", h.diffConfig)
	mux.HandleFunc("GET /api/v1/config/export", h.exportConfig)
	mux.HandleFunc("POST /api/v1/config/import", h.importConfig)
	mux.HandleFunc("POST /api/v1/config/confirm", h.confirmApply)

	// WireGuard.
	mux.HandleFunc("GET /api/v1/wg/peers", h.listWGPeers)
	mux.HandleFunc("POST /api/v1/wg/peers", h.addWGPeer)
	mux.HandleFunc("DELETE /api/v1/wg/peers/{pubkey}", h.removeWGPeer)
	mux.HandleFunc("POST /api/v1/wg/client-config", h.generateWGClientConfig)

	// Path test and explain.
	mux.HandleFunc("POST /api/v1/test", h.pathTest)
	mux.HandleFunc("POST /api/v1/explain", h.explainPath)

	// Audit log.
	mux.HandleFunc("GET /api/v1/audit", h.listAuditLog)

	// Diagnostics — rate-limited more aggressively since ping/connections
	// execute system commands and could be abused for resource exhaustion.
	diagRate := cfg.DiagRateLimit
	if diagRate <= 0 {
		diagRate = 5
	}
	diagLimiter := NewRateLimiter(diagRate, diagRate*2)
	diagRL := diagLimiter.Middleware

	mux.HandleFunc("GET /api/v1/diag/interfaces", h.diagInterfaces) // Read-only, no subprocess.
	mux.HandleFunc("GET /api/v1/diag/leases", h.diagLeases)         // Read-only, file parse.
	mux.HandleFunc("GET /api/v1/diag/dry-run", h.dryRun)
	mux.Handle("GET /api/v1/diag/ping/{target}", diagRL(http.HandlerFunc(h.diagPing)))
	mux.Handle("GET /api/v1/diag/connections", diagRL(http.HandlerFunc(h.diagConnections)))

	// Apply middleware stack (outermost first):
	// 1. Logging — always logs, even rejected requests
	// 2. Rate limiting — shed load before auth check
	// 3. Auth — reject unauthenticated
	// 4. Audit — log mutations (POST/PUT/DELETE)
	// 5. Metrics counting
	var handler http.Handler = mux
	handler = metrics.CountingMiddleware(handler)
	handler = AuditMiddleware(handler)
	if cfg.APIKey != "" {
		handler = AuthMiddleware(cfg.APIKey, handler)
	}
	apiRate := cfg.RateLimit
	if apiRate <= 0 {
		apiRate = 100
	}
	apiLimiter := NewRateLimiter(apiRate, apiRate*2)
	handler = apiLimiter.Middleware(handler)
	handler = LoggingMiddleware(handler)

	return handler
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "gatekeeperd",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
