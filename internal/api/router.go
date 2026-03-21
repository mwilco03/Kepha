package api

import (
	"encoding/json"
	"net/http"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/inspect"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
	"github.com/gatekeeper-firewall/gatekeeper/internal/rbac"
	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
)

// RouterConfig holds all dependencies for the API router.
type RouterConfig struct {
	Store   *config.Store
	NFT     backend.Firewall // Was *driver.NFTables; now accepts any Firewall implementation.
	WG      *driver.WireGuard
	Dnsmasq *driver.Dnsmasq
	APIKey  string
	Metrics *Metrics

	// ServiceMgr is the pluggable service manager (optional).
	ServiceMgr *service.Manager

	// Net is the network manager for ping, connections, conntrack (optional).
	Net backend.NetworkManager

	// RBACEnforcer enables role-based access control when set.
	// When nil, falls back to the legacy single API key auth.
	RBACEnforcer *rbac.Enforcer

	// FingerprintSvc is the TLS fingerprint service (optional).
	FingerprintSvc *service.FingerprintService

	// IOCStore is the indicator of compromise store (optional).
	IOCStore *inspect.IOCStore
	// MMDBUpdater is the ASN mmdb auto-updater (optional).
	MMDBUpdater *inspect.MMDBUpdater

	// ContentFilterEngine is the content filter engine (optional).
	ContentFilterEngine *service.ContentFilterEngine

	// MTUMgr is the MTU management service (optional).
	MTUMgr *service.MTUManager

	// XDPSvc is the XDP fast path service (optional).
	XDPSvc *service.XDPService

	// RateLimit controls API rate limiting (requests/sec). 0 = default (100/s).
	RateLimit int
	// DiagRateLimit controls diagnostic endpoint rate limiting. 0 = default (5/s).
	DiagRateLimit int
}

// NewRouter creates the HTTP handler for the Gatekeeper API.
func NewRouter(store *config.Store) http.Handler {
	return NewRouterWithDriver(store, nil, "")
}

// NewRouterWithDriver creates the HTTP handler with an optional firewall backend.
func NewRouterWithDriver(store *config.Store, nft backend.Firewall, apiKey string) http.Handler {
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
		net:     cfg.Net,
	}

	metrics := cfg.Metrics
	if metrics == nil {
		metrics = NewMetrics()
	}

	mux := http.NewServeMux()

	// Health checks (unauthenticated per OpenAPI spec).
	mux.HandleFunc("GET /api/v1/status", handleStatus)
	mux.HandleFunc("GET /api/v1/healthz", handleStatus) // Liveness: process is running.
	mux.HandleFunc("GET /api/v1/readyz", h.handleReady) // Readiness: DB is accessible.

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
	mux.HandleFunc("POST /api/v1/wg/prune", h.pruneWGPeers)

	// Path test and explain.
	mux.HandleFunc("POST /api/v1/test", h.pathTest)
	mux.HandleFunc("POST /api/v1/explain", h.explainPath)

	// Audit log.
	mux.HandleFunc("GET /api/v1/audit", h.listAuditLog)

	// Services — pluggable service management.
	if cfg.ServiceMgr != nil {
		sh := &serviceHandlers{mgr: cfg.ServiceMgr}
		mux.HandleFunc("GET /api/v1/services", sh.listServices)
		mux.HandleFunc("GET /api/v1/services/{name}", sh.getService)
		mux.HandleFunc("GET /api/v1/services/{name}/schema", sh.getServiceSchema)
		mux.HandleFunc("POST /api/v1/services/{name}/enable", sh.enableService)
		mux.HandleFunc("POST /api/v1/services/{name}/disable", sh.disableService)
		mux.HandleFunc("PUT /api/v1/services/{name}/config", sh.configureService)
	}

	// Fingerprint endpoints (requires fingerprint service).
	if cfg.FingerprintSvc != nil {
		fph := &fingerprintHandlers{svc: cfg.FingerprintSvc}
		mux.HandleFunc("GET /api/v1/fingerprints", fph.listFingerprints)
		mux.HandleFunc("GET /api/v1/fingerprints/{hash}", fph.getFingerprint)
		mux.HandleFunc("GET /api/v1/fingerprints/{hash}/identify", fph.identifyFingerprint)
		mux.HandleFunc("POST /api/v1/fingerprints/{hash}/assign", fph.assignProfile)
		mux.HandleFunc("GET /api/v1/fingerprints/{hash}/threat", fph.checkThreat)
	}

	// IOC management endpoints (requires IOC store).
	if cfg.IOCStore != nil {
		ih := &iocHandlers{store: cfg.IOCStore, updater: cfg.MMDBUpdater}
		mux.HandleFunc("GET /api/v1/iocs", ih.listIOCs)
		mux.HandleFunc("POST /api/v1/iocs", ih.addIOC)
		mux.HandleFunc("POST /api/v1/iocs/bulk", ih.bulkAddIOCs)
		mux.HandleFunc("DELETE /api/v1/iocs/{type}/{value}", ih.removeIOC)
		mux.HandleFunc("GET /api/v1/iocs/match", ih.matchIOC)
		mux.HandleFunc("GET /api/v1/iocs/stats", ih.iocStats)
		mux.HandleFunc("GET /api/v1/iocs/templates", ih.listTemplates)
		mux.HandleFunc("POST /api/v1/iocs/templates", ih.addTemplate)
		mux.HandleFunc("DELETE /api/v1/iocs/templates/{name}", ih.removeTemplate)
		mux.HandleFunc("GET /api/v1/iocs/mmdb", ih.mmdbStatus)
		mux.HandleFunc("POST /api/v1/iocs/mmdb/refresh", ih.mmdbRefresh)
		mux.HandleFunc("POST /api/v1/iocs/mmdb/config", ih.mmdbConfig)
	}

	// MTU management endpoints (requires MTU manager).
	if cfg.MTUMgr != nil {
		mh := &mtuHandlers{mgr: cfg.MTUMgr, store: cfg.Store}
		mux.HandleFunc("GET /api/v1/mtu/status", mh.mtuStatus)
	}

	// XDP fast path endpoints (requires XDP service).
	if cfg.XDPSvc != nil {
		xh := &xdpHandlers{svc: cfg.XDPSvc}
		mux.HandleFunc("GET /api/v1/xdp/status", xh.xdpStatus)
		mux.HandleFunc("GET /api/v1/xdp/capabilities", xh.xdpCapabilities)
		mux.HandleFunc("GET /api/v1/xdp/stats", xh.xdpStats)
		mux.HandleFunc("GET /api/v1/xdp/blocklist", xh.listBlocklist)
		mux.HandleFunc("POST /api/v1/xdp/blocklist", xh.addBlocklistEntry)
		mux.HandleFunc("DELETE /api/v1/xdp/blocklist/{ip}", xh.removeBlocklistEntry)
		mux.HandleFunc("GET /api/v1/xdp/acls", xh.listACLRules)
		mux.HandleFunc("POST /api/v1/xdp/acls", xh.addACLRule)
	}

	// Content filtering (requires content filter engine or store).
	{
		cfh := &contentFilterHandlers{store: cfg.Store, engine: cfg.ContentFilterEngine}
		mux.HandleFunc("GET /api/v1/content-filters", cfh.listFilters)
		mux.HandleFunc("POST /api/v1/content-filters", cfh.createFilter)
		mux.HandleFunc("GET /api/v1/content-filters/{name}", cfh.getFilter)
		mux.HandleFunc("PUT /api/v1/content-filters/{name}", cfh.updateFilter)
		mux.HandleFunc("DELETE /api/v1/content-filters/{name}", cfh.deleteFilter)

		// Exception workflow: request → review (admin approve/deny) → revoke.
		mux.HandleFunc("GET /api/v1/content-filters/exceptions", cfh.listExceptions)
		mux.HandleFunc("POST /api/v1/content-filters/exceptions", cfh.requestException)
		mux.HandleFunc("GET /api/v1/content-filters/exceptions/{id}", cfh.getException)
		mux.HandleFunc("POST /api/v1/content-filters/exceptions/{id}/approve", cfh.approveException)
		mux.HandleFunc("POST /api/v1/content-filters/exceptions/{id}/deny", cfh.denyException)
		mux.HandleFunc("POST /api/v1/content-filters/exceptions/{id}/revoke", cfh.revokeException)

		// Check/test a domain against filters.
		mux.HandleFunc("GET /api/v1/content-filters/check", cfh.checkDomain)
		mux.HandleFunc("GET /api/v1/content-filters/stats", cfh.stats)
	}

	// RBAC key management (requires RBAC to be enabled).
	if cfg.RBACEnforcer != nil {
		kh := &keyHandlers{enforcer: cfg.RBACEnforcer}
		mux.HandleFunc("GET /api/v1/keys", kh.listKeys)
		mux.HandleFunc("POST /api/v1/keys", kh.createKey)
		mux.HandleFunc("DELETE /api/v1/keys/{id}", kh.revokeKey)
		mux.HandleFunc("POST /api/v1/keys/{id}/rotate", kh.rotateKey)
	}

	// Diagnostics — rate-limited more aggressively since ping/connections
	// execute system commands and could be abused for resource exhaustion.
	diagRate := cfg.DiagRateLimit
	if diagRate <= 0 {
		diagRate = 5
	}
	diagLimiter := NewRateLimiter(diagRate, diagRate*2)
	diagRL := diagLimiter.Middleware

	mux.HandleFunc("GET /api/v1/diag/interfaces", h.diagInterfaces)   // Read-only, zone-to-interface map.
	mux.HandleFunc("GET /api/v1/diag/links", h.diagLinks)             // Read-only, all system interfaces via netlink.
	mux.HandleFunc("GET /api/v1/diag/topology", h.diagTopology)       // Auto-detect WAN/LAN layout.
	mux.HandleFunc("GET /api/v1/diag/leases", h.diagLeases)         // Read-only, file parse.
	mux.HandleFunc("GET /api/v1/perf/nic", h.perfNIC)               // Read-only, sysfs + ethtool.
	mux.HandleFunc("GET /api/v1/diag/dry-run", h.dryRun)
	mux.Handle("GET /api/v1/diag/ping/{target}", diagRL(http.HandlerFunc(h.diagPing)))
	mux.Handle("GET /api/v1/diag/connections", diagRL(http.HandlerFunc(h.diagConnections)))

	// Middleware stack (outermost first):
	// 1. Logging — always logs, even rejected requests
	// 2. Security headers — defensive HTTP headers on every response
	// 3. Rate limiting — shed load before auth check
	// 4. Auth — reject unauthenticated
	// 5. Audit — log mutations (POST/PUT/DELETE)
	// 6. Metrics counting
	var handler http.Handler = mux
	handler = metrics.CountingMiddleware(handler)
	handler = AuditMiddleware(handler)
	if cfg.RBACEnforcer != nil {
		handler = rbac.RBACMiddleware(cfg.RBACEnforcer)(handler)
	} else if cfg.APIKey != "" {
		handler = AuthMiddleware(cfg.APIKey, handler)
	}
	apiRate := cfg.RateLimit
	if apiRate <= 0 {
		apiRate = 100
	}
	apiLimiter := NewRateLimiter(apiRate, apiRate*2)
	handler = apiLimiter.Middleware(handler)
	handler = SecurityHeadersMiddleware(handler)
	handler = LoggingMiddleware(handler)

	return handler
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "gatekeeperd",
	})
}

// handleReady checks that the database is accessible and firewall is loaded (readiness probe).
func (h *handlers) handleReady(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}

	if err := h.ops.Store().Ping(); err != nil {
		checks["database"] = "unavailable"
	} else {
		checks["database"] = "ok"
	}

	// Verify firewall has compiled rules (best-effort).
	if h.nft != nil {
		if _, err := h.nft.DryRun(); err != nil {
			checks["firewall"] = "error"
		} else {
			checks["firewall"] = "ok"
		}
	}

	checks["service"] = "gatekeeperd"
	if checks["database"] == "unavailable" {
		checks["status"] = "unavailable"
		writeJSON(w, http.StatusServiceUnavailable, checks)
		return
	}
	checks["status"] = "ready"
	writeJSON(w, http.StatusOK, checks)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
