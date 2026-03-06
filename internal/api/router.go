package api

import (
	"encoding/json"
	"net/http"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
)

// NewRouter creates the HTTP handler for the Gatekeeper API.
func NewRouter(store *config.Store) http.Handler {
	return NewRouterWithDriver(store, nil, "")
}

// NewRouterWithDriver creates the HTTP handler with an optional nftables driver.
func NewRouterWithDriver(store *config.Store, nft *driver.NFTables, apiKey string) http.Handler {
	h := &handlers{store: store, nft: nft}

	mux := http.NewServeMux()

	// Status (unauthenticated).
	mux.HandleFunc("GET /api/v1/status", handleStatus)

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

	// Profiles.
	mux.HandleFunc("GET /api/v1/profiles", h.listProfiles)
	mux.HandleFunc("POST /api/v1/profiles", h.createProfile)
	mux.HandleFunc("GET /api/v1/profiles/{name}", h.getProfile)
	mux.HandleFunc("PUT /api/v1/profiles/{name}", h.updateProfile)

	// Policies.
	mux.HandleFunc("GET /api/v1/policies", h.listPolicies)
	mux.HandleFunc("POST /api/v1/policies", h.createPolicy)
	mux.HandleFunc("GET /api/v1/policies/{name}", h.getPolicy)
	mux.HandleFunc("PUT /api/v1/policies/{name}", h.updatePolicy)
	mux.HandleFunc("DELETE /api/v1/policies/{name}", h.deletePolicy)

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

	// Diagnostics.
	mux.HandleFunc("GET /api/v1/diag/interfaces", h.diagInterfaces)
	mux.HandleFunc("GET /api/v1/diag/dry-run", h.dryRun)

	// Apply middleware stack.
	var handler http.Handler = mux
	if apiKey != "" {
		handler = AuthMiddleware(apiKey, handler)
	}
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
