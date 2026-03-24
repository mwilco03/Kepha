package api

import (
	"encoding/json"
	"net/http"

	"github.com/mwilco03/kepha/internal/service"
	"github.com/mwilco03/kepha/internal/xdp"
)

// xdpHandlers handles XDP API endpoints.
type xdpHandlers struct {
	svc *service.XDPService
}

// xdpStatus returns XDP manager status.
// GET /api/v1/xdp/status
func (xh *xdpHandlers) xdpStatus(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}
	writeJSON(w, http.StatusOK, mgr.Status())
}

// xdpCapabilities returns system XDP capabilities.
// GET /api/v1/xdp/capabilities
func (xh *xdpHandlers) xdpCapabilities(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}
	writeJSON(w, http.StatusOK, mgr.Capabilities())
}

// xdpStats returns per-interface XDP statistics.
// GET /api/v1/xdp/stats
func (xh *xdpHandlers) xdpStats(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}
	stats := mgr.AllStats()
	if stats == nil {
		stats = []xdp.Stats{}
	}
	writeJSON(w, http.StatusOK, stats)
}

// listBlocklist returns the current XDP blocklist.
// GET /api/v1/xdp/blocklist
func (xh *xdpHandlers) listBlocklist(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}
	entries := mgr.BlocklistEntries()
	if entries == nil {
		entries = []xdp.BlocklistEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// addBlocklistEntry adds an IP to the XDP blocklist.
// POST /api/v1/xdp/blocklist
func (xh *xdpHandlers) addBlocklistEntry(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}

	var entry xdp.BlocklistEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if entry.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}

	if err := mgr.AddToBlocklist(entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added", "ip": entry.IP})
}

// removeBlocklistEntry removes an IP from the XDP blocklist.
// DELETE /api/v1/xdp/blocklist/{ip}
func (xh *xdpHandlers) removeBlocklistEntry(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}

	ip := r.PathValue("ip")
	if err := mgr.RemoveFromBlocklist(ip); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "ip": ip})
}

// listACLRules returns the current XDP ACL rules.
// GET /api/v1/xdp/acls
func (xh *xdpHandlers) listACLRules(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}
	rules := mgr.ACLRules()
	if rules == nil {
		rules = []xdp.ACLRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// addACLRule adds an ACL rule to the XDP fast path.
// POST /api/v1/xdp/acls
func (xh *xdpHandlers) addACLRule(w http.ResponseWriter, r *http.Request) {
	mgr := xh.svc.Manager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "XDP service not running",
		})
		return
	}

	var rule xdp.ACLRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if err := mgr.AddACLRule(rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}
