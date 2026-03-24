package api

import (
	"net/http"
	"strconv"

	"github.com/mwilco03/kepha/internal/config"
)

// --- DNS Host Overrides ---

func (h *handlers) listDNSHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.ops.Store().ListDNSHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (h *handlers) createDNSHost(w http.ResponseWriter, r *http.Request) {
	var host config.DNSHost
	if err := readJSON(r, &host); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	host.Enabled = true
	if err := h.ops.Store().CreateDNSHost(&host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, host)
}

func (h *handlers) updateDNSHost(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var host config.DNSHost
	if err := readJSON(r, &host); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	host.ID = id
	if err := h.ops.Store().UpdateDNSHost(&host); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (h *handlers) deleteDNSHost(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.ops.Store().DeleteDNSHost(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- DNS Feeds ---

func (h *handlers) listDNSFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := h.ops.Store().ListDNSFeeds()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, feeds)
}

func (h *handlers) enableDNSFeed(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.ops.Store().EnableDNSFeed(name, true); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "feed": name})
}

func (h *handlers) disableDNSFeed(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.ops.Store().EnableDNSFeed(name, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "feed": name})
}

func (h *handlers) getDNSFeed(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	feed, err := h.ops.Store().GetDNSFeed(name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, feed)
}

// --- DNS Block Log ---

func (h *handlers) listBlockedDomains(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	domains, err := h.ops.Store().ListBlockedDomains(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domains)
}

func (h *handlers) allowBlockedDomain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := readJSON(r, &body); err != nil || body.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if err := h.ops.Store().AllowBlockedDomain(body.Domain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "allowed", "domain": body.Domain})
}
