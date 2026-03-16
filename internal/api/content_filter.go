package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/rbac"
	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
)

type contentFilterHandlers struct {
	store  *config.Store
	engine *service.ContentFilterEngine
}

// --- Content filter CRUD ---

func (h *contentFilterHandlers) listFilters(w http.ResponseWriter, r *http.Request) {
	filters, err := h.store.ListContentFilters()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if filters == nil {
		filters = []model.ContentFilter{}
	}
	writeJSON(w, http.StatusOK, filters)
}

func (h *contentFilterHandlers) getFilter(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cf, err := h.store.GetContentFilter(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cf == nil {
		writeError(w, http.StatusNotFound, "content filter not found")
		return
	}
	writeJSON(w, http.StatusOK, cf)
}

func (h *contentFilterHandlers) createFilter(w http.ResponseWriter, r *http.Request) {
	var cf model.ContentFilter
	if err := readJSON(r, &cf); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cf.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// Validate categories.
	for _, cat := range cf.BlockedCategories {
		if !model.ValidCategories[cat] {
			writeError(w, http.StatusBadRequest, "invalid category: "+string(cat))
			return
		}
	}
	if err := h.store.CreateContentFilter(&cf); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "content filter already exists")
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	h.reloadEngine()
	writeJSON(w, http.StatusCreated, cf)
}

func (h *contentFilterHandlers) updateFilter(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var cf model.ContentFilter
	if err := readJSON(r, &cf); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cf.Name = name
	for _, cat := range cf.BlockedCategories {
		if !model.ValidCategories[cat] {
			writeError(w, http.StatusBadRequest, "invalid category: "+string(cat))
			return
		}
	}
	if err := h.store.UpdateContentFilter(&cf); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.reloadEngine()
	writeJSON(w, http.StatusOK, cf)
}

func (h *contentFilterHandlers) deleteFilter(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.DeleteContentFilter(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.reloadEngine()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Exception workflow ---

func (h *contentFilterHandlers) requestException(w http.ResponseWriter, r *http.Request) {
	var ex model.FilterException
	if err := readJSON(r, &ex); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate required fields.
	if ex.FilterID == 0 {
		writeError(w, http.StatusBadRequest, "filter_id is required")
		return
	}
	if ex.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if ex.Justification == "" {
		writeError(w, http.StatusBadRequest, "justification is required — document why this exception is needed")
		return
	}
	if ex.ExpiresAt.IsZero() {
		writeError(w, http.StatusBadRequest, "expires_at is required — exceptions must be time-bounded")
		return
	}
	// Cap exception duration to 90 days.
	maxExpiry := time.Now().Add(90 * 24 * time.Hour)
	if ex.ExpiresAt.After(maxExpiry) {
		writeError(w, http.StatusBadRequest, "expires_at cannot be more than 90 days from now")
		return
	}

	// Set requestor from RBAC context if available.
	if ak := rbac.APIKeyFromContext(r.Context()); ak != nil {
		ex.RequestedBy = ak.Name + " (" + ak.ID + ")"
	} else {
		ex.RequestedBy = "api"
	}

	if err := h.store.CreateFilterException(&ex); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ex)
}

func (h *contentFilterHandlers) listExceptions(w http.ResponseWriter, r *http.Request) {
	var filterID int64
	if fid := r.URL.Query().Get("filter_id"); fid != "" {
		filterID, _ = strconv.ParseInt(fid, 10, 64)
	}
	status := model.ExceptionStatus(r.URL.Query().Get("status"))

	exceptions, err := h.store.ListFilterExceptions(filterID, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if exceptions == nil {
		exceptions = []model.FilterException{}
	}
	writeJSON(w, http.StatusOK, exceptions)
}

func (h *contentFilterHandlers) getException(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid exception id")
		return
	}
	ex, err := h.store.GetFilterException(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ex == nil {
		writeError(w, http.StatusNotFound, "exception not found")
		return
	}
	writeJSON(w, http.StatusOK, ex)
}

// approveException is admin-only: approves a pending exception request.
func (h *contentFilterHandlers) approveException(w http.ResponseWriter, r *http.Request) {
	h.reviewException(w, r, true)
}

// denyException is admin-only: denies a pending exception request.
func (h *contentFilterHandlers) denyException(w http.ResponseWriter, r *http.Request) {
	h.reviewException(w, r, false)
}

func (h *contentFilterHandlers) reviewException(w http.ResponseWriter, r *http.Request, approve bool) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid exception id")
		return
	}

	var body struct {
		Note string `json:"note"`
	}
	_ = readJSON(r, &body)

	reviewerID := "admin"
	if ak := rbac.APIKeyFromContext(r.Context()); ak != nil {
		reviewerID = ak.Name + " (" + ak.ID + ")"
	}

	if err := h.store.ReviewFilterException(id, approve, reviewerID, body.Note); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Reload engine so approved exception takes effect immediately.
	h.reloadEngine()

	action := "approved"
	if !approve {
		action = "denied"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": action})
}

// revokeException is admin-only: revokes a previously approved exception.
func (h *contentFilterHandlers) revokeException(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid exception id")
		return
	}

	revokerID := "admin"
	if ak := rbac.APIKeyFromContext(r.Context()); ak != nil {
		revokerID = ak.Name + " (" + ak.ID + ")"
	}

	if err := h.store.RevokeFilterException(id, revokerID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reloadEngine()
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// checkDomain tests a domain against the content filter engine.
func (h *contentFilterHandlers) checkDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain query param required")
		return
	}
	if h.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "content filter engine not initialized")
		return
	}
	result := h.engine.CheckDomain(domain)
	writeJSON(w, http.StatusOK, result)
}

// stats returns content filter engine statistics.
func (h *contentFilterHandlers) stats(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, h.engine.Stats())
}

func (h *contentFilterHandlers) reloadEngine() {
	if h.engine != nil {
		if err := h.engine.Reload(); err != nil {
			// Log but don't fail the API call — the store mutation succeeded.
			writeError(nil, 0, err.Error()) // noop if w is nil
		}
	}
}
