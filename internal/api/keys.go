package api

import (
	"encoding/json"
	"net/http"

	"github.com/gatekeeper-firewall/gatekeeper/internal/rbac"
)

// keyHandlers implements the RBAC key management API endpoints.
type keyHandlers struct {
	enforcer *rbac.Enforcer
}

func (kh *keyHandlers) listKeys(w http.ResponseWriter, r *http.Request) {
	// Only admin can manage keys.
	if role := rbac.RoleFromContext(r.Context()); role != rbac.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}

	keys, err := kh.enforcer.ListKeys()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (kh *keyHandlers) createKey(w http.ResponseWriter, r *http.Request) {
	if role := rbac.RoleFromContext(r.Context()); role != rbac.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}

	var req struct {
		Name         string   `json:"name"`
		Role         string   `json:"role"`
		ZoneScope    []string `json:"zone_scope"`
		ProfileScope []string `json:"profile_scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name == "" || req.Role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and role are required"})
		return
	}

	key, id, err := kh.enforcer.CreateKey(req.Name, req.Role, req.ZoneScope, req.ProfileScope)
	if err != nil {
		status := http.StatusInternalServerError
		if err == rbac.ErrInvalidRole {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":  id,
		"key": key,
		"note": "Save this key now — it will not be shown again.",
	})
}

func (kh *keyHandlers) revokeKey(w http.ResponseWriter, r *http.Request) {
	if role := rbac.RoleFromContext(r.Context()); role != rbac.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}

	id := r.PathValue("id")
	if err := kh.enforcer.RevokeKey(id); err != nil {
		status := http.StatusInternalServerError
		if err == rbac.ErrKeyNotFound {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": id})
}

func (kh *keyHandlers) rotateKey(w http.ResponseWriter, r *http.Request) {
	if role := rbac.RoleFromContext(r.Context()); role != rbac.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}

	id := r.PathValue("id")
	newKey, err := kh.enforcer.RotateKey(id)
	if err != nil {
		status := http.StatusInternalServerError
		if err == rbac.ErrKeyNotFound {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":      id,
		"new_key": newKey,
		"note":    "Save this key now — it will not be shown again.",
	})
}
