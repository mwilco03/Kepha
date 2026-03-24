package api

import (
	"encoding/json"
	"net/http"

	"github.com/mwilco03/kepha/internal/inspect"
	"github.com/mwilco03/kepha/internal/service"
)

// fingerprintHandlers handles fingerprint API endpoints.
type fingerprintHandlers struct {
	svc *service.FingerprintService
}

// listFingerprints returns observed fingerprints.
// GET /api/v1/fingerprints?type=ja4&limit=100
func (fh *fingerprintHandlers) listFingerprints(w http.ResponseWriter, r *http.Request) {
	store := fh.svc.Store()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "fingerprint service not running",
		})
		return
	}

	fpType := r.URL.Query().Get("type")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := parseInt(l); err == nil && n > 0 {
			limit = n
		}
	}

	fps, err := store.ListFingerprints(fpType, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if fps == nil {
		fps = []inspect.ObservedFingerprint{}
	}
	writeJSON(w, http.StatusOK, fps)
}

// getFingerprint returns a specific fingerprint by hash.
// GET /api/v1/fingerprints/{hash}
func (fh *fingerprintHandlers) getFingerprint(w http.ResponseWriter, r *http.Request) {
	store := fh.svc.Store()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "fingerprint service not running",
		})
		return
	}

	hash := r.PathValue("hash")
	fp, err := store.GetFingerprint(hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if fp == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "fingerprint not found"})
		return
	}
	writeJSON(w, http.StatusOK, fp)
}

// identifyFingerprint identifies a device from a fingerprint hash.
// GET /api/v1/fingerprints/{hash}/identify
func (fh *fingerprintHandlers) identifyFingerprint(w http.ResponseWriter, r *http.Request) {
	engine := fh.svc.Engine()
	if engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "fingerprint service not running",
		})
		return
	}

	hash := r.PathValue("hash")
	identity, confidence, err := engine.IdentifyDevice(hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	result := map[string]any{
		"hash":       hash,
		"identity":   identity,
		"confidence": confidence,
	}

	// Also check threat feeds.
	threat, err := engine.CheckThreat(hash)
	if err == nil {
		result["threat"] = threat
	}

	writeJSON(w, http.StatusOK, result)
}

// assignProfile maps a fingerprint to a device profile.
// POST /api/v1/fingerprints/{hash}/assign
func (fh *fingerprintHandlers) assignProfile(w http.ResponseWriter, r *http.Request) {
	store := fh.svc.Store()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "fingerprint service not running",
		})
		return
	}

	hash := r.PathValue("hash")
	var body struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if body.Profile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "profile name required"})
		return
	}

	if err := store.AssignProfile(hash, body.Profile); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned", "hash": hash, "profile": body.Profile})
}

// checkThreat checks a fingerprint against threat feeds.
// GET /api/v1/fingerprints/{hash}/threat
func (fh *fingerprintHandlers) checkThreat(w http.ResponseWriter, r *http.Request) {
	engine := fh.svc.Engine()
	if engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "fingerprint service not running",
		})
		return
	}

	hash := r.PathValue("hash")
	match, err := engine.CheckThreat(hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, match)
}

// parseInt parses a string to int for query params.
func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &json.UnmarshalTypeError{}
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
