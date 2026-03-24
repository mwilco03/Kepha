package api

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/mwilco03/kepha/internal/inspect"
)

// iocHandlers implements the IOC management API.
type iocHandlers struct {
	store   *inspect.IOCStore
	updater *inspect.MMDBUpdater // Optional — nil if mmdb updater not configured.
}

// listIOCs returns IOCs matching optional filters.
// GET /api/v1/iocs?type=ip&source=manual&active=true&limit=100
func (ih *iocHandlers) listIOCs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	iocType := inspect.IOCType(q.Get("type"))
	source := inspect.IOCSource(q.Get("source"))
	activeOnly := q.Get("active") != "false"
	limit := 100
	if l := q.Get("limit"); l != "" {
		if n, err := parseInt(l); err == nil && n > 0 {
			limit = n
		}
	}

	iocs, err := ih.store.ListIOCs(iocType, source, activeOnly, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if iocs == nil {
		iocs = []inspect.IOC{}
	}
	writeJSON(w, http.StatusOK, iocs)
}

// addIOC creates a new indicator of compromise.
// POST /api/v1/iocs
//
//	{
//	  "type": "ip",
//	  "value": "10.0.0.1",
//	  "severity": "high",
//	  "reason": "Cobalt Strike C2 beacon",
//	  "source": "manual",
//	  "tags": ["c2", "apt"],
//	  "expires_in": "24h"
//	}
func (ih *iocHandlers) addIOC(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type      inspect.IOCType     `json:"type"`
		Value     string              `json:"value"`
		Severity  inspect.IOCSeverity `json:"severity"`
		Reason    string              `json:"reason"`
		Source    inspect.IOCSource   `json:"source"`
		Reference string              `json:"reference"`
		Tags      []string            `json:"tags"`
		ExpiresIn string              `json:"expires_in"` // Duration string (e.g. "24h", "1h30m")
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	ioc := inspect.IOC{
		Type:      body.Type,
		Value:     body.Value,
		Severity:  body.Severity,
		Reason:    body.Reason,
		Source:    body.Source,
		Reference: body.Reference,
		Tags:      body.Tags,
	}

	if body.ExpiresIn != "" {
		dur, err := time.ParseDuration(body.ExpiresIn)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid expires_in: " + err.Error()})
			return
		}
		ioc.ExpiresAt = time.Now().Add(dur)
	}

	result, err := ih.store.AddIOC(ioc)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

// bulkAddIOCs adds multiple IOCs at once.
// POST /api/v1/iocs/bulk
//
//	{ "iocs": [ { "type": "ip", "value": "1.2.3.4", ... }, ... ] }
func (ih *iocHandlers) bulkAddIOCs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IOCs []inspect.IOC `json:"iocs"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if len(body.IOCs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no iocs provided"})
		return
	}

	added, err := ih.store.BulkAddIOCs(body.IOCs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"added": added,
		"total": len(body.IOCs),
	})
}

// removeIOC deactivates an IOC.
// DELETE /api/v1/iocs/{type}/{value}
func (ih *iocHandlers) removeIOC(w http.ResponseWriter, r *http.Request) {
	iocType := inspect.IOCType(r.PathValue("type"))
	value := r.PathValue("value")

	if err := ih.store.RemoveIOC(iocType, value); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// matchIOC checks if a value matches any active IOC.
// GET /api/v1/iocs/match?ip=10.0.0.1      (checks IP, CIDR, and ASN)
// GET /api/v1/iocs/match?fingerprint=t13d1516h2_xxx
// GET /api/v1/iocs/match?domain=evil.com
// GET /api/v1/iocs/match?asn=AS14618       (direct ASN lookup)
func (ih *iocHandlers) matchIOC(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var ioc *inspect.IOC
	var matchType string

	if ip := q.Get("ip"); ip != "" {
		ioc = ih.store.MatchIP(ip) // Also checks CIDR and ASN via resolver.
		matchType = "ip"
	} else if fp := q.Get("fingerprint"); fp != "" {
		ioc = ih.store.MatchFingerprint(fp)
		matchType = "fingerprint"
	} else if domain := q.Get("domain"); domain != "" {
		ioc = ih.store.MatchDomain(domain)
		matchType = "domain"
	} else if asn := q.Get("asn"); asn != "" {
		ioc = ih.store.GetIOC(inspect.IOCTypeASN, asn)
		matchType = "asn"
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "specify ip, fingerprint, domain, or asn query parameter",
		})
		return
	}

	result := map[string]any{
		"match_type": matchType,
		"matched":    ioc != nil,
	}

	if ioc != nil {
		result["ioc"] = ioc
		// Also find the response template.
		if tmpl := ih.store.MatchResponse(ioc); tmpl != nil {
			result["response"] = tmpl
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// iocStats returns store statistics.
// GET /api/v1/iocs/stats
func (ih *iocHandlers) iocStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ih.store.Stats())
}

// listTemplates returns response templates.
// GET /api/v1/iocs/templates
func (ih *iocHandlers) listTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ih.store.Templates())
}

// addTemplate creates or updates a response template.
// POST /api/v1/iocs/templates
func (ih *iocHandlers) addTemplate(w http.ResponseWriter, r *http.Request) {
	var tmpl inspect.ResponseTemplate
	if err := readJSON(r, &tmpl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if err := ih.store.AddTemplate(tmpl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "name": tmpl.Name})
}

// removeTemplate removes a response template.
// DELETE /api/v1/iocs/templates/{name}
func (ih *iocHandlers) removeTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := ih.store.RemoveTemplate(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// --- MMDB management ---

// mmdbStatus returns the current state of the ASN mmdb database.
// GET /api/v1/iocs/mmdb
func (ih *iocHandlers) mmdbStatus(w http.ResponseWriter, r *http.Request) {
	if ih.updater == nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"source": "none", "status": "mmdb updater not configured",
		})
		return
	}
	writeJSON(w, http.StatusOK, ih.updater.Status())
}

// mmdbRefresh triggers an immediate mmdb download.
// POST /api/v1/iocs/mmdb/refresh
func (ih *iocHandlers) mmdbRefresh(w http.ResponseWriter, r *http.Request) {
	if ih.updater == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "mmdb updater not configured",
		})
		return
	}
	if err := ih.updater.ForceRefresh(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ih.updater.Status())
}

// mmdbConfig updates mmdb configuration (license key, source switch).
// POST /api/v1/iocs/mmdb/config
//
//	{ "license_key": "your_maxmind_key" }
func (ih *iocHandlers) mmdbConfig(w http.ResponseWriter, r *http.Request) {
	if ih.updater == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "mmdb updater not configured",
		})
		return
	}

	var body struct {
		LicenseKey string `json:"license_key"`
		Path       string `json:"path"` // Manual mmdb file path.
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if body.Path != "" {
		// Validate path: must be absolute, no traversal, must end in .mmdb.
		cleaned := filepath.Clean(body.Path)
		if strings.Contains(cleaned, "..") || !strings.HasSuffix(cleaned, ".mmdb") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mmdb path"})
			return
		}
		if err := ih.updater.LoadFromPath(cleaned); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ih.updater.Status())
		return
	}

	if body.LicenseKey != "" {
		ih.updater.SetLicenseKey(body.LicenseKey)
	}
	writeJSON(w, http.StatusOK, ih.updater.Status())
}
