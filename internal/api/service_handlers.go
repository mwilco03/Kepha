package api

import (
	"net/http"

	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
)

// serviceHandlers provides API endpoints for service management.
type serviceHandlers struct {
	mgr *service.Manager
}

// listServices returns all registered services with their status.
func (sh *serviceHandlers) listServices(w http.ResponseWriter, r *http.Request) {
	services := sh.mgr.List()
	if services == nil {
		services = []service.ServiceInfo{}
	}

	// Filter by category if requested.
	if cat := r.URL.Query().Get("category"); cat != "" {
		var filtered []service.ServiceInfo
		for _, s := range services {
			if s.Category == cat {
				filtered = append(filtered, s)
			}
		}
		services = filtered
		if services == nil {
			services = []service.ServiceInfo{}
		}
	}

	writeJSON(w, http.StatusOK, services)
}

// getService returns details for a single service.
func (sh *serviceHandlers) getService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	info, err := sh.mgr.Get(name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// getServiceSchema returns the config schema for a service.
func (sh *serviceHandlers) getServiceSchema(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	schema, err := sh.mgr.Schema(name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, schema)
}

// enableService enables and starts a service.
func (sh *serviceHandlers) enableService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := sh.mgr.Enable(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, _ := sh.mgr.Get(name)
	writeJSON(w, http.StatusOK, info)
}

// disableService stops and disables a service.
func (sh *serviceHandlers) disableService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := sh.mgr.Disable(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, _ := sh.mgr.Get(name)
	writeJSON(w, http.StatusOK, info)
}

// configureService updates a service's configuration.
func (sh *serviceHandlers) configureService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var cfg map[string]string
	if err := readJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := sh.mgr.Configure(name, cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, _ := sh.mgr.Get(name)
	writeJSON(w, http.StatusOK, info)
}
