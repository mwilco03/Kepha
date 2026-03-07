package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var templates *template.Template

func init() {
	templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))
}

// Handler creates the web UI HTTP handler.
func Handler(store *config.Store) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /", handleDashboard(store))
	mux.HandleFunc("GET /zones", handleZones(store))
	mux.HandleFunc("GET /zones/{name}", handleZoneDetail(store))
	mux.HandleFunc("GET /aliases", handleAliases(store))
	mux.HandleFunc("GET /devices", handleDevices(store))
	mux.HandleFunc("GET /policies", handlePolicies(store))
	mux.HandleFunc("GET /config", handleConfig(store))
	mux.HandleFunc("GET /assign", handleAssignForm(store))
	mux.HandleFunc("GET /wireguard", handleWireGuard())

	return mux
}

func handleDashboard(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		zones, _ := store.ListZones()
		devices, _ := store.ListDevices()
		aliases, _ := store.ListAliases()
		revs, _ := store.ListRevisions()

		var lastCommit string
		if len(revs) > 0 {
			lastCommit = revs[0].Timestamp
		}

		render(w, "dashboard", map[string]any{
			"Title":       "Dashboard",
			"Zones":       zones,
			"Devices":     devices,
			"Aliases":     aliases,
			"ZoneCount":   len(zones),
			"DeviceCount": len(devices),
			"AliasCount":  len(aliases),
			"LastCommit":  lastCommit,
		})
	}
}

func handleZones(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zones, _ := store.ListZones()
		render(w, "zones", map[string]any{
			"Title": "Zones",
			"Zones": zones,
		})
	}
}

func handleZoneDetail(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		zone, err := store.GetZone(name)
		if err != nil || zone == nil {
			http.NotFound(w, r)
			return
		}

		// Get devices in this zone via profiles.
		profiles, _ := store.ListProfiles()
		devices, _ := store.ListDevices()

		var zoneProfiles []model.Profile
		profileIDs := make(map[int64]bool)
		for _, p := range profiles {
			if p.ZoneID == zone.ID {
				zoneProfiles = append(zoneProfiles, p)
				profileIDs[p.ID] = true
			}
		}

		var zoneDevices []model.DeviceAssignment
		for _, d := range devices {
			if profileIDs[d.ProfileID] {
				zoneDevices = append(zoneDevices, d)
			}
		}

		render(w, "zone_detail", map[string]any{
			"Title":    "Zone: " + zone.Name,
			"Zone":     zone,
			"Profiles": zoneProfiles,
			"Devices":  zoneDevices,
		})
	}
}

func handleAliases(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aliases, _ := store.ListAliases()
		render(w, "aliases", map[string]any{
			"Title":   "Aliases",
			"Aliases": aliases,
		})
	}
}

func handleDevices(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, _ := store.ListDevices()
		profiles, _ := store.ListProfiles()

		profileMap := make(map[int64]string)
		for _, p := range profiles {
			profileMap[p.ID] = p.Name
		}

		type deviceRow struct {
			model.DeviceAssignment
			ProfileName string
		}
		var rows []deviceRow
		for _, d := range devices {
			rows = append(rows, deviceRow{
				DeviceAssignment: d,
				ProfileName:      profileMap[d.ProfileID],
			})
		}

		render(w, "devices", map[string]any{
			"Title":   "Devices",
			"Devices": rows,
		})
	}
}

func handlePolicies(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policies, _ := store.ListPolicies()
		render(w, "policies", map[string]any{
			"Title":    "Policies",
			"Policies": policies,
		})
	}
}

func handleConfig(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		revs, _ := store.ListRevisions()
		snap, _ := store.Export()
		var snapJSON string
		if snap != nil {
			data, _ := json.MarshalIndent(snap, "", "  ")
			snapJSON = string(data)
		}
		render(w, "config", map[string]any{
			"Title":     "Configuration",
			"Revisions": revs,
			"Snapshot":  snapJSON,
		})
	}
}

func handleAssignForm(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		profiles, _ := store.ListProfiles()
		render(w, "assign", map[string]any{
			"Title":    "Assign Device",
			"Profiles": profiles,
		})
	}
}

func handleWireGuard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, "wireguard", map[string]any{
			"Title": "WireGuard",
		})
	}
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name+".html", data); err != nil {
		slog.Error("template render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
