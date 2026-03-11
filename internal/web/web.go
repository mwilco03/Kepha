package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
)

const sessionCookieName = "gk_session"

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var templates *template.Template

func init() {
	templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))
}

// WebDeps holds optional dependencies for the web UI.
type WebDeps struct {
	ServiceMgr *service.Manager
	WG         *driver.WireGuard
	NFT        backend.Firewall // Was *driver.NFTables; now any Firewall implementation.
	LeaseFile  string           // Path to dnsmasq lease file.
	APIKey     string // API key for web session auth (empty = no auth).
}

// Handler creates the web UI HTTP handler.
func Handler(store *config.Store, svcMgrs ...*service.Manager) http.Handler {
	deps := &WebDeps{}
	if len(svcMgrs) > 0 {
		deps.ServiceMgr = svcMgrs[0]
	}
	return HandlerWithDeps(store, deps)
}

// HandlerWithDeps creates the web UI with full dependency injection.
func HandlerWithDeps(store *config.Store, deps *WebDeps) http.Handler {
	mux := http.NewServeMux()

	// Static assets are always public.
	mux.Handle("GET /static/", http.FileServerFS(staticFS))

	// Login page is always accessible.
	mux.HandleFunc("GET /login", handleLoginPage())
	mux.HandleFunc("POST /login", handleLoginSubmit(deps.APIKey))
	mux.HandleFunc("GET /logout", handleLogout())

	// All other routes require session auth.
	mux.HandleFunc("GET /", handleDashboard(store, deps))
	mux.HandleFunc("GET /zones", handleZones(store))
	mux.HandleFunc("GET /zones/{name}", handleZoneDetail(store))
	mux.HandleFunc("GET /aliases", handleAliases(store))
	mux.HandleFunc("GET /devices", handleDevices(store))
	mux.HandleFunc("GET /policies", handlePolicies(store))
	mux.HandleFunc("GET /config", handleConfig(store))
	mux.HandleFunc("GET /assign", handleAssignForm(store))
	mux.HandleFunc("GET /wireguard", handleWireGuard())
	mux.HandleFunc("GET /leases", handleLeases(deps))
	mux.HandleFunc("GET /firewall", handleFirewall(store, deps))

	if deps.ServiceMgr != nil {
		mux.HandleFunc("GET /services", handleServices(deps.ServiceMgr))
	}

	// Wrap with session auth if API key is configured.
	if deps.APIKey != "" {
		return sessionAuth(deps.APIKey, mux)
	}
	return mux
}

func handleDashboard(store *config.Store, deps *WebDeps) http.HandlerFunc {
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

		var peerCount int
		if deps.WG != nil {
			peerCount = len(deps.WG.ListPeers())
		}

		leases := parseLeaseFile(deps.LeaseFile)

		render(w, "dashboard", map[string]any{
			"Title":       "Dashboard",
			"Zones":       zones,
			"Devices":     devices,
			"Aliases":     aliases,
			"ZoneCount":   len(zones),
			"DeviceCount": len(devices),
			"AliasCount":  len(aliases),
			"PeerCount":   peerCount,
			"LeaseCount":  len(leases),
			"Leases":      leases,
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

func handleLeases(deps *WebDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		leases := parseLeaseFile(deps.LeaseFile)
		render(w, "leases", map[string]any{
			"Title":  "DHCP Leases",
			"Leases": leases,
		})
	}
}

// leaseEntry represents a parsed DHCP lease for the web UI.
type leaseEntry struct {
	Expiry   string
	MAC      string
	IP       string
	Hostname string
}

// parseLeaseFile reads dnsmasq leases from the given file path.
func parseLeaseFile(path string) []leaseEntry {
	if path == "" {
		path = "/var/lib/misc/dnsmasq.leases"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var leases []leaseEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			expiry := fields[0]
			if ts, err := strconv.ParseInt(expiry, 10, 64); err == nil {
				expiry = time.Unix(ts, 0).Format("2006-01-02 15:04:05")
			}
			leases = append(leases, leaseEntry{
				Expiry:   expiry,
				MAC:      fields[1],
				IP:       fields[2],
				Hostname: fields[3],
			})
		}
	}
	return leases
}

func handleFirewall(store *config.Store, deps *WebDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zones, _ := store.ListZones()
		policies, _ := store.ListPolicies()
		profiles, _ := store.ListProfiles()

		// Build zone→policy mapping via profiles.
		type zonePolicyRow struct {
			ZoneName      string
			Interface     string
			ProfileName   string
			PolicyName    string
			DefaultAction string
			RuleCount     int
		}
		policyMap := make(map[string]model.Policy)
		for _, p := range policies {
			policyMap[p.Name] = p
		}

		var rows []zonePolicyRow
		for _, prof := range profiles {
			var zoneName, iface string
			for _, z := range zones {
				if z.ID == prof.ZoneID {
					zoneName = z.Name
					iface = z.Interface
					break
				}
			}
			pol := policyMap[prof.PolicyName]
			rows = append(rows, zonePolicyRow{
				ZoneName:      zoneName,
				Interface:     iface,
				ProfileName:   prof.Name,
				PolicyName:    prof.PolicyName,
				DefaultAction: string(pol.DefaultAction),
				RuleCount:     len(pol.Rules),
			})
		}

		// Compiled ruleset via dry-run.
		var ruleset string
		if deps.NFT != nil {
			text, err := deps.NFT.DryRun()
			if err != nil {
				ruleset = "# Error compiling ruleset: " + err.Error()
			} else {
				ruleset = text
			}
		}

		render(w, "firewall", map[string]any{
			"Title":       "Firewall",
			"ZonePolicies": rows,
			"Ruleset":     ruleset,
			"Policies":    policies,
		})
	}
}

func handleServices(mgr *service.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		services := mgr.List()

		// Group by category.
		categories := make(map[string][]service.ServiceInfo)
		for _, s := range services {
			categories[s.Category] = append(categories[s.Category], s)
		}

		render(w, "services", map[string]any{
			"Title":      "Services",
			"Services":   services,
			"Categories": categories,
		})
	}
}

// sessionAuth wraps a handler with cookie-based session authentication.
// Static assets and the login page bypass auth.
func sessionAuth(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public paths: static assets, login, logout.
		if strings.HasPrefix(r.URL.Path, "/static/") ||
			r.URL.Path == "/login" || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}
		if !validSession(r, apiKey) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleLoginPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, "login", map[string]any{
			"Title": "Login",
			"Error": r.URL.Query().Get("error"),
		})
	}
}

func handleLoginSubmit(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		key := r.FormValue("api_key")
		if key != apiKey {
			http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
			return
		}
		setSessionCookie(w, apiKey)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// setSessionCookie creates an HMAC-signed session cookie.
func setSessionCookie(w http.ResponseWriter, apiKey string) {
	sig := signSession(apiKey)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sig,
		Path:     "/",
		MaxAge:   86400, // 24 hours.
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// validSession checks the session cookie against the API key.
func validSession(r *http.Request, apiKey string) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	expected := signSession(apiKey)
	return hmac.Equal([]byte(cookie.Value), []byte(expected))
}

// signSession produces an HMAC-SHA256 of a fixed payload using the API key.
func signSession(apiKey string) string {
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte("gatekeeper-web-session"))
	return hex.EncodeToString(mac.Sum(nil))
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name+".html", data); err != nil {
		slog.Error("template render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
