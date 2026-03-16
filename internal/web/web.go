package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	sessions := newSessionStore()
	limiter := newLoginRateLimiter()

	// Static assets are always public.
	mux.Handle("GET /static/", http.FileServerFS(staticFS))

	// Login page is always accessible.
	mux.HandleFunc("GET /login", handleLoginPage())
	mux.HandleFunc("POST /login", handleLoginSubmit(deps.APIKey, sessions, limiter))
	mux.HandleFunc("GET /logout", handleLogout(sessions))

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

	// Wrap with session auth and security headers if API key is configured.
	var handler http.Handler = mux
	if deps.APIKey != "" {
		handler = sessionAuth(deps.APIKey, sessions, handler)
	}
	return securityHeaders(handler)
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
// Only reads from /var/lib/ or /tmp/ to prevent path traversal.
func parseLeaseFile(path string) []leaseEntry {
	if path == "" {
		path = "/var/lib/misc/dnsmasq.leases"
	}
	// Restrict to safe directories to prevent information disclosure
	// if an admin misconfigures the lease file path.
	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, "/var/lib/") && !strings.HasPrefix(cleaned, "/tmp/") {
		slog.Warn("lease file path outside allowed directories, ignoring", "path", path)
		return nil
	}
	data, err := os.ReadFile(cleaned)
	if err != nil {
		return nil
	}
	var leases []leaseEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		expiry := fields[0]
		if ts, err := strconv.ParseInt(expiry, 10, 64); err == nil {
			expiry = time.Unix(ts, 0).Format("2006-01-02 15:04:05")
		} else {
			continue // Skip lines with non-numeric expiry.
		}
		mac := fields[1]
		ip := fields[2]
		hostname := fields[3]
		// Basic format validation: MAC should be xx:xx:xx:xx:xx:xx,
		// IP should parse as a valid address.
		if len(mac) != 17 || net.ParseIP(ip) == nil {
			continue
		}
		// Truncate hostname to prevent extremely long values.
		if len(hostname) > 253 {
			hostname = hostname[:253]
		}
		leases = append(leases, leaseEntry{
			Expiry:   expiry,
			MAC:      mac,
			IP:       ip,
			Hostname: hostname,
		})
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

// securityHeaders wraps a handler to add standard security response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

// sessionAuth wraps a handler with cookie-based session authentication.
// Static assets and the login page bypass auth.
func sessionAuth(apiKey string, sessions *sessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public paths: static assets, login, logout.
		if strings.HasPrefix(r.URL.Path, "/static/") ||
			r.URL.Path == "/login" || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}
		if !validSession(r, apiKey, sessions) {
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

func handleLoginSubmit(apiKey string, sessions *sessionStore, limiter *loginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		// Rate limit login attempts by remote address.
		clientIP := r.RemoteAddr
		if idx := strings.LastIndex(clientIP, ":"); idx >= 0 {
			clientIP = clientIP[:idx]
		}
		if !limiter.allow(clientIP) {
			slog.Warn("login rate limited", "ip", clientIP)
			http.Error(w, "Too many login attempts. Try again later.", http.StatusTooManyRequests)
			return
		}

		key := r.FormValue("api_key")
		// Constant-time comparison to prevent timing attacks on the API key.
		if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) != 1 {
			slog.Warn("failed login attempt", "ip", clientIP)
			http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
			return
		}

		limiter.reset(clientIP)
		setSessionCookie(w, apiKey, sessions)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handleLogout(sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Invalidate session server-side.
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			sessions.revoke(cookie.Value)
		}
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

// setSessionCookie creates a cryptographically random session token,
// stores it server-side, and sets it as a cookie.
func setSessionCookie(w http.ResponseWriter, apiKey string, sessions *sessionStore) {
	token := generateSessionToken(apiKey)
	sessions.add(token)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   86400, // 24 hours.
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// validSession checks the session cookie against the server-side session store.
func validSession(r *http.Request, apiKey string, sessions *sessionStore) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return sessions.valid(cookie.Value)
}

// generateSessionToken creates a random nonce and signs it with the API key.
// Format: hex(nonce) + "." + hex(HMAC-SHA256(apiKey, nonce))
func generateSessionToken(apiKey string) string {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	nonceHex := hex.EncodeToString(nonce)
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write(nonce)
	sig := hex.EncodeToString(mac.Sum(nil))
	return nonceHex + "." + sig
}

// sessionStore tracks active sessions server-side with expiry.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token → expiry
}

func newSessionStore() *sessionStore {
	s := &sessionStore{sessions: make(map[string]time.Time)}
	go s.cleanupLoop()
	return s
}

func (s *sessionStore) add(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = time.Now().Add(24 * time.Hour)
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *sessionStore) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, expiry := range s.sessions {
			if now.After(expiry) {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

// loginRateLimiter tracks failed login attempts per IP.
type loginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{attempts: make(map[string][]time.Time)}
}

// allow returns true if the IP has fewer than 5 attempts in the last minute.
func (l *loginRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Minute)
	var recent []time.Time
	for _, t := range l.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, time.Now())
	l.attempts[ip] = recent
	return len(recent) <= 5
}

func (l *loginRateLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name+".html", data); err != nil {
		slog.Error("template render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
