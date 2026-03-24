package web

import (
	"bytes"
	"crypto/hmac"
	"fmt"
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

	"github.com/mwilco03/kepha/internal/backend"
	"github.com/mwilco03/kepha/internal/config"
	"github.com/mwilco03/kepha/internal/driver"
	"github.com/mwilco03/kepha/internal/model"
	"github.com/mwilco03/kepha/internal/service"
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
// Note (M-SA5): The web UI reads directly from config.Store for list/get
// operations rather than going through the ops layer. This is acceptable
// for read-only queries — ops adds validation and audit for mutations only.
// All mutations (assign, commit, rollback) go through the API endpoints.
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

	// Export session validator so the API middleware can accept web sessions.
	SessionValidator = sessions.valid

	// Wrap with session auth, CSRF protection, and security headers.
	var handler http.Handler = mux
	if deps.APIKey != "" {
		handler = csrfProtect(sessions, handler)
		handler = sessionAuth(deps.APIKey, sessions, handler)
	}
	return securityHeaders(handler)
}

// SessionValidator is set during HandlerWithDeps initialization.
// It validates web UI session tokens and is used by the API auth
// middleware to accept htmx requests authenticated via session cookie.
var SessionValidator func(token string) bool

func handleDashboard(store *config.Store, deps *WebDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		zones, zErr := store.ListZones(); if zErr != nil { slog.Warn("store error", "op", "ListZones", "error", zErr) }
		devices, dErr := store.ListDevices(); if dErr != nil { slog.Warn("store error", "op", "ListDevices", "error", dErr) }
		aliases, aErr := store.ListAliases(); if aErr != nil { slog.Warn("store error", "op", "ListAliases", "error", aErr) }
		revs, rErr := store.ListRevisions(); if rErr != nil { slog.Warn("store error", "op", "ListRevisions", "error", rErr) }

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
		zones, zErr := store.ListZones(); if zErr != nil { slog.Warn("store error", "op", "ListZones", "error", zErr) }
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
		profiles, prErr := store.ListProfiles(); if prErr != nil { slog.Warn("store error", "op", "ListProfiles", "error", prErr) }
		devices, dErr := store.ListDevices(); if dErr != nil { slog.Warn("store error", "op", "ListDevices", "error", dErr) }

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
		aliases, aErr := store.ListAliases(); if aErr != nil { slog.Warn("store error", "op", "ListAliases", "error", aErr) }
		render(w, "aliases", map[string]any{
			"Title":   "Aliases",
			"Aliases": aliases,
		})
	}
}

func handleDevices(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, dErr := store.ListDevices(); if dErr != nil { slog.Warn("store error", "op", "ListDevices", "error", dErr) }
		profiles, prErr := store.ListProfiles(); if prErr != nil { slog.Warn("store error", "op", "ListProfiles", "error", prErr) }

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
		policies, pErr := store.ListPolicies(); if pErr != nil { slog.Warn("store error", "op", "ListPolicies", "error", pErr) }
		render(w, "policies", map[string]any{
			"Title":    "Policies",
			"Policies": policies,
		})
	}
}

func handleConfig(store *config.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		revs, rErr := store.ListRevisions(); if rErr != nil { slog.Warn("store error", "op", "ListRevisions", "error", rErr) }
		snap, exErr := store.Export(); if exErr != nil { slog.Warn("store error", "op", "Export", "error", exErr) }
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
		profiles, prErr := store.ListProfiles(); if prErr != nil { slog.Warn("store error", "op", "ListProfiles", "error", prErr) }
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
		zones, zErr := store.ListZones(); if zErr != nil { slog.Warn("store error", "op", "ListZones", "error", zErr) }
		policies, pErr := store.ListPolicies(); if pErr != nil { slog.Warn("store error", "op", "ListPolicies", "error", pErr) }
		profiles, prErr := store.ListProfiles(); if prErr != nil { slog.Warn("store error", "op", "ListProfiles", "error", prErr) }

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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		// L8: HSTS when served over TLS.
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// csrfProtect enforces double-submit cookie CSRF protection on state-changing
// requests (POST/PUT/DELETE). The CSRF token is the session cookie value —
// an attacker cannot read it cross-origin due to SameSite and HttpOnly.
// Forms must include a hidden _csrf field or an X-CSRF-Token header.
func csrfProtect(sessions *sessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		// Login form doesn't have a session yet — skip CSRF check.
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		sessionCookie, err := r.Cookie(sessionCookieName)
		if err != nil || sessionCookie.Value == "" {
			next.ServeHTTP(w, r) // No session — auth middleware will reject.
			return
		}

		// Check form field or header against the HMAC-derived CSRF token.
		csrfToken := r.FormValue("_csrf")
		if csrfToken == "" {
			csrfToken = r.Header.Get("X-CSRF-Token")
		}

		expected := deriveCSRFToken(sessionCookie.Value)
		if subtle.ConstantTimeCompare([]byte(csrfToken), []byte(expected)) != 1 {
			http.Error(w, "CSRF token mismatch", http.StatusForbidden)
			return
		}

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
		// M-F6: Only show error for known values to prevent phishing via crafted URLs.
		showError := r.URL.Query().Get("error") == "invalid"
		render(w, "login", map[string]any{
			"Title": "Login",
			"Error": showError,
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
const csrfCookieName = "gk_csrf"

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
	// Separate CSRF cookie — readable by JS for double-submit pattern.
	// Derived from session token via HMAC so the CSRF cookie does not
	// leak the actual session credential to JavaScript.
	csrfToken := deriveCSRFToken(token)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: false, // Readable by JS for htmx X-CSRF-Token header.
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

// deriveCSRFToken produces an HMAC of the session token so the CSRF cookie
// does not leak the actual session credential to JavaScript.
func deriveCSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte("gk-csrf-v1"))
	mac.Write([]byte(sessionToken))
	return fmt.Sprintf("%x", mac.Sum(nil))
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
	stopCh   chan struct{}
}

func newSessionStore() *sessionStore {
	s := &sessionStore{
		sessions: make(map[string]time.Time),
		stopCh:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Stop terminates the background cleanup goroutine (M-CR12/M-SRE7).
func (s *sessionStore) Stop() {
	close(s.stopCh)
}

const maxSessions = 10000

func (s *sessionStore) add(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Evict oldest sessions if at capacity.
	if len(s.sessions) >= maxSessions {
		var oldestToken string
		var oldestTime time.Time
		for t, exp := range s.sessions {
			if oldestToken == "" || exp.Before(oldestTime) {
				oldestToken = t
				oldestTime = exp
			}
		}
		if oldestToken != "" {
			delete(s.sessions, oldestToken)
		}
	}
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
	for {
		select {
		case <-ticker.C:
		case <-s.stopCh:
			return
		}
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
	l := &loginRateLimiter{attempts: make(map[string][]time.Time)}
	// L9: Cleanup stale entries every 5 minutes to prevent memory leak.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			l.mu.Lock()
			cutoff := time.Now().Add(-5 * time.Minute)
			for ip, times := range l.attempts {
				var recent []time.Time
				for _, t := range times {
					if t.After(cutoff) {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(l.attempts, ip)
				} else {
					l.attempts[ip] = recent
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
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
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name+".html", data); err != nil {
		slog.Error("template render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}
