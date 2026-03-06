package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AuditEntry records a mutation for the audit log.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	RemoteIP  string    `json:"remote_ip"`
	Status    int       `json:"status"`
}

// AuditMiddleware logs all mutation requests (POST, PUT, DELETE).
func AuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)

		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			slog.Info("audit",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"status", wrapped.status,
			)
		}
	})
}

// SanitizeInput strips null bytes and trims whitespace from common attack vectors.
func SanitizeInput(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.TrimSpace(s)
	return s
}
