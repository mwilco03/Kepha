package api

import (
	"log/slog"
	"net/http"
	"sync"
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

// auditStore is an interface for the subset of config.Store that audit needs.
type auditStore interface {
	LogAudit(source, action, resource, resourceID string, detail any) error
}

var (
	auditStoreMu   sync.RWMutex
	auditStoreInst auditStore
)

// SetAuditStore registers the config store for DB-backed audit logging.
// Called at boot time by the daemon.
func SetAuditStore(s auditStore) {
	auditStoreMu.Lock()
	defer auditStoreMu.Unlock()
	auditStoreInst = s
}

// AuditMiddleware logs all mutation requests (POST, PUT, DELETE)
// to both structured stdout and the database audit log.
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

			// Persist to database audit log.
			auditStoreMu.RLock()
			s := auditStoreInst
			auditStoreMu.RUnlock()
			if s != nil {
				if err := s.LogAudit("api", r.Method, r.URL.Path, "", map[string]any{
					"remote": r.RemoteAddr,
					"status": wrapped.status,
				}); err != nil {
					slog.Warn("failed to persist audit entry", "error", err)
				}
			}
		}
	})
}
