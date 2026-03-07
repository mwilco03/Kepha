package api

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics tracks basic operational metrics for Prometheus scraping.
type Metrics struct {
	RequestCount  atomic.Int64
	CommitCount   atomic.Int64
	RollbackCount atomic.Int64
	ApplyCount    atomic.Int64
	ApplyErrors   atomic.Int64
	StartTime     time.Time
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		StartTime: time.Now(),
	}
}

// Handler returns an HTTP handler that serves Prometheus-formatted metrics.
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		uptime := time.Since(m.StartTime).Seconds()

		fmt.Fprintf(w, "# HELP gatekeeper_uptime_seconds Time since daemon start.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_uptime_seconds gauge\n")
		fmt.Fprintf(w, "gatekeeper_uptime_seconds %.2f\n\n", uptime)

		fmt.Fprintf(w, "# HELP gatekeeper_requests_total Total API requests.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_requests_total counter\n")
		fmt.Fprintf(w, "gatekeeper_requests_total %d\n\n", m.RequestCount.Load())

		fmt.Fprintf(w, "# HELP gatekeeper_commits_total Total config commits.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_commits_total counter\n")
		fmt.Fprintf(w, "gatekeeper_commits_total %d\n\n", m.CommitCount.Load())

		fmt.Fprintf(w, "# HELP gatekeeper_rollbacks_total Total config rollbacks.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_rollbacks_total counter\n")
		fmt.Fprintf(w, "gatekeeper_rollbacks_total %d\n\n", m.RollbackCount.Load())

		fmt.Fprintf(w, "# HELP gatekeeper_applies_total Total nftables apply operations.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_applies_total counter\n")
		fmt.Fprintf(w, "gatekeeper_applies_total %d\n\n", m.ApplyCount.Load())

		fmt.Fprintf(w, "# HELP gatekeeper_apply_errors_total Total nftables apply errors.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_apply_errors_total counter\n")
		fmt.Fprintf(w, "gatekeeper_apply_errors_total %d\n\n", m.ApplyErrors.Load())
	}
}

// CountingMiddleware increments request count for each request.
func (m *Metrics) CountingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.RequestCount.Add(1)
		next.ServeHTTP(w, r)
	})
}
