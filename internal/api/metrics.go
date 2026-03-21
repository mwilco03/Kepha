package api

import (
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks operational metrics for Prometheus scraping.
type Metrics struct {
	RequestCount  atomic.Int64
	CommitCount   atomic.Int64
	RollbackCount atomic.Int64
	ApplyCount    atomic.Int64
	ApplyErrors   atomic.Int64
	StartTime     time.Time

	// Per-endpoint request counts.
	endpointMu    sync.Mutex
	endpointCount map[string]*atomic.Int64

	// Latency histogram (milliseconds).
	latencyMu  sync.Mutex
	latencies  []float64
	latencySum float64
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		StartTime:     time.Now(),
		endpointCount: make(map[string]*atomic.Int64),
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

		// Goroutine count.
		fmt.Fprintf(w, "# HELP gatekeeper_goroutines Current number of goroutines.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_goroutines gauge\n")
		fmt.Fprintf(w, "gatekeeper_goroutines %d\n\n", runtime.NumGoroutine())

		// Per-endpoint counts.
		m.endpointMu.Lock()
		fmt.Fprintf(w, "# HELP gatekeeper_endpoint_requests_total Requests per endpoint.\n")
		fmt.Fprintf(w, "# TYPE gatekeeper_endpoint_requests_total counter\n")
		for path, cnt := range m.endpointCount {
			fmt.Fprintf(w, "gatekeeper_endpoint_requests_total{path=%q} %d\n", path, cnt.Load())
		}
		m.endpointMu.Unlock()
		fmt.Fprintln(w)

		// Latency histogram (quantiles).
		m.latencyMu.Lock()
		n := len(m.latencies)
		if n > 0 {
			sorted := make([]float64, n)
			copy(sorted, m.latencies)
			sort.Float64s(sorted)
			fmt.Fprintf(w, "# HELP gatekeeper_request_duration_ms Request latency in milliseconds.\n")
			fmt.Fprintf(w, "# TYPE gatekeeper_request_duration_ms summary\n")
			fmt.Fprintf(w, "gatekeeper_request_duration_ms{quantile=\"0.5\"} %.2f\n", percentile(sorted, 0.5))
			fmt.Fprintf(w, "gatekeeper_request_duration_ms{quantile=\"0.9\"} %.2f\n", percentile(sorted, 0.9))
			fmt.Fprintf(w, "gatekeeper_request_duration_ms{quantile=\"0.99\"} %.2f\n", percentile(sorted, 0.99))
			fmt.Fprintf(w, "gatekeeper_request_duration_ms_sum %.2f\n", m.latencySum)
			fmt.Fprintf(w, "gatekeeper_request_duration_ms_count %d\n\n", n)
		}
		m.latencyMu.Unlock()
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// CountingMiddleware increments request count, per-endpoint count, and
// records latency for each request.
func (m *Metrics) CountingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.RequestCount.Add(1)

		// Per-endpoint count.
		path := r.URL.Path
		m.endpointMu.Lock()
		cnt, ok := m.endpointCount[path]
		if !ok {
			cnt = &atomic.Int64{}
			m.endpointCount[path] = cnt
		}
		m.endpointMu.Unlock()
		cnt.Add(1)

		next.ServeHTTP(w, r)

		// Record latency (keep last 10K samples to bound memory).
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		m.latencyMu.Lock()
		m.latencySum += ms
		if len(m.latencies) < 10000 {
			m.latencies = append(m.latencies, ms)
		} else {
			m.latencies[int(m.RequestCount.Load())%10000] = ms
		}
		m.latencyMu.Unlock()
	})
}
