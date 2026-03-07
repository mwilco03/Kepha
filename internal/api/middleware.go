package api

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// AuthMiddleware checks for API key authentication.
// Status and metrics endpoints are exempted per the OpenAPI spec (security: []).
func AuthMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt unauthenticated endpoints.
		if r.URL.Path == "/api/v1/status" || r.URL.Path == "/api/v1/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		key := r.Header.Get("X-API-Key")
		if key == "" {
			// Try Basic auth.
			_, key, _ = r.BasicAuth()
		}
		if key != apiKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimiter is a simple token-bucket rate limiter per IP.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*bucket
	rate    int
	burst   int
}

type bucket struct {
	tokens    int
	lastCheck time.Time
}

// NewRateLimiter creates a rate limiter with the given requests/sec and burst.
func NewRateLimiter(rate, burst int) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
	}
}

// Middleware returns an HTTP middleware that rate-limits by client IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !rl.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.clients[key]
	if !ok {
		b = &bucket{tokens: rl.burst, lastCheck: time.Now()}
		rl.clients[key] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.lastCheck = now
	b.tokens += int(elapsed * float64(rl.rate))
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// LoggingMiddleware logs each request.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
