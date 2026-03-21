// Package ops provides the shared business logic layer for Gatekeeper.
//
// Both the CLI and API handlers call through this layer to ensure:
//   - Identical input validation regardless of entry point
//   - Consistent audit logging with source provenance
//   - No bypass of security controls
//
// The ops layer deliberately does NOT expose driver operations (nft.Apply,
// dnsmasq.Apply, wg.Apply). Only the daemon owns those — the CLI signals
// the daemon to apply after writing to the DB.
package ops

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

// Sentinel errors for the ops layer. Use errors.Is() in handlers
// instead of string-matching error messages (M-CR1).
var (
	ErrAlreadyExists = errors.New("already exists")
	ErrNotFound      = errors.New("not found")
	ErrInvalidInput  = errors.New("invalid input")
)

// IsConflict returns true if the error indicates a uniqueness violation.
// Replaces string-matching in API handlers.
func IsConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAlreadyExists) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "UNIQUE constraint")
}

// IsNotFound returns true if the error indicates a missing resource.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotFound) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no rows")
}

// Actor identifies who is performing an operation, used for audit logging
// and future RBAC. Every mutation must carry an Actor.
type Actor struct {
	Source string // "api", "cli", "web" — written to audit log source column
	User   string // Future: username, API key identity, or "root" for CLI
}

// Ops provides validated, audited operations on the config store.
// It is the single entry point for all mutations — neither the CLI
// nor the API handlers should call store methods directly for writes.
type Ops struct {
	store *config.Store
}

// New creates an Ops instance backed by the given store.
func New(store *config.Store) *Ops {
	return &Ops{store: store}
}

// Store returns the underlying store for read-only operations that
// don't require validation or audit logging (e.g., list queries).
func (o *Ops) Store() *config.Store {
	return o.store
}

// audit logs a mutation. Failures are logged as warnings rather than
// silently discarded (M-CR2).
func (o *Ops) audit(actor Actor, action, resource, name string, data any) {
	if err := o.store.LogAudit(actor.Source, action, resource, name, data); err != nil {
		slog.Warn("audit log write failed", "action", action, "resource", resource, "name", name, "error", err)
	}
}
