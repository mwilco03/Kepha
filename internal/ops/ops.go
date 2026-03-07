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
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

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
