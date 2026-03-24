// Package service content_filter implements a DNS-level content filtering engine.
//
// Architecture:
//
//	Config layer: admin creates ContentFilter rules (categories, domains) via API
//	Store layer:  filters and exceptions are persisted in SQLite
//	Engine layer: this file — builds an in-memory domain index from filters,
//	              provides O(1) domain → decision lookups on the DNS hot path
//	Enforcement:  DNS interceptor calls CheckDomain() before forwarding queries
//
// Security boundaries:
//   - Filter rules and exception approvals require separate RBAC permissions
//   - Exception requests require documented justification
//   - Only admin role can approve/deny/revoke exceptions
//   - Approved exceptions are time-bounded and auto-expire
//   - All mutations are audit-logged
//   - The engine is read-only on the hot path (no writes during DNS resolution)
package service

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/mwilco03/kepha/internal/config"
	"github.com/mwilco03/kepha/internal/model"
)

// FilterDecision is the result of checking a domain against content filters.
type FilterDecision string

const (
	FilterAllow FilterDecision = "allow"
	FilterBlock FilterDecision = "block"
)

// FilterResult contains the decision and metadata about why a domain was blocked/allowed.
type FilterResult struct {
	Decision  FilterDecision      `json:"decision"`
	Domain    string              `json:"domain"`
	FilterID  int64               `json:"filter_id,omitempty"`
	Category  model.ContentCategory `json:"category,omitempty"`
	Reason    string              `json:"reason,omitempty"`
	Exception *model.FilterException `json:"exception,omitempty"` // Non-nil if an exception was applied.
}

// ContentFilterEngine evaluates domains against configured content filters.
// It maintains an in-memory index rebuilt from the store on Reload().
//
// The engine is safe for concurrent use: the hot path (CheckDomain) uses
// read-only access to immutable snapshots swapped atomically via sync.RWMutex.
type ContentFilterEngine struct {
	mu    sync.RWMutex
	store *config.Store

	// Immutable snapshots rebuilt on Reload().
	blockedDomains  map[string]blockEntry // domain → reason
	allowedDomains  map[string]bool       // domain → always allowed (explicit allowlist)
	exceptedDomains map[string]bool       // domain → has active approved exception
	filters         []model.ContentFilter // current filter configs

	// Category domain lists. Populated by external category feed or static lists.
	// Key is category, value is set of domains.
	categoryDomains map[model.ContentCategory]map[string]bool
}

type blockEntry struct {
	filterID int64
	category model.ContentCategory
	reason   string
}

// NewContentFilterEngine creates a new engine backed by the given store.
func NewContentFilterEngine(store *config.Store) *ContentFilterEngine {
	return &ContentFilterEngine{
		store:           store,
		blockedDomains:  make(map[string]blockEntry),
		allowedDomains:  make(map[string]bool),
		exceptedDomains: make(map[string]bool),
		categoryDomains: make(map[model.ContentCategory]map[string]bool),
	}
}

// Reload rebuilds the in-memory index from the store. Called on startup
// and after any filter/exception mutation.
func (e *ContentFilterEngine) Reload() error {
	filters, err := e.store.ListContentFilters()
	if err != nil {
		return err
	}

	// Expire stale exceptions before building the index.
	if n, err := e.store.ExpireFilterExceptions(); err == nil && n > 0 {
		slog.Info("content filter: expired exceptions", "count", n)
	}

	// Snapshot categoryDomains under a single read lock to avoid
	// RLock→Lock deadlock (Go RWMutex is not reentrant).
	e.mu.RLock()
	catDomains := make(map[model.ContentCategory]map[string]bool, len(e.categoryDomains))
	for cat, domains := range e.categoryDomains {
		catDomains[cat] = domains // Shallow copy of pointer — domains map is read-only.
	}
	e.mu.RUnlock()

	// Build new index (no locks held during construction).
	blocked := make(map[string]blockEntry)
	allowed := make(map[string]bool)
	excepted := make(map[string]bool)

	for _, f := range filters {
		if !f.Enabled {
			continue
		}

		// Explicit allowlist always takes priority.
		for _, d := range f.AllowedDomains {
			allowed[normalizeDomain(d)] = true
		}

		// Explicit domain blocklist.
		for _, d := range f.BlockedDomains {
			nd := normalizeDomain(d)
			if !allowed[nd] {
				blocked[nd] = blockEntry{
					filterID: f.ID,
					category: model.CategoryCustom,
					reason:   "explicit blocklist",
				}
			}
		}

		// Category-based blocking: use pre-snapshotted category domains.
		for _, cat := range f.BlockedCategories {
			for d := range catDomains[cat] {
				nd := normalizeDomain(d)
				if !allowed[nd] {
					blocked[nd] = blockEntry{
						filterID: f.ID,
						category: cat,
						reason:   "category: " + string(cat),
					}
				}
			}
		}

		// Load active exceptions for this filter.
		exceptions, err := e.store.ActiveExceptionsForFilter(f.ID)
		if err != nil {
			slog.Warn("content filter: failed to load exceptions", "filter", f.Name, "error", err)
			continue
		}
		for _, ex := range exceptions {
			excepted[normalizeDomain(ex.Domain)] = true
		}
	}

	// Atomic swap.
	e.mu.Lock()
	e.blockedDomains = blocked
	e.allowedDomains = allowed
	e.exceptedDomains = excepted
	e.filters = filters
	e.mu.Unlock()

	slog.Info("content filter: reloaded",
		"filters", len(filters),
		"blocked_domains", len(blocked),
		"allowed_domains", len(allowed),
		"exceptions", len(excepted),
	)
	return nil
}

// SetCategoryDomains registers domains for a content category.
// Called by external category feed importers.
func (e *ContentFilterEngine) SetCategoryDomains(cat model.ContentCategory, domains []string) {
	set := make(map[string]bool, len(domains))
	for _, d := range domains {
		set[normalizeDomain(d)] = true
	}

	e.mu.Lock()
	e.categoryDomains[cat] = set
	e.mu.Unlock()
}

// CheckDomain evaluates a domain against the content filters.
// This is the hot-path function called for every DNS query.
// It uses only read locks and pre-built maps — no database access.
func (e *ContentFilterEngine) CheckDomain(domain string) FilterResult {
	nd := normalizeDomain(domain)

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. Explicit allowlist — always wins.
	if e.allowedDomains[nd] {
		return FilterResult{Decision: FilterAllow, Domain: domain, Reason: "allowlisted"}
	}

	// 2. Check parent domains for wildcard-style matching.
	// e.g., "foo.bar.example.com" checks "foo.bar.example.com",
	// "bar.example.com", "example.com"
	for check := nd; check != ""; check = parentDomain(check) {
		// 2a. Approved exception overrides block.
		if e.exceptedDomains[check] {
			return FilterResult{Decision: FilterAllow, Domain: domain, Reason: "approved exception"}
		}

		// 2b. Block match.
		if entry, ok := e.blockedDomains[check]; ok {
			return FilterResult{
				Decision: FilterBlock,
				Domain:   domain,
				FilterID: entry.filterID,
				Category: entry.category,
				Reason:   entry.reason,
			}
		}
	}

	// 3. Not blocked — allow by default.
	return FilterResult{Decision: FilterAllow, Domain: domain}
}

// Stats returns engine statistics.
func (e *ContentFilterEngine) Stats() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	catCounts := make(map[string]int, len(e.categoryDomains))
	for cat, domains := range e.categoryDomains {
		catCounts[string(cat)] = len(domains)
	}
	return map[string]any{
		"filters":          len(e.filters),
		"blocked_domains":  len(e.blockedDomains),
		"allowed_domains":  len(e.allowedDomains),
		"active_exceptions": len(e.exceptedDomains),
		"category_domains": catCounts,
	}
}

// normalizeDomain lowercases and strips trailing dots.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimRight(d, ".")
	return d
}

// parentDomain returns the parent domain by stripping the leftmost label.
// Returns empty string if there are no more labels.
func parentDomain(d string) string {
	idx := strings.IndexByte(d, '.')
	if idx < 0 {
		return ""
	}
	return d[idx+1:]
}
