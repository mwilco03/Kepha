package service

import (
	"testing"

	"github.com/mwilco03/kepha/internal/model"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Example.COM", "example.com"},
		{"foo.bar.", "foo.bar"},
		{"  UPPER.case  ", "upper.case"},
	}
	for _, tc := range tests {
		got := normalizeDomain(tc.input)
		if got != tc.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParentDomain(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"foo.bar.example.com", "bar.example.com"},
		{"example.com", "com"},
		{"com", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := parentDomain(tc.input)
		if got != tc.want {
			t.Errorf("parentDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCheckDomain_DirectBlock(t *testing.T) {
	e := &ContentFilterEngine{
		blockedDomains: map[string]blockEntry{
			"evil.com": {filterID: 1, category: model.CategoryMalware, reason: "malware"},
		},
		allowedDomains:  make(map[string]bool),
		exceptedDomains: make(map[string]bool),
	}

	// Direct match should block.
	r := e.CheckDomain("evil.com")
	if r.Decision != FilterBlock {
		t.Errorf("expected block, got %s", r.Decision)
	}

	// Subdomain should also block (parent matching).
	r = e.CheckDomain("sub.evil.com")
	if r.Decision != FilterBlock {
		t.Errorf("expected subdomain block, got %s", r.Decision)
	}

	// Unblocked domain should allow.
	r = e.CheckDomain("good.com")
	if r.Decision != FilterAllow {
		t.Errorf("expected allow, got %s", r.Decision)
	}
}

func TestCheckDomain_AllowlistOverridesBlock(t *testing.T) {
	e := &ContentFilterEngine{
		blockedDomains: map[string]blockEntry{
			"example.com": {filterID: 1, reason: "blocked"},
		},
		allowedDomains:  map[string]bool{"example.com": true},
		exceptedDomains: make(map[string]bool),
	}

	r := e.CheckDomain("example.com")
	if r.Decision != FilterAllow {
		t.Errorf("allowlist should override block, got %s", r.Decision)
	}
}

func TestCheckDomain_ExceptionOverridesBlock(t *testing.T) {
	e := &ContentFilterEngine{
		blockedDomains: map[string]blockEntry{
			"blocked.com": {filterID: 1, reason: "blocked"},
		},
		allowedDomains:  make(map[string]bool),
		exceptedDomains: map[string]bool{"blocked.com": true},
	}

	r := e.CheckDomain("blocked.com")
	if r.Decision != FilterAllow {
		t.Errorf("exception should override block, got %s", r.Decision)
	}
	if r.Reason != "approved exception" {
		t.Errorf("expected exception reason, got %q", r.Reason)
	}
}

func TestCheckDomain_SubdomainException(t *testing.T) {
	e := &ContentFilterEngine{
		blockedDomains: map[string]blockEntry{
			"social.com": {filterID: 1, reason: "social media"},
		},
		allowedDomains: make(map[string]bool),
		// Exception on parent domain covers subdomains.
		exceptedDomains: map[string]bool{"social.com": true},
	}

	r := e.CheckDomain("api.social.com")
	if r.Decision != FilterAllow {
		t.Errorf("parent exception should cover subdomain, got %s", r.Decision)
	}
}

func TestSetCategoryDomains(t *testing.T) {
	e := NewContentFilterEngine(nil)
	e.SetCategoryDomains(model.CategoryAds, []string{"ads.example.com", "track.example.com"})

	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.categoryDomains[model.CategoryAds]) != 2 {
		t.Errorf("expected 2 category domains, got %d", len(e.categoryDomains[model.CategoryAds]))
	}
}
