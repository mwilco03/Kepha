package xdp

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mwilco03/kepha/internal/validate"
)

// Countermeasures implements active defense techniques that impose costs
// on attackers while minimizing impact on legitimate traffic.
//
// Unlike simple blocking (DROP), these techniques are designed to waste
// an attacker's time, resources, and patience:
//
// # Techniques
//
// 1. Tarpit (TCP slow-drain)
//    Accept the TCP connection but respond with minimum window size (1 byte)
//    and artificially slow the data transfer. The attacker's connection slot
//    is tied up for minutes instead of milliseconds. At scale, this exhausts
//    their connection pool. Implemented via nftables queue + userspace throttle.
//
// 2. Latency injection
//    Add random delay (100ms-5s) to responses from suspicious sources.
//    Attackers running automated tools see massive slowdowns that make their
//    scans impractical. Legitimate users on the same network are unaffected
//    because targeting is per-IP based on threat score.
//
// 3. Bandwidth throttle
//    Rate-limit suspicious sources to a trickle (e.g., 1 kbps). They can
//    technically still communicate, but scanning or exfiltration becomes
//    infeasible. Uses nftables hashlimit matching.
//
// 4. Connection reset storm (RST chaos)
//    Periodically RST connections from known-bad IPs. The attacker's tools
//    must handle reconnection, adding overhead and confusion. Some tools
//    will give up entirely after repeated failures.
//
// 5. SYN cookie enforcement
//    Force SYN cookies for suspicious sources. This prevents SYN flood
//    attacks and adds slight overhead to the attacker's connection setup
//    while using zero server memory for half-open connections.
//
// 6. TTL manipulation
//    Respond with randomized TTL values to confuse network mapping and
//    OS fingerprinting tools (nmap, p0f). The attacker can't reliably
//    determine the OS or network topology.
//
// All countermeasures are opt-in and configurable per-IP or per-CIDR.
// They can be triggered manually or automatically by threat feed matches
// and anomaly detection alerts.
type Countermeasures struct {
	mu       sync.RWMutex
	policies map[string]*CountermeasurePolicy // IP or CIDR -> policy
	global   CountermeasureConfig
	stats    CountermeasureStats
	enforcer *Enforcer
	// enabled controls whether countermeasures are enforced in the kernel.
	// Disabled by default — requires a deliberate call to Enable().
	// Policies can be added while disabled; they will not be applied
	// until Enable() is called.
	enabled bool
}

// CountermeasurePolicy defines what active defenses to apply to a target.
type CountermeasurePolicy struct {
	Target      string            `json:"target"`       // IP address or CIDR
	Techniques  []TechniqueConfig `json:"techniques"`
	Reason      string            `json:"reason"`       // Why this policy was created
	Source      string            `json:"source"`       // "manual", "threat_feed", "anomaly"
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`   // Zero = permanent
	HitCount    atomic.Uint64     `json:"hit_count"`
	Active      bool              `json:"active"`
}

// TechniqueConfig configures a single countermeasure technique.
type TechniqueConfig struct {
	Type    TechniqueType `json:"type"`
	Enabled bool          `json:"enabled"`
	Params  map[string]string `json:"params,omitempty"`
}

// TechniqueType identifies a countermeasure technique.
type TechniqueType string

const (
	TechniqueTarpit         TechniqueType = "tarpit"
	TechniqueLatency        TechniqueType = "latency"
	TechniqueBandwidth      TechniqueType = "bandwidth"
	TechniqueRSTChaos       TechniqueType = "rst_chaos"
	TechniqueSYNCookie      TechniqueType = "syn_cookie"
	TechniqueTTLRandomize   TechniqueType = "ttl_randomize"
)

// DefaultAvgPacketSize is the assumed average packet size for converting
// byte rates to packet rates. 1500 is standard Ethernet; set higher for
// jumbo frame environments (e.g., 9000) or lower for overlay networks
// with reduced MTU (e.g., 1450 for VXLAN on Proxmox).
const DefaultAvgPacketSize = 1500

// CountermeasureConfig holds global settings.
type CountermeasureConfig struct {
	// TarpitWindowSize is the TCP window size offered to tarpitted connections.
	// Smaller = slower drain. Default: 1 byte.
	TarpitWindowSize int `json:"tarpit_window_size"`
	// TarpitTimeout is how long to hold a tarpitted connection.
	TarpitTimeout time.Duration `json:"tarpit_timeout"`

	// LatencyMinMs is the minimum added latency in milliseconds.
	LatencyMinMs int `json:"latency_min_ms"`
	// LatencyMaxMs is the maximum added latency in milliseconds.
	LatencyMaxMs int `json:"latency_max_ms"`

	// BandwidthLimitBps is the bandwidth cap in bytes per second.
	BandwidthLimitBps int `json:"bandwidth_limit_bps"`

	// RSTChaosProbability is the probability (0.0-1.0) of RST-ing a connection.
	RSTChaosProbability float64 `json:"rst_chaos_probability"`
	// RSTChaosIntervalSec is the minimum interval between RSTs for the same IP.
	RSTChaosIntervalSec int `json:"rst_chaos_interval_sec"`

	// AvgPacketSize is the assumed average packet size for byte-to-packet-rate
	// conversions. 0 = use DefaultAvgPacketSize (1500). Set to 9000 for jumbo
	// frame zones or 1450 for VXLAN overlay environments.
	AvgPacketSize int `json:"avg_packet_size"`
}

// CountermeasureStats tracks countermeasure activity.
type CountermeasureStats struct {
	TarpitActive      int    `json:"tarpit_active"`      // Currently tarpitted connections
	TarpitTotal       uint64 `json:"tarpit_total"`       // Total connections tarpitted
	LatencyInjections uint64 `json:"latency_injections"` // Times latency was injected
	BandwidthThrottled uint64 `json:"bandwidth_throttled"` // Connections throttled
	RSTsSent          uint64 `json:"rsts_sent"`           // RST packets sent
	SYNCookiesForced  uint64 `json:"syn_cookies_forced"`  // SYN cookies applied
	TTLRandomized     uint64 `json:"ttl_randomized"`      // Packets with randomized TTL
}

// NewCountermeasures creates a new countermeasures engine with defaults.
//
// The engine starts DISABLED. Policies can be added but will not be
// enforced until Enable() is explicitly called. This is a safety
// measure — active countermeasures (tarpit, RST chaos, etc.) should
// never activate without a deliberate operator decision.
func NewCountermeasures() *Countermeasures {
	return &Countermeasures{
		policies: make(map[string]*CountermeasurePolicy),
		global: CountermeasureConfig{
			TarpitWindowSize:    1,     // 1 byte — maximum slowdown
			TarpitTimeout:       5 * time.Minute,
			LatencyMinMs:        100,   // 100ms minimum
			LatencyMaxMs:        5000,  // 5s maximum
			BandwidthLimitBps:   1024,  // 1 KB/s
			RSTChaosProbability: 0.3,   // 30% chance per connection
			RSTChaosIntervalSec: 10,    // No more than 1 RST per 10 seconds per IP
		},
		enforcer: NewEnforcer(),
		enabled:  false, // Disabled by default. Requires deliberate Enable() call.
	}
}

// Enable activates enforcement of countermeasure policies. When enabled,
// nftables rules are applied via netlink for all active policies.
//
// This is a deliberate action — countermeasures are never auto-enabled.
func (c *Countermeasures) Enable() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.enabled = true
	slog.Info("countermeasures enabled — active defense is now enforcing")
	return c.syncEnforcer()
}

// Disable deactivates enforcement and tears down all countermeasure rules.
// Policies are retained but no longer enforced.
func (c *Countermeasures) Disable() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.enabled = false
	slog.Info("countermeasures disabled — tearing down enforcement rules")
	return c.enforcer.Teardown()
}

// Enabled reports whether countermeasure enforcement is active.
func (c *Countermeasures) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// syncEnforcer pushes all active policies to the kernel via netlink.
// Must be called with c.mu held.
func (c *Countermeasures) syncEnforcer() error {
	if !c.enabled {
		return nil
	}
	policies := c.activePoliciesLocked()
	return c.enforcer.Sync(policies, c.global)
}

// activePoliciesLocked returns non-expired active policies. Must hold c.mu.
func (c *Countermeasures) activePoliciesLocked() []CountermeasurePolicy {
	now := time.Now()
	result := make([]CountermeasurePolicy, 0, len(c.policies))
	for _, p := range c.policies {
		if p.Active && (p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt)) {
			result = append(result, *p)
		}
	}
	return result
}

// AddPolicy creates a countermeasure policy for a target IP or CIDR.
func (c *Countermeasures) AddPolicy(policy CountermeasurePolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if policy.Target == "" {
		return fmt.Errorf("target IP or CIDR is required")
	}
	if len(policy.Techniques) == 0 {
		return fmt.Errorf("at least one technique must be specified")
	}

	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}
	policy.Active = true

	c.policies[policy.Target] = &policy

	slog.Info("countermeasure policy added",
		"target", policy.Target,
		"techniques", len(policy.Techniques),
		"reason", policy.Reason,
		"source", policy.Source,
		"enforcing", c.enabled,
	)

	if err := c.syncEnforcer(); err != nil {
		slog.Warn("failed to sync enforcer after add", "error", err)
	}
	return nil
}

// RemovePolicy removes a countermeasure policy.
func (c *Countermeasures) RemovePolicy(target string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.policies[target]; !ok {
		return fmt.Errorf("no policy for %q", target)
	}
	delete(c.policies, target)

	if err := c.syncEnforcer(); err != nil {
		slog.Warn("failed to sync enforcer after remove", "error", err)
	}
	return nil
}

// GetPolicy returns the policy for a specific target.
func (c *Countermeasures) GetPolicy(target string) *CountermeasurePolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.policies[target]
	if !ok {
		return nil
	}
	return copyPolicy(p)
}

// ListPolicies returns all active countermeasure policies.
func (c *Countermeasures) ListPolicies() []CountermeasurePolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]CountermeasurePolicy, 0, len(c.policies))
	now := time.Now()
	for _, p := range c.policies {
		// Skip expired policies.
		if !p.ExpiresAt.IsZero() && now.After(p.ExpiresAt) {
			continue
		}
		result = append(result, *copyPolicy(p))
	}
	return result
}

// copyPolicy returns a safe copy of a policy. Callers must not hold references to internal state.
func copyPolicy(p *CountermeasurePolicy) *CountermeasurePolicy {
	cp := CountermeasurePolicy{
		Target:     p.Target,
		Techniques: p.Techniques,
		Reason:     p.Reason,
		Source:     p.Source,
		CreatedAt:  p.CreatedAt,
		ExpiresAt:  p.ExpiresAt,
		Active:     p.Active,
	}
	cp.HitCount.Store(p.HitCount.Load())
	return &cp
}

// Evaluate determines what countermeasures should be applied to an IP.
// Returns nil if no countermeasures apply. Returns a copy — safe for concurrent use.
func (c *Countermeasures) Evaluate(srcIP string) *CountermeasurePolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	// Exact IP match first.
	if p, ok := c.policies[srcIP]; ok {
		if p.Active && (p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt)) {
			p.HitCount.Add(1)
			return copyPolicy(p)
		}
	}

	// CIDR match — check all policies.
	for _, p := range c.policies {
		if !p.Active || (!p.ExpiresAt.IsZero() && now.After(p.ExpiresAt)) {
			continue
		}
		if matchCIDRSimple(srcIP, p.Target) {
			p.HitCount.Add(1)
			return copyPolicy(p)
		}
	}

	return nil
}

// CountermeasureRule is a structured representation of a countermeasure nftables
// rule. Callers should apply these via the netlink backend, not via shell-out.
type CountermeasureRule struct {
	Target    string        // IP or CIDR to match.
	Technique TechniqueType // Which countermeasure technique.
	Action    string        // "accept", "drop", or "queue".
	Protocol  string        // "tcp", "" (any).
	Ports     []uint16      // Destination ports (empty = any).
	RateLimit int           // Packets per second (0 = no limit).
	TTL       int           // TTL override (0 = no change).
	QueueNum  int           // NFQUEUE number (0 = unused).
	Comment   string        // Rule comment for audit.
}

// GenerateRules produces structured countermeasure rule descriptors for all
// active policies. These should be applied via the netlink backend — no
// shell-out to the nft CLI.
func (c *Countermeasures) GenerateRules() []CountermeasureRule {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var rules []CountermeasureRule
	now := time.Now()

	for _, p := range c.policies {
		if !p.Active || (!p.ExpiresAt.IsZero() && now.After(p.ExpiresAt)) {
			continue
		}

		for _, tech := range p.Techniques {
			if !tech.Enabled {
				continue
			}

			switch tech.Type {
			case TechniqueTarpit:
				rules = append(rules,
					CountermeasureRule{
						Target: p.Target, Technique: TechniqueTarpit,
						Action: "accept", Protocol: "tcp",
						Ports: []uint16{22, 23, 80, 443}, RateLimit: 1,
						Comment: "tarpit-" + p.Target,
					},
					CountermeasureRule{
						Target: p.Target, Technique: TechniqueTarpit,
						Action: "drop", Protocol: "tcp",
						Ports: []uint16{22, 23, 80, 443},
						Comment: "tarpit-drop-" + p.Target,
					},
				)

			case TechniqueLatency:
				rules = append(rules, CountermeasureRule{
					Target: p.Target, Technique: TechniqueLatency,
					Action: "queue", QueueNum: 100,
					Comment: "latency-inject-" + p.Target,
				})

			case TechniqueBandwidth:
				limitBps := c.global.BandwidthLimitBps
				if v, ok := tech.Params["limit_bps"]; ok {
					fmt.Sscanf(v, "%d", &limitBps)
				}
				avgPktSize := c.global.AvgPacketSize
				if avgPktSize <= 0 {
					avgPktSize = DefaultAvgPacketSize
				}
				pps := limitBps / avgPktSize
				if pps < 1 {
					pps = 1
				}
				rules = append(rules,
					CountermeasureRule{
						Target: p.Target, Technique: TechniqueBandwidth,
						Action: "accept", RateLimit: pps,
						Comment: "bw-limit-" + p.Target,
					},
					CountermeasureRule{
						Target: p.Target, Technique: TechniqueBandwidth,
						Action: "drop",
						Comment: "bw-throttle-" + p.Target,
					},
				)

			case TechniqueSYNCookie:
				rules = append(rules,
					CountermeasureRule{
						Target: p.Target, Technique: TechniqueSYNCookie,
						Action: "accept", Protocol: "tcp", RateLimit: 1,
						Comment: "syn-cookie-" + p.Target,
					},
					CountermeasureRule{
						Target: p.Target, Technique: TechniqueSYNCookie,
						Action: "drop", Protocol: "tcp",
						Comment: "syn-cookie-enforce-" + p.Target,
					},
				)

			case TechniqueTTLRandomize:
				b := make([]byte, 1)
				if _, err := rand.Read(b); err != nil {
					slog.Error("crypto/rand failed for TTL randomization", "error", err)
					continue
				}
				ttl := 32 + int(b[0])%96
				rules = append(rules, CountermeasureRule{
					Target: p.Target, Technique: TechniqueTTLRandomize,
					Action: "accept", TTL: ttl,
					Comment: "ttl-rand-" + p.Target,
				})
			}
		}
	}

	return rules
}

// GenerateNftRules is DEPRECATED. Use GenerateRules() + netlink backend instead.
// Retained temporarily for backward compatibility with callers not yet migrated.
func (c *Countermeasures) GenerateNftRules() []string {
	structured := c.GenerateRules()
	rules := make([]string, 0, len(structured))
	for _, r := range structured {
		rules = append(rules, r.Comment) // Placeholder — callers should migrate.
	}
	return rules
}

// Stats returns current countermeasure statistics.
func (c *Countermeasures) Stats() CountermeasureStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// DefaultThreatPolicy creates a standard countermeasure policy for a
// threat feed match. Applies tarpit + bandwidth throttle + SYN cookie.
func DefaultThreatPolicy(target, reason string) CountermeasurePolicy {
	return CountermeasurePolicy{
		Target: target,
		Techniques: []TechniqueConfig{
			{Type: TechniqueTarpit, Enabled: true},
			{Type: TechniqueBandwidth, Enabled: true, Params: map[string]string{"limit_bps": "512"}},
			{Type: TechniqueSYNCookie, Enabled: true},
			{Type: TechniqueTTLRandomize, Enabled: true},
		},
		Reason:    reason,
		Source:    "threat_feed",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Auto-expire after 24h.
		Active:    true,
	}
}

// DefaultAnomalyPolicy creates a lighter countermeasure for anomaly detection.
// Applies latency injection + bandwidth limit (less aggressive than threat policy).
func DefaultAnomalyPolicy(target, reason string) CountermeasurePolicy {
	return CountermeasurePolicy{
		Target: target,
		Techniques: []TechniqueConfig{
			{Type: TechniqueLatency, Enabled: true, Params: map[string]string{
				"min_ms": "200",
				"max_ms": "2000",
			}},
			{Type: TechniqueBandwidth, Enabled: true, Params: map[string]string{"limit_bps": "10240"}},
		},
		Reason:    reason,
		Source:    "anomaly",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour), // Lighter: 1h expiry.
		Active:    true,
	}
}

// sanitizeForNft sanitizes a string for use in nftables comments.
func sanitizeForNft(s string) string {
	// Replace characters that aren't safe in nft comments/names.
	replacer := func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}
	result := make([]byte, 0, len(s))
	for _, r := range s {
		result = append(result, byte(replacer(r)))
	}
	return string(result)
}

// matchCIDRSimple delegates to the shared validate.MatchCIDR implementation.
func matchCIDRSimple(ip, target string) bool {
	return validate.MatchCIDR(ip, target)
}
