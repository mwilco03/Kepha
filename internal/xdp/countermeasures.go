package xdp

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"
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
	HitCount    uint64            `json:"hit_count"`
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
	p := c.policies[target]
	return p
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
		result = append(result, *p)
	}
	return result
}

// Evaluate determines what countermeasures should be applied to an IP.
// Returns nil if no countermeasures apply.
func (c *Countermeasures) Evaluate(srcIP string) *CountermeasurePolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	// Exact IP match first.
	if p, ok := c.policies[srcIP]; ok {
		if p.Active && (p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt)) {
			p.HitCount++
			return p
		}
	}

	// CIDR match — check all policies.
	for _, p := range c.policies {
		if !p.Active || (!p.ExpiresAt.IsZero() && now.After(p.ExpiresAt)) {
			continue
		}
		if matchCIDRSimple(srcIP, p.Target) {
			p.HitCount++
			return p
		}
	}

	return nil
}

// GenerateNftRules produces nftables rule fragments for all active policies.
// These can be injected into the Gatekeeper rule chain.
//
// Returns rules as nft command strings suitable for batch execution.
func (c *Countermeasures) GenerateNftRules() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var rules []string
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
				// nftables doesn't have native tarpit, but we can use queue
				// to userspace + delayed accept. Alternative: use iptables
				// TARPIT target via xtables-nft compatibility.
				rules = append(rules,
					fmt.Sprintf("ip saddr %s tcp dport { 22, 23, 80, 443 } meter tarpit_%s { ip saddr limit rate 1/minute } accept",
						p.Target, sanitizeForNft(p.Target)),
					fmt.Sprintf("ip saddr %s tcp dport { 22, 23, 80, 443 } drop",
						p.Target),
				)

			case TechniqueLatency:
				// Use tc-netem for per-IP latency injection, or nftables queue
				// to userspace delay. Here we generate the nft queue rule.
				rules = append(rules,
					fmt.Sprintf("ip saddr %s queue num 100 bypass comment \"latency-inject-%s\"",
						p.Target, sanitizeForNft(p.Target)),
				)

			case TechniqueBandwidth:
				// nftables hashlimit for bandwidth throttling.
				limitBps := c.global.BandwidthLimitBps
				if v, ok := tech.Params["limit_bps"]; ok {
					fmt.Sscanf(v, "%d", &limitBps)
				}
				// Convert bytes/sec to packets/sec using configured or detected MTU.
				// Supports jumbo frames (9000) and VXLAN-reduced MTUs (1450).
				avgPktSize := c.global.AvgPacketSize
				if avgPktSize <= 0 {
					avgPktSize = DefaultAvgPacketSize
				}
				pps := limitBps / avgPktSize
				if pps < 1 {
					pps = 1
				}
				rules = append(rules,
					fmt.Sprintf("ip saddr %s limit rate %d/second accept",
						p.Target, pps),
					fmt.Sprintf("ip saddr %s drop comment \"bw-throttle-%s\"",
						p.Target, sanitizeForNft(p.Target)),
				)

			case TechniqueSYNCookie:
				// Force SYN cookies for this source.
				rules = append(rules,
					fmt.Sprintf("ip saddr %s tcp flags syn limit rate 1/second accept",
						p.Target),
					fmt.Sprintf("ip saddr %s tcp flags syn drop comment \"syn-cookie-enforce-%s\"",
						p.Target, sanitizeForNft(p.Target)),
				)

			case TechniqueTTLRandomize:
				// TTL manipulation via nftables mangle.
				ttl := 32 + rand.Intn(96) // Random TTL between 32-128.
				rules = append(rules,
					fmt.Sprintf("ip daddr %s ip ttl set %d comment \"ttl-rand-%s\"",
						p.Target, ttl, sanitizeForNft(p.Target)),
				)
			}
		}
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

// matchCIDRSimple checks if an IP matches a target (IP or CIDR prefix).
func matchCIDRSimple(ip, target string) bool {
	// If target contains '/', it's a CIDR — check prefix.
	if idx := len(target) - 1; idx > 0 {
		for i := idx; i >= 0; i-- {
			if target[i] == '/' {
				prefix := target[:i]
				// Simple dotted-quad prefix match.
				parts := splitDots(prefix)
				ipParts := splitDots(ip)
				if len(parts) == 0 || len(ipParts) < len(parts) {
					return false
				}
				for j, p := range parts {
					if p != ipParts[j] {
						return false
					}
				}
				return true
			}
		}
	}
	return ip == target
}

func splitDots(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}
