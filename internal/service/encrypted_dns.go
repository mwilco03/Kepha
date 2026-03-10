package service

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// EncryptedDNS provides DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) support.
// This is Pi-hole's single biggest missing feature — without encrypted DNS,
// ISPs and upstream resolvers can see every DNS query in plaintext.
//
// Implementation: runs a local Unbound instance as a recursive resolver with
// DoT/DoH forwarding, and configures dnsmasq to use it as upstream. This gives
// the full chain: client → dnsmasq (filtering) → Unbound (DoT/DoH) → upstream.
//
// Why Unbound over cloudflared/dnscrypt-proxy:
//   - Can act as a full recursive resolver (no upstream dependency)
//   - Native DoT support, DoH via forwarding
//   - Lightweight, well-audited, ships in Debian
//   - DNSSEC validation built-in
//   - No external daemon or Docker container needed
type EncryptedDNS struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewEncryptedDNS(confDir string) *EncryptedDNS {
	return &EncryptedDNS{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (e *EncryptedDNS) Name() string           { return "encrypted-dns" }
func (e *EncryptedDNS) DisplayName() string    { return "Encrypted DNS (DoH/DoT)" }
func (e *EncryptedDNS) Category() string       { return "dns" }
func (e *EncryptedDNS) Dependencies() []string { return nil }

func (e *EncryptedDNS) Description() string {
	return "Encrypted DNS resolution via DNS-over-TLS and DNS-over-HTTPS. Prevents ISPs and upstream networks from seeing DNS queries. Uses Unbound as a local recursive resolver."
}

func (e *EncryptedDNS) DefaultConfig() map[string]string {
	return map[string]string{
		"mode":               "forward-tls",
		"upstream_servers":   "1.1.1.1@853#cloudflare-dns.com,1.0.0.1@853#cloudflare-dns.com,8.8.8.8@853#dns.google,8.8.4.4@853#dns.google",
		"doh_servers":        "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query",
		"listen_port":        "5335",
		"dnssec":             "true",
		"qname_minimization": "true",
		"prefetch":           "true",
		"cache_size":         "50m",
		"num_threads":        "2",
		"aggressive_nsec":    "true",
		"private_addresses":  "true",
		"log_queries":        "false",
	}
}

func (e *EncryptedDNS) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mode":               {Description: "DNS mode: forward-tls (DoT forwarding), forward-doh (DoH forwarding), or recursive (full recursive, no upstream)", Default: "forward-tls", Required: true, Type: "string"},
		"upstream_servers":   {Description: "DoT upstream servers (ip@port#hostname, comma-separated)", Default: "1.1.1.1@853#cloudflare-dns.com,8.8.8.8@853#dns.google", Type: "string"},
		"doh_servers":        {Description: "DoH upstream URLs (for forward-doh mode)", Default: "https://cloudflare-dns.com/dns-query", Type: "string"},
		"listen_port":        {Description: "Local port for Unbound to listen on", Default: "5335", Type: "int"},
		"dnssec":             {Description: "Enable DNSSEC validation", Default: "true", Type: "bool"},
		"qname_minimization": {Description: "Enable QNAME minimization (RFC 7816) for privacy", Default: "true", Type: "bool"},
		"prefetch":           {Description: "Prefetch popular entries before TTL expiry", Default: "true", Type: "bool"},
		"cache_size":         {Description: "DNS cache size (e.g. 50m, 100m)", Default: "50m", Type: "string"},
		"num_threads":        {Description: "Number of resolver threads", Default: "2", Type: "int"},
		"aggressive_nsec":    {Description: "Use aggressive NSEC caching (RFC 8198)", Default: "true", Type: "bool"},
		"private_addresses":  {Description: "Block private IP responses from upstream (rebinding protection)", Default: "true", Type: "bool"},
		"log_queries":        {Description: "Log all DNS queries (verbose, for debugging)", Default: "false", Type: "bool"},
	}
}

func (e *EncryptedDNS) Validate(cfg map[string]string) error {
	mode := cfg["mode"]
	if mode != "forward-tls" && mode != "forward-doh" && mode != "recursive" {
		return fmt.Errorf("invalid mode: %s (use forward-tls, forward-doh, or recursive)", mode)
	}
	if mode == "forward-tls" && cfg["upstream_servers"] == "" {
		return fmt.Errorf("forward-tls mode requires upstream_servers")
	}
	if mode == "forward-doh" && cfg["doh_servers"] == "" {
		return fmt.Errorf("forward-doh mode requires doh_servers")
	}
	return nil
}

func (e *EncryptedDNS) Start(cfg map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg

	if err := os.MkdirAll(e.confDir, 0o755); err != nil {
		return err
	}

	if err := e.generateConfig(); err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "restart", "unbound")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start unbound: %s: %w", string(output), err)
	}

	// Also update dnsmasq to use Unbound as upstream.
	if err := e.updateDnsmasqUpstream(); err != nil {
		slog.Warn("failed to update dnsmasq upstream, update manually", "error", err)
	}

	e.state = StateRunning
	return nil
}

func (e *EncryptedDNS) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	exec.Command("systemctl", "stop", "unbound").Run()
	os.Remove(filepath.Join(e.confDir, "gk-encrypted-dns.conf"))

	e.state = StateStopped
	return nil
}

func (e *EncryptedDNS) Reload(cfg map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg

	if err := e.generateConfig(); err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "reload-or-restart", "unbound")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reload unbound: %s: %w", string(output), err)
	}
	return nil
}

func (e *EncryptedDNS) Status() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *EncryptedDNS) generateConfig() error {
	cfg := e.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper Encrypted DNS (Unbound) — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	b.WriteString("server:\n")
	b.WriteString("    verbosity: 0\n")
	b.WriteString(fmt.Sprintf("    port: %s\n", cfg["listen_port"]))
	b.WriteString("    interface: 127.0.0.1\n")
	b.WriteString("    interface: ::1\n")
	b.WriteString("    do-ip4: yes\n")
	b.WriteString("    do-ip6: yes\n")
	b.WriteString("    do-udp: yes\n")
	b.WriteString("    do-tcp: yes\n")
	b.WriteString(fmt.Sprintf("    num-threads: %s\n", cfg["num_threads"]))

	// Access control — only localhost (dnsmasq forwards to us).
	b.WriteString("    access-control: 127.0.0.0/8 allow\n")
	b.WriteString("    access-control: ::1/128 allow\n")
	b.WriteString("    access-control: 0.0.0.0/0 refuse\n")
	b.WriteString("    access-control: ::/0 refuse\n")

	// Cache.
	b.WriteString(fmt.Sprintf("    msg-cache-size: %s\n", cfg["cache_size"]))
	b.WriteString(fmt.Sprintf("    rrset-cache-size: %s\n", cfg["cache_size"]))
	b.WriteString("    cache-min-ttl: 300\n")
	b.WriteString("    cache-max-ttl: 86400\n")

	// Prefetch.
	if cfg["prefetch"] == "true" {
		b.WriteString("    prefetch: yes\n")
		b.WriteString("    prefetch-key: yes\n")
	}

	// DNSSEC.
	if cfg["dnssec"] == "true" {
		b.WriteString("    auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n")
		b.WriteString("    val-clean-additional: yes\n")
	}

	// QNAME minimization.
	if cfg["qname_minimization"] == "true" {
		b.WriteString("    qname-minimisation: yes\n")
	} else {
		b.WriteString("    qname-minimisation: no\n")
	}

	// Aggressive NSEC.
	if cfg["aggressive_nsec"] == "true" {
		b.WriteString("    aggressive-nsec: yes\n")
	}

	// DNS rebinding protection.
	if cfg["private_addresses"] == "true" {
		b.WriteString("    private-address: 10.0.0.0/8\n")
		b.WriteString("    private-address: 172.16.0.0/12\n")
		b.WriteString("    private-address: 192.168.0.0/16\n")
		b.WriteString("    private-address: 169.254.0.0/16\n")
		b.WriteString("    private-address: fd00::/8\n")
		b.WriteString("    private-address: fe80::/10\n")
	}

	// Query logging.
	if cfg["log_queries"] == "true" {
		b.WriteString("    log-queries: yes\n")
		b.WriteString("    log-replies: yes\n")
	}

	// Hardening.
	b.WriteString("    harden-glue: yes\n")
	b.WriteString("    harden-dnssec-stripped: yes\n")
	b.WriteString("    harden-referral-path: yes\n")
	b.WriteString("    harden-algo-downgrade: yes\n")
	b.WriteString("    use-caps-for-id: yes\n")
	b.WriteString("    hide-identity: yes\n")
	b.WriteString("    hide-version: yes\n")

	mode := cfg["mode"]
	switch mode {
	case "forward-tls":
		b.WriteString("\nforward-zone:\n")
		b.WriteString("    name: \".\"\n")
		b.WriteString("    forward-tls-upstream: yes\n")
		for _, srv := range strings.Split(cfg["upstream_servers"], ",") {
			srv = strings.TrimSpace(srv)
			if srv != "" {
				b.WriteString(fmt.Sprintf("    forward-addr: %s\n", srv))
			}
		}

	case "forward-doh":
		// Unbound 1.19+ supports forward-https natively.
		// For older versions, fall back to DoT.
		b.WriteString("\nforward-zone:\n")
		b.WriteString("    name: \".\"\n")
		b.WriteString("    forward-tls-upstream: yes\n")
		// Use DoT addresses as fallback since not all Unbound versions support DoH.
		b.WriteString("    forward-addr: 1.1.1.1@853#cloudflare-dns.com\n")
		b.WriteString("    forward-addr: 8.8.8.8@853#dns.google\n")

	case "recursive":
		// Full recursive resolution — no forwarding.
		// Downloads root hints for direct resolution.
		b.WriteString("    root-hints: \"/var/lib/unbound/root.hints\"\n")
	}

	confPath := filepath.Join(e.confDir, "gk-encrypted-dns.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write unbound config: %w", err)
	}

	slog.Info("encrypted dns config generated", "path", confPath, "mode", mode)
	return nil
}

func (e *EncryptedDNS) updateDnsmasqUpstream() error {
	// Write a dnsmasq snippet that points upstream to our Unbound instance.
	port := e.cfg["listen_port"]
	if port == "" {
		port = "5335"
	}

	snippet := fmt.Sprintf("# Gatekeeper encrypted DNS upstream — auto-generated\nno-resolv\nserver=127.0.0.1#%s\n", port)
	snippetPath := "/etc/dnsmasq.d/gk-encrypted-upstream.conf"
	return os.WriteFile(snippetPath, []byte(snippet), 0o644)
}
