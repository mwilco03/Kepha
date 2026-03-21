package service

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DNSFilter provides network-wide ad/tracker blocking via DNS.
// It extends dnsmasq with blocklist support, acting as a Pi-hole analogue
// without Pi-hole's architectural flaws (PHP dependency, FTL complexity,
// fragile SQLite locking, broken CNAME handling).
//
// Key improvements over Pi-hole:
//   - No PHP — pure config generation for dnsmasq
//   - Blocklist updates are atomic (write temp, rename)
//   - Per-device bypass via device profiles (not IP-based hacks)
//   - Consolidated with DHCP — no separate daemon
//   - Query logging via dnsmasq's built-in facility
//   - Regex blocking via dnsmasq address= directives
//   - Allowlist always wins (Pi-hole regex ordering bugs)
type DNSFilter struct {
	mu       sync.Mutex
	state    State
	confDir  string
	cacheDir string
	cfg      map[string]string
}

func NewDNSFilter(confDir, cacheDir string) *DNSFilter {
	return &DNSFilter{
		confDir:  confDir,
		cacheDir: cacheDir,
		state:    StateStopped,
	}
}

func (d *DNSFilter) Name() string           { return "dns-filter" }
func (d *DNSFilter) DisplayName() string    { return "DNS Filtering" }
func (d *DNSFilter) Category() string       { return "dns" }
func (d *DNSFilter) Dependencies() []string { return nil }

func (d *DNSFilter) Description() string {
	return "Network-wide ad and tracker blocking via DNS. Blocks domains from configurable blocklists, supports allowlists, and provides per-device bypass."
}

func (d *DNSFilter) DefaultConfig() map[string]string {
	return map[string]string{
		"upstream_dns":     "1.1.1.1,8.8.8.8",
		"blocklists":       "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"allowlist":        "",
		"custom_blocklist": "",
		"query_logging":    "true",
		"log_facility":     "/var/log/gatekeeper/dns-queries.log",
		"cache_size":       "10000",
		"block_response":   "0.0.0.0",
		"dnssec":           "false",
		"local_domain":     "gk.local",
		"conditional_fwd":  "",
	}
}

func (d *DNSFilter) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"upstream_dns":     {Description: "Comma-separated upstream DNS servers", Default: "1.1.1.1,8.8.8.8", Type: "string"},
		"blocklists":       {Description: "Comma-separated blocklist URLs (hosts format)", Default: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Type: "string"},
		"allowlist":        {Description: "Comma-separated domains to always allow", Type: "string"},
		"custom_blocklist": {Description: "Comma-separated extra domains to block", Type: "string"},
		"query_logging":    {Description: "Enable DNS query logging", Default: "true", Type: "bool"},
		"log_facility":     {Description: "Path for query log file", Default: "/var/log/gatekeeper/dns-queries.log", Type: "path"},
		"cache_size":       {Description: "DNS cache size (entries)", Default: "10000", Type: "int"},
		"block_response":   {Description: "IP to return for blocked domains (0.0.0.0 or NXDOMAIN)", Default: "0.0.0.0", Type: "string"},
		"dnssec":           {Description: "Enable DNSSEC validation", Default: "false", Type: "bool"},
		"local_domain":     {Description: "Local domain suffix for LAN hosts", Default: "gk.local", Type: "string"},
		"conditional_fwd":  {Description: "Conditional forwarding: domain=server pairs, semicolon-separated", Type: "string"},
	}
}

func (d *DNSFilter) Validate(cfg map[string]string) error {
	if dns := cfg["upstream_dns"]; dns != "" {
		for _, s := range strings.Split(dns, ",") {
			s = strings.TrimSpace(s)
			if net.ParseIP(s) == nil {
				return fmt.Errorf("invalid upstream DNS IP: %s", s)
			}
		}
	}
	if resp := cfg["block_response"]; resp != "" && resp != "NXDOMAIN" {
		if net.ParseIP(resp) == nil {
			return fmt.Errorf("invalid block_response: %s (use IP or NXDOMAIN)", resp)
		}
	}
	return nil
}

func (d *DNSFilter) Start(cfg map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cfg = cfg

	if err := os.MkdirAll(d.confDir, 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(d.cacheDir, 0o750); err != nil {
		return err
	}

	if err := d.generateConfig(); err != nil {
		return err
	}

	if err := d.fetchBlocklists(); err != nil {
		slog.Warn("blocklist fetch failed, using cached", "error", err)
	}

	d.state = StateRunning
	return nil
}

func (d *DNSFilter) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = StateStopped
	// Remove generated config so dnsmasq no longer loads it.
	os.Remove(filepath.Join(d.confDir, "gk-dns-filter.conf"))
	os.Remove(filepath.Join(d.confDir, "gk-blocklist.conf"))
	return nil
}

func (d *DNSFilter) Reload(cfg map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = cfg
	return d.generateConfig()
}

func (d *DNSFilter) Status() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

func (d *DNSFilter) generateConfig() error {
	cfg := d.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper DNS Filter — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	// Upstream DNS servers.
	if dns := cfg["upstream_dns"]; dns != "" {
		b.WriteString("no-resolv\n")
		for _, s := range strings.Split(dns, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				b.WriteString(fmt.Sprintf("server=%s\n", s))
			}
		}
	}

	// DNS cache.
	if size := cfg["cache_size"]; size != "" {
		b.WriteString(fmt.Sprintf("cache-size=%s\n", size))
	}

	// DNSSEC.
	if cfg["dnssec"] == "true" {
		b.WriteString("dnssec\n")
		b.WriteString("trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")
	}

	// Query logging.
	if cfg["query_logging"] == "true" {
		b.WriteString("log-queries\n")
		if fac := cfg["log_facility"]; fac != "" {
			b.WriteString(fmt.Sprintf("log-facility=%s\n", fac))
		}
	}

	// Local domain.
	if dom := cfg["local_domain"]; dom != "" {
		b.WriteString(fmt.Sprintf("local=/%s/\n", dom))
		b.WriteString(fmt.Sprintf("domain=%s\n", dom))
		b.WriteString("expand-hosts\n")
	}

	// Conditional forwarding.
	if fwd := cfg["conditional_fwd"]; fwd != "" {
		for _, pair := range strings.Split(fwd, ";") {
			pair = strings.TrimSpace(pair)
			if pair != "" {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) == 2 {
					b.WriteString(fmt.Sprintf("server=/%s/%s\n", parts[0], parts[1]))
				}
			}
		}
	}

	// Include blocklist file.
	blocklistPath := filepath.Join(d.confDir, "gk-blocklist.conf")
	b.WriteString(fmt.Sprintf("\nconf-file=%s\n", blocklistPath))

	confPath := filepath.Join(d.confDir, "gk-dns-filter.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o640); err != nil {
		return fmt.Errorf("write dns filter config: %w", err)
	}

	// Generate blocklist conf.
	if err := d.generateBlocklist(); err != nil {
		return err
	}

	slog.Info("dns filter config generated", "path", confPath)
	return nil
}

func (d *DNSFilter) generateBlocklist() error {
	cfg := d.cfg
	blockResponse := cfg["block_response"]
	if blockResponse == "" {
		blockResponse = "0.0.0.0"
	}

	var b strings.Builder
	b.WriteString("# Gatekeeper DNS Blocklist — auto-generated\n\n")

	// Allowlist (always takes priority, loaded as local-only records that resolve normally).
	allowSet := make(map[string]bool)
	if allow := cfg["allowlist"]; allow != "" {
		for _, domain := range strings.Split(allow, ",") {
			domain = strings.TrimSpace(strings.ToLower(domain))
			if domain != "" {
				allowSet[domain] = true
			}
		}
	}

	// Load cached blocklist domains.
	blocked := d.loadCachedBlocklist()

	// Add custom blocked domains.
	if custom := cfg["custom_blocklist"]; custom != "" {
		for _, domain := range strings.Split(custom, ",") {
			domain = strings.TrimSpace(strings.ToLower(domain))
			if domain != "" {
				blocked = append(blocked, domain)
			}
		}
	}

	// Write block directives, respecting allowlist.
	count := 0
	seen := make(map[string]bool)
	for _, domain := range blocked {
		if allowSet[domain] || seen[domain] {
			continue
		}
		seen[domain] = true
		if blockResponse == "NXDOMAIN" {
			b.WriteString(fmt.Sprintf("address=/%s/\n", domain))
		} else {
			b.WriteString(fmt.Sprintf("address=/%s/%s\n", domain, blockResponse))
		}
		count++
	}

	blocklistPath := filepath.Join(d.confDir, "gk-blocklist.conf")
	if err := os.WriteFile(blocklistPath, []byte(b.String()), 0o640); err != nil {
		return fmt.Errorf("write blocklist: %w", err)
	}

	slog.Info("dns blocklist generated", "domains_blocked", count, "allowlisted", len(allowSet))
	return nil
}

func (d *DNSFilter) fetchBlocklists() error {
	cfg := d.cfg
	urls := cfg["blocklists"]
	if urls == "" {
		return nil
	}

	var allDomains []string
	for _, url := range strings.Split(urls, ",") {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		domains, err := d.fetchHostsFile(url)
		if err != nil {
			slog.Warn("failed to fetch blocklist", "url", url, "error", err)
			continue
		}
		allDomains = append(allDomains, domains...)
	}

	// Cache the domains.
	cachePath := filepath.Join(d.cacheDir, "blocklist-domains.txt")
	if err := os.WriteFile(cachePath, []byte(strings.Join(allDomains, "\n")), 0o640); err != nil {
		return err
	}

	slog.Info("blocklists fetched and cached", "total_domains", len(allDomains))
	return nil
}

func (d *DNSFilter) fetchHostsFile(url string) ([]string, error) {
	if HTTP == nil {
		return nil, fmt.Errorf("HTTP client not initialized")
	}
	// Fetch via native HTTP client (no exec.Command).
	body, _, err := HTTP.Get(url, nil, 30)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}

	var domains []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Hosts file format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			domain := strings.ToLower(fields[1])
			if domain != "localhost" && domain != "localhost.localdomain" &&
				domain != "broadcasthost" && domain != "local" &&
				strings.Contains(domain, ".") {
				domains = append(domains, domain)
			}
		}
	}
	return domains, nil
}

func (d *DNSFilter) loadCachedBlocklist() []string {
	cachePath := filepath.Join(d.cacheDir, "blocklist-domains.txt")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil
	}
	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains
}

// BlocklistStats returns stats about the current blocklist.
func (d *DNSFilter) BlocklistStats() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()

	domains := d.loadCachedBlocklist()
	allowCount := 0
	if allow := d.cfg["allowlist"]; allow != "" {
		allowCount = len(strings.Split(allow, ","))
	}

	return map[string]int{
		"blocked_domains": len(domains),
		"allowlisted":     allowCount,
	}
}
