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

// IDS provides Intrusion Detection and Prevention via Suricata.
// Suricata inspects network traffic against rule sets (ET Open, Snort rules)
// to detect attacks, malware, and suspicious activity.
//
// Modes:
//   - IDS (detect only): logs alerts but does not block traffic
//   - IPS (inline): actively drops malicious packets via nftables integration
//
// This is a Tier 1 feature across pfSense/OPNsense communities and one of
// the primary reasons users choose those platforms over consumer routers.
type IDS struct {
	mu      sync.Mutex
	state   State
	confDir string
	logDir  string
	cfg     map[string]string
}

func NewIDS(confDir, logDir string) *IDS {
	return &IDS{
		confDir: confDir,
		logDir:  logDir,
		state:   StateStopped,
	}
}

func (i *IDS) Name() string           { return "ids" }
func (i *IDS) DisplayName() string    { return "IDS/IPS (Suricata)" }
func (i *IDS) Category() string       { return "security" }
func (i *IDS) Dependencies() []string { return nil }

func (i *IDS) Description() string {
	return "Intrusion Detection and Prevention System using Suricata. Inspects network traffic for attacks, malware, and exploits using ET Open and custom rule sets."
}

func (i *IDS) DefaultConfig() map[string]string {
	return map[string]string{
		"mode":                "ids",
		"interfaces":          "",
		"home_net":            "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		"rule_sources":        "et/open",
		"custom_rules":        "",
		"alert_log":           "true",
		"eve_json":            "true",
		"stream_depth":        "1mb",
		"max_pending_packets": "1024",
		"default_rule_path":   "/var/lib/suricata/rules",
		"update_interval":     "86400",
		"enabled_categories":  "emerging-malware,emerging-trojan,emerging-exploit,emerging-dos,emerging-scan,emerging-policy",
		"disabled_categories": "",
	}
}

func (i *IDS) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mode":                {Description: "Operating mode: ids (detect only) or ips (inline blocking)", Default: "ids", Required: true, Type: "string"},
		"interfaces":          {Description: "Interfaces to monitor (comma-separated, empty = all non-WAN)", Required: true, Type: "string"},
		"home_net":            {Description: "Home network CIDRs (comma-separated)", Default: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", Type: "string"},
		"rule_sources":        {Description: "Rule sources: et/open (Emerging Threats Open), custom", Default: "et/open", Type: "string"},
		"custom_rules":        {Description: "Path to custom rules directory", Type: "path"},
		"alert_log":           {Description: "Write alert log (fast.log)", Default: "true", Type: "bool"},
		"eve_json":            {Description: "Write EVE JSON log (for SIEM integration)", Default: "true", Type: "bool"},
		"stream_depth":        {Description: "Stream reassembly depth", Default: "1mb", Type: "string"},
		"max_pending_packets": {Description: "Max pending packets buffer", Default: "1024", Type: "int"},
		"default_rule_path":   {Description: "Path to Suricata rules", Default: "/var/lib/suricata/rules", Type: "path"},
		"update_interval":     {Description: "Rule update interval in seconds (0 = manual)", Default: "86400", Type: "int"},
		"enabled_categories":  {Description: "Enabled rule categories (comma-separated)", Default: "emerging-malware,emerging-trojan,emerging-exploit,emerging-dos,emerging-scan,emerging-policy", Type: "string"},
		"disabled_categories": {Description: "Disabled rule categories (comma-separated)", Type: "string"},
	}
}

func (i *IDS) Validate(cfg map[string]string) error {
	mode := cfg["mode"]
	if mode != "ids" && mode != "ips" {
		return fmt.Errorf("invalid mode: %s (use ids or ips)", mode)
	}
	if cfg["interfaces"] == "" {
		return fmt.Errorf("interfaces is required")
	}
	return nil
}

func (i *IDS) Start(cfg map[string]string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cfg = cfg

	for _, dir := range []string{i.confDir, i.logDir, cfg["default_rule_path"]} {
		if dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
	}

	// Update rules if using ET Open.
	if strings.Contains(cfg["rule_sources"], "et/open") {
		if err := i.updateRules(); err != nil {
			slog.Warn("rule update failed, using cached rules", "error", err)
		}
	}

	if err := i.generateConfig(); err != nil {
		return err
	}

	// Start Suricata.
	args := []string{"--init-errors-fatal"}

	mode := cfg["mode"]
	if mode == "ips" {
		// IPS mode: use nftables queue for inline inspection.
		args = append(args, "-q", "0")
	} else {
		// IDS mode: use AF_PACKET for passive monitoring.
		for _, iface := range strings.Split(cfg["interfaces"], ",") {
			iface = strings.TrimSpace(iface)
			if iface != "" {
				args = append(args, "--af-packet="+iface)
			}
		}
	}

	args = append(args, "-c", filepath.Join(i.confDir, "suricata.yaml"))
	args = append(args, "--pidfile", filepath.Join(i.logDir, "suricata.pid"))
	args = append(args, "-D") // Daemonize.

	cmd := exec.Command("suricata", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start suricata: %s: %w", string(output), err)
	}

	// If IPS mode, set up nftables queue rule.
	if mode == "ips" {
		i.setupNFQueue(cfg)
	}

	i.state = StateRunning
	slog.Info("suricata started", "mode", mode, "interfaces", cfg["interfaces"])
	return nil
}

func (i *IDS) Stop() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Kill suricata.
	pidFile := filepath.Join(i.logDir, "suricata.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pid := strings.TrimSpace(string(data))
		exec.Command("kill", pid).Run()
	}

	// Remove IPS nftables queue if active.
	if i.cfg != nil && i.cfg["mode"] == "ips" {
		exec.Command("nft", "delete", "chain", "inet", "gatekeeper", "ids_queue").Run()
	}

	i.state = StateStopped
	return nil
}

func (i *IDS) Reload(cfg map[string]string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cfg = cfg

	if err := i.generateConfig(); err != nil {
		return err
	}

	// Send SIGUSR2 to Suricata for live rule reload.
	pidFile := filepath.Join(i.logDir, "suricata.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pid := strings.TrimSpace(string(data))
		exec.Command("kill", "-USR2", pid).Run()
		slog.Info("suricata rules reloaded")
	}

	return nil
}

func (i *IDS) Status() State {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.state
}

func (i *IDS) generateConfig() error {
	cfg := i.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper Suricata config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	b.WriteString("%YAML 1.1\n---\n\n")

	// Variables.
	homeNet := cfg["home_net"]
	if homeNet == "" {
		homeNet = "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
	} else {
		homeNet = "[" + homeNet + "]"
	}
	b.WriteString("vars:\n")
	b.WriteString(fmt.Sprintf("  address-groups:\n    HOME_NET: \"%s\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n", homeNet))
	b.WriteString("    HTTP_SERVERS: \"$HOME_NET\"\n")
	b.WriteString("    DNS_SERVERS: \"$HOME_NET\"\n")
	b.WriteString("  port-groups:\n    HTTP_PORTS: \"80\"\n    SHELLCODE_PORTS: \"!80\"\n")

	// Default log directory.
	b.WriteString(fmt.Sprintf("\ndefault-log-dir: %s\n", i.logDir))

	// Outputs.
	b.WriteString("\noutputs:\n")
	if cfg["alert_log"] == "true" {
		b.WriteString("  - fast:\n      enabled: yes\n      filename: fast.log\n      append: yes\n")
	}
	if cfg["eve_json"] == "true" {
		b.WriteString("  - eve-log:\n      enabled: yes\n      filename: eve.json\n      types:\n")
		b.WriteString("        - alert\n        - dns\n        - tls\n        - http\n        - flow\n        - stats:\n            enabled: yes\n            interval: 30\n")
	}

	// Detection engine.
	b.WriteString("\ndetect-engine:\n  - profile: medium\n  - sgh-mpm-context: auto\n")

	// Stream engine.
	b.WriteString(fmt.Sprintf("\nstream:\n  reassembly:\n    depth: %s\n", cfg["stream_depth"]))
	b.WriteString(fmt.Sprintf("\nmax-pending-packets: %s\n", cfg["max_pending_packets"]))

	// Threading.
	b.WriteString("\nthreading:\n  set-cpu-affinity: no\n  detect-thread-ratio: 1.0\n")

	// Rules.
	rulePath := cfg["default_rule_path"]
	b.WriteString(fmt.Sprintf("\ndefault-rule-path: %s\n", rulePath))
	b.WriteString("rule-files:\n  - suricata.rules\n")
	if custom := cfg["custom_rules"]; custom != "" {
		b.WriteString(fmt.Sprintf("  - %s/*.rules\n", custom))
	}

	// IPS mode config.
	if cfg["mode"] == "ips" {
		b.WriteString("\nnfq:\n  mode: accept\n  repeat-mark: 1\n  repeat-mask: 1\n  route-queue: 2\n  fail-open: yes\n")
	}

	// AF-PACKET config for IDS mode.
	if cfg["mode"] == "ids" {
		b.WriteString("\naf-packet:\n")
		for _, iface := range strings.Split(cfg["interfaces"], ",") {
			iface = strings.TrimSpace(iface)
			if iface != "" {
				b.WriteString(fmt.Sprintf("  - interface: %s\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n", iface))
			}
		}
	}

	confPath := filepath.Join(i.confDir, "suricata.yaml")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write suricata config: %w", err)
	}

	slog.Info("suricata config generated", "path", confPath)
	return nil
}

func (i *IDS) updateRules() error {
	slog.Info("updating suricata rules")
	cmd := exec.Command("suricata-update", "--no-test", "--no-reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("suricata-update: %s: %w", string(output), err)
	}
	slog.Info("suricata rules updated")
	return nil
}

func (i *IDS) setupNFQueue(cfg map[string]string) {
	// Create nftables chain that sends traffic to Suricata's NFQUEUE.
	var rules strings.Builder
	rules.WriteString("table inet gatekeeper {\n")
	rules.WriteString("  chain ids_queue {\n")
	rules.WriteString("    type filter hook forward priority -150; policy accept;\n")

	for _, iface := range strings.Split(cfg["interfaces"], ",") {
		iface = strings.TrimSpace(iface)
		if iface != "" {
			rules.WriteString(fmt.Sprintf("    iifname \"%s\" queue num 0 bypass\n", iface))
			rules.WriteString(fmt.Sprintf("    oifname \"%s\" queue num 0 bypass\n", iface))
		}
	}

	rules.WriteString("  }\n}\n")

	rulesPath := filepath.Join(i.confDir, "ids-nfqueue.nft")
	if err := os.WriteFile(rulesPath, []byte(rules.String()), 0o640); err != nil {
		slog.Warn("failed to write IPS nftables rules", "error", err)
		return
	}

	cmd := exec.Command("nft", "-f", rulesPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to apply IPS nftables rules", "error", err, "output", string(output))
	}
}
