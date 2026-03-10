package service

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DDNS provides Dynamic DNS updates so the gateway's public IP is always
// reachable via a hostname. Supports common DDNS providers via their
// HTTP update APIs.
type DDNS struct {
	mu     sync.Mutex
	state  State
	cfg    map[string]string
	stopCh chan struct{}
	lastIP string
}

func NewDDNS() *DDNS {
	return &DDNS{
		state: StateStopped,
	}
}

func (d *DDNS) Name() string           { return "ddns" }
func (d *DDNS) DisplayName() string    { return "Dynamic DNS" }
func (d *DDNS) Category() string       { return "dns" }
func (d *DDNS) Dependencies() []string { return nil }

func (d *DDNS) Description() string {
	return "Dynamic DNS client that keeps a hostname pointed at your public IP. Supports DuckDNS, Cloudflare, No-IP, Dynu, and custom HTTP update endpoints."
}

func (d *DDNS) DefaultConfig() map[string]string {
	return map[string]string{
		"provider":     "duckdns",
		"hostname":     "",
		"token":        "",
		"username":     "",
		"password":     "",
		"api_key":      "",
		"zone_id":      "",
		"record_id":    "",
		"update_url":   "",
		"interval":     "300",
		"ip_check_url": "https://api.ipify.org",
		"interface":    "",
	}
}

func (d *DDNS) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"provider":     {Description: "DDNS provider (duckdns, cloudflare, noip, dynu, custom)", Default: "duckdns", Required: true, Type: "string"},
		"hostname":     {Description: "Hostname to update", Required: true, Type: "string"},
		"token":        {Description: "API token (DuckDNS, Cloudflare)", Type: "string"},
		"username":     {Description: "Username (No-IP)", Type: "string"},
		"password":     {Description: "Password (No-IP)", Type: "string"},
		"api_key":      {Description: "API key (Cloudflare)", Type: "string"},
		"zone_id":      {Description: "Zone ID (Cloudflare)", Type: "string"},
		"record_id":    {Description: "Record ID (Cloudflare)", Type: "string"},
		"update_url":   {Description: "Custom update URL (use {ip} and {hostname} placeholders)", Type: "string"},
		"interval":     {Description: "Update check interval in seconds", Default: "300", Type: "int"},
		"ip_check_url": {Description: "URL to check current public IP", Default: "https://api.ipify.org", Type: "string"},
		"interface":    {Description: "Use IP from this interface instead of external check", Type: "string"},
	}
}

func (d *DDNS) Validate(cfg map[string]string) error {
	provider := cfg["provider"]
	switch provider {
	case "duckdns":
		if cfg["hostname"] == "" || cfg["token"] == "" {
			return fmt.Errorf("duckdns requires hostname and token")
		}
	case "cloudflare":
		if cfg["token"] == "" || cfg["zone_id"] == "" || cfg["hostname"] == "" {
			return fmt.Errorf("cloudflare requires token, zone_id, and hostname")
		}
	case "noip":
		if cfg["username"] == "" || cfg["password"] == "" || cfg["hostname"] == "" {
			return fmt.Errorf("noip requires username, password, and hostname")
		}
	case "dynu":
		if cfg["hostname"] == "" {
			return fmt.Errorf("dynu requires hostname")
		}
	case "custom":
		if cfg["update_url"] == "" {
			return fmt.Errorf("custom provider requires update_url")
		}
	default:
		return fmt.Errorf("unknown provider: %s (use duckdns, cloudflare, noip, dynu, custom)", provider)
	}
	return nil
}

func (d *DDNS) Start(cfg map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = cfg
	d.stopCh = make(chan struct{})

	// Do an immediate update.
	if err := d.doUpdate(); err != nil {
		slog.Warn("initial DDNS update failed", "error", err)
	}

	// Start periodic update loop.
	go d.updateLoop()

	d.state = StateRunning
	return nil
}

func (d *DDNS) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.stopCh != nil {
		close(d.stopCh)
	}
	d.state = StateStopped
	return nil
}

func (d *DDNS) Reload(cfg map[string]string) error {
	d.mu.Lock()
	d.cfg = cfg
	d.mu.Unlock()
	return d.doUpdate()
}

func (d *DDNS) Status() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

func (d *DDNS) updateLoop() {
	interval := 300 * time.Second
	if secs := d.cfg["interval"]; secs != "" {
		if v, err := time.ParseDuration(secs + "s"); err == nil && v >= 60*time.Second {
			interval = v
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if err := d.doUpdate(); err != nil {
				slog.Warn("DDNS update failed", "error", err)
			}
		}
	}
}

func (d *DDNS) doUpdate() error {
	ip, err := d.getCurrentIP()
	if err != nil {
		return fmt.Errorf("get current IP: %w", err)
	}

	d.mu.Lock()
	lastIP := d.lastIP
	cfg := d.cfg
	d.mu.Unlock()

	if ip == lastIP {
		return nil // No change.
	}

	slog.Info("DDNS IP changed, updating", "old", lastIP, "new", ip, "provider", cfg["provider"])

	var updateErr error
	switch cfg["provider"] {
	case "duckdns":
		updateErr = d.updateDuckDNS(cfg, ip)
	case "cloudflare":
		updateErr = d.updateCloudflare(cfg, ip)
	case "noip":
		updateErr = d.updateNoIP(cfg, ip)
	case "dynu":
		updateErr = d.updateDynu(cfg, ip)
	case "custom":
		updateErr = d.updateCustom(cfg, ip)
	}

	if updateErr != nil {
		return updateErr
	}

	d.mu.Lock()
	d.lastIP = ip
	d.mu.Unlock()

	slog.Info("DDNS update successful", "ip", ip, "hostname", cfg["hostname"])
	return nil
}

func (d *DDNS) getCurrentIP() (string, error) {
	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()

	// If an interface is specified, use its IP.
	if iface := cfg["interface"]; iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return "", err
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
		return "", fmt.Errorf("no IPv4 address on %s", iface)
	}

	// External IP check.
	url := cfg["ip_check_url"]
	if url == "" {
		url = "https://api.ipify.org"
	}
	cmd := exec.Command("curl", "-sS", "--max-time", "10", url)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(output))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP from check: %s", ip)
	}
	return ip, nil
}

func (d *DDNS) updateDuckDNS(cfg map[string]string, ip string) error {
	hostname := strings.TrimSuffix(cfg["hostname"], ".duckdns.org")
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s", hostname, cfg["token"], ip)
	return curlGet(url)
}

func (d *DDNS) updateCloudflare(cfg map[string]string, ip string) error {
	cmd := exec.Command("curl", "-sS", "--max-time", "10",
		"-X", "PUT",
		"-H", "Authorization: Bearer "+cfg["token"],
		"-H", "Content-Type: application/json",
		"--data", fmt.Sprintf(`{"type":"A","name":"%s","content":"%s","ttl":120}`, cfg["hostname"], ip),
		fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", cfg["zone_id"], cfg["record_id"]),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cloudflare update: %s: %w", string(output), err)
	}
	return nil
}

func (d *DDNS) updateNoIP(cfg map[string]string, ip string) error {
	url := fmt.Sprintf("https://%s:%s@dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s",
		cfg["username"], cfg["password"], cfg["hostname"], ip)
	return curlGet(url)
}

func (d *DDNS) updateDynu(cfg map[string]string, ip string) error {
	url := fmt.Sprintf("https://api.dynu.com/nic/update?hostname=%s&myip=%s&password=%s",
		cfg["hostname"], ip, cfg["password"])
	return curlGet(url)
}

func (d *DDNS) updateCustom(cfg map[string]string, ip string) error {
	url := cfg["update_url"]
	url = strings.ReplaceAll(url, "{ip}", ip)
	url = strings.ReplaceAll(url, "{hostname}", cfg["hostname"])
	return curlGet(url)
}

func curlGet(url string) error {
	cmd := exec.Command("curl", "-sS", "--max-time", "10", url)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("curl %s: %s: %w", url, string(output), err)
	}
	return nil
}
