package service

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// CaptivePortal provides a captive portal for guest network access.
// Unauthenticated devices on designated zones are redirected to a
// splash page where they must accept terms, enter a password, or
// authenticate before getting internet access.
//
// Implementation: uses nftables DNAT rules to redirect HTTP traffic
// to a local web server, plus a whitelist of authenticated MACs.
type CaptivePortal struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewCaptivePortal(confDir string) *CaptivePortal {
	return &CaptivePortal{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (c *CaptivePortal) Name() string           { return "captive-portal" }
func (c *CaptivePortal) DisplayName() string    { return "Captive Portal" }
func (c *CaptivePortal) Category() string       { return "network" }
func (c *CaptivePortal) Dependencies() []string { return nil }

func (c *CaptivePortal) Description() string {
	return "Guest network captive portal. Redirects unauthenticated devices to a splash page for terms acceptance or password entry before allowing internet access."
}

func (c *CaptivePortal) DefaultConfig() map[string]string {
	return map[string]string{
		"zone":            "guest",
		"portal_port":     "8888",
		"redirect_url":    "",
		"auth_mode":       "click",
		"password":        "",
		"session_timeout": "3600",
		"idle_timeout":    "900",
		"bandwidth_up":    "0",
		"bandwidth_down":  "0",
		"splash_title":    "Welcome to Guest WiFi",
		"splash_message":  "Please accept the terms of service to continue.",
		"terms_url":       "",
		"allowed_macs":    "",
		"allowed_domains": "captive.apple.com,connectivitycheck.gstatic.com,www.msftconnecttest.com",
	}
}

func (c *CaptivePortal) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"zone":            {Description: "Zone to apply captive portal to", Default: "guest", Required: true, Type: "string"},
		"portal_port":     {Description: "Port for the captive portal web server", Default: "8888", Type: "int"},
		"redirect_url":    {Description: "Custom redirect URL (empty = built-in)", Type: "string"},
		"auth_mode":       {Description: "Authentication mode: click (accept terms), password, or external", Default: "click", Type: "string"},
		"password":        {Description: "Password for password auth mode", Type: "string"},
		"session_timeout": {Description: "Max session duration in seconds", Default: "3600", Type: "int"},
		"idle_timeout":    {Description: "Idle timeout before re-auth required (seconds)", Default: "900", Type: "int"},
		"bandwidth_up":    {Description: "Upload bandwidth limit in kbps (0 = unlimited)", Default: "0", Type: "int"},
		"bandwidth_down":  {Description: "Download bandwidth limit in kbps (0 = unlimited)", Default: "0", Type: "int"},
		"splash_title":    {Description: "Splash page title", Default: "Welcome to Guest WiFi", Type: "string"},
		"splash_message":  {Description: "Splash page message", Default: "Please accept the terms of service to continue.", Type: "string"},
		"terms_url":       {Description: "URL to terms of service page", Type: "string"},
		"allowed_macs":    {Description: "MAC addresses that bypass the portal (comma-separated)", Type: "string"},
		"allowed_domains": {Description: "Domains reachable without auth (captive portal detection)", Default: "captive.apple.com,connectivitycheck.gstatic.com,www.msftconnecttest.com", Type: "string"},
	}
}

func (c *CaptivePortal) Validate(cfg map[string]string) error {
	mode := cfg["auth_mode"]
	if mode != "click" && mode != "password" && mode != "external" {
		return fmt.Errorf("invalid auth_mode: %s (use click, password, or external)", mode)
	}
	if mode == "password" && cfg["password"] == "" {
		return fmt.Errorf("password required for password auth mode")
	}
	if cfg["zone"] == "" {
		return fmt.Errorf("zone is required")
	}
	return nil
}

func (c *CaptivePortal) Start(cfg map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg

	if err := os.MkdirAll(c.confDir, 0o755); err != nil {
		return err
	}

	if err := c.generateNftRules(); err != nil {
		return err
	}

	c.state = StateRunning
	slog.Info("captive portal started", "zone", cfg["zone"], "auth_mode", cfg["auth_mode"])
	return nil
}

func (c *CaptivePortal) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove captive portal nft rules file if it exists.
	rulesPath := filepath.Join(c.confDir, "captive-portal.nft")
	os.Remove(rulesPath)

	// Flush the captive portal chain via netlink.
	nftDeleteChain(nft.TableFamilyINet, "gatekeeper", "captive_portal")

	c.state = StateStopped
	return nil
}

func (c *CaptivePortal) Reload(cfg map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	return c.generateNftRules()
}

func (c *CaptivePortal) Status() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *CaptivePortal) generateNftRules() error {
	cfg := c.cfg
	portalPort := cfg["portal_port"]
	if portalPort == "" {
		portalPort = "8888"
	}
	pp, _ := strconv.ParseUint(portalPort, 10, 16)
	if pp == 0 {
		pp = 8888
	}

	var rules [][]expr.Any

	// Allow already-authenticated MACs.
	if macs := cfg["allowed_macs"]; macs != "" {
		for _, mac := range strings.Split(macs, ",") {
			mac = strings.TrimSpace(mac)
			if mac == "" {
				continue
			}
			hw, err := net.ParseMAC(mac)
			if err != nil {
				slog.Warn("invalid MAC in captive portal allowlist", "mac", mac)
				continue
			}
			rules = append(rules, nftRule(nftMatchEtherSaddr(hw), nftExpr(nftAccept())))
		}
	}

	// Redirect HTTP to portal.
	rules = append(rules, nftRule(nftMatchTCPDport(80), nftRedirectToPort(uint16(pp))))
	// Block HTTPS for unauthenticated.
	rules = append(rules, nftRule(nftMatchTCPDport(443), nftExpr(nftDrop())))

	policy := nft.ChainPolicyAccept
	if err := nftApplyRules(nft.TableFamilyINet, "gatekeeper", []nftChainSpec{{
		Name:     "captive_portal",
		Type:     nft.ChainTypeNAT,
		Hook:     nft.ChainHookPrerouting,
		Priority: nft.ChainPriorityNATDest,
		Policy:   &policy,
		Rules:    rules,
	}}); err != nil {
		slog.Warn("captive portal nft apply failed", "error", err)
	}

	slog.Info("captive portal rules applied")
	return nil
}

// AuthorizeMAC adds a MAC address to the bypass list.
func (c *CaptivePortal) AuthorizeMAC(mac string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	macs := c.cfg["allowed_macs"]
	if macs == "" {
		c.cfg["allowed_macs"] = mac
	} else {
		c.cfg["allowed_macs"] = macs + "," + mac
	}

	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC: %s: %w", mac, err)
	}
	if err := nftAddRule(nft.TableFamilyINet, "gatekeeper", "captive_portal",
		nftRule(nftMatchEtherSaddr(hw), nftExpr(nftAccept()))); err != nil {
		return fmt.Errorf("authorize MAC: %w", err)
	}

	slog.Info("captive portal: MAC authorized", "mac", mac)
	return nil
}
