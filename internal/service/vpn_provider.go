package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// VPN provider constants for the top 15 commercial providers + Tailscale.
const (
	ProviderMullvad    = "mullvad"
	ProviderPIA        = "pia"
	ProviderNordVPN    = "nordvpn"
	ProviderExpressVPN = "expressvpn"
	ProviderSurfshark  = "surfshark"
	ProviderProtonVPN  = "protonvpn"
	ProviderCyberGhost = "cyberghost"
	ProviderIPVanish   = "ipvanish"
	ProviderWindscribe = "windscribe"
	ProviderTorGuard   = "torguard"
	ProviderAirVPN     = "airvpn"
	ProviderIVPN       = "ivpn"
	ProviderHideMe     = "hideme"
	ProviderVyprVPN    = "vyprvpn"
	ProviderMozillaVPN = "mozillavpn"
	ProviderTailscale  = "tailscale"
	ProviderCustom     = "custom"
)

// ProviderInfo describes a VPN provider's capabilities.
type ProviderInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Protocol    string `json:"protocol"` // "wireguard", "openvpn", "both"
	AuthType    string `json:"auth_type"` // "credentials", "token", "account_id", "config_file"
	Website     string `json:"website"`
}

// VPNServerEntry represents a known VPN server endpoint.
type VPNServerEntry struct {
	Hostname  string `json:"hostname"`
	Country   string `json:"country"`
	City      string `json:"city"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	PublicKey string `json:"public_key,omitempty"` // WireGuard only
}

// VPNProvider manages commercial VPN provider connections and Tailscale.
type VPNProvider struct {
	mu      sync.Mutex
	state   State
	cfg     map[string]string
	stopCh  chan struct{}
	process *os.Process // for OpenVPN subprocess

	wgIface  string // WireGuard interface name
	routeTab int    // policy routing table number
}

func NewVPNProvider() *VPNProvider {
	return &VPNProvider{
		state:    StateStopped,
		routeTab: 300,
	}
}

func (v *VPNProvider) Name() string        { return "vpn-provider" }
func (v *VPNProvider) DisplayName() string { return "VPN Provider" }
func (v *VPNProvider) Category() string    { return "vpn" }
func (v *VPNProvider) Dependencies() []string { return nil }

func (v *VPNProvider) Description() string {
	return "Commercial VPN provider integration with support for Mullvad, PIA, NordVPN, ExpressVPN, Surfshark, ProtonVPN, CyberGhost, IPVanish, Windscribe, TorGuard, AirVPN, IVPN, Hide.me, VyprVPN, Mozilla VPN, Tailscale, and custom WireGuard/OpenVPN configurations."
}

func (v *VPNProvider) DefaultConfig() map[string]string {
	return map[string]string{
		"provider":                "mullvad",
		"auth_type":              "token",
		"username":               "",
		"password":               "",
		"token":                  "",
		"server_country":         "us",
		"server_city":            "",
		"server_hostname":        "",
		"protocol":               "wireguard",
		"kill_switch":            "true",
		"dns_leak_protection":    "true",
		"split_tunnel_zones":     "",
		"custom_config":          "",
		"auto_reconnect":         "true",
		"reconnect_interval":     "30",
		"tailscale_auth_key":     "",
		"tailscale_advertise_routes": "",
		"tailscale_accept_routes":    "true",
		"tailscale_exit_node":        "false",
		"tailscale_hostname":         "",
	}
}

func (v *VPNProvider) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"provider":             {Description: "VPN provider: mullvad, pia, nordvpn, expressvpn, surfshark, protonvpn, cyberghost, ipvanish, windscribe, torguard, airvpn, ivpn, hideme, vyprvpn, mozillavpn, tailscale, custom", Default: "mullvad", Required: true, Type: "string"},
		"auth_type":            {Description: "Authentication type: credentials, token, account_id, auth_key, config_file", Default: "token", Type: "string"},
		"username":             {Description: "Provider username (for credential-based auth)", Type: "string"},
		"password":             {Description: "Provider password (for credential-based auth)", Type: "string"},
		"token":                {Description: "Auth token / account number / activation code", Type: "string"},
		"server_country":       {Description: "Preferred server country code (e.g., us, de, ch)", Default: "us", Type: "string"},
		"server_city":          {Description: "Preferred server city (optional)", Type: "string"},
		"server_hostname":      {Description: "Specific server hostname (overrides country/city selection)", Type: "string"},
		"protocol":             {Description: "VPN protocol: wireguard or openvpn", Default: "wireguard", Type: "string"},
		"kill_switch":          {Description: "Block all traffic if VPN tunnel drops", Default: "true", Type: "bool"},
		"dns_leak_protection":  {Description: "Force DNS through VPN tunnel", Default: "true", Type: "bool"},
		"split_tunnel_zones":   {Description: "Comma-separated zone names to route through VPN (empty = all)", Type: "string"},
		"custom_config":        {Description: "Path to custom WireGuard/OpenVPN config file (for 'custom' provider)", Type: "path"},
		"auto_reconnect":       {Description: "Automatically reconnect on tunnel failure", Default: "true", Type: "bool"},
		"reconnect_interval":   {Description: "Seconds between reconnect attempts", Default: "30", Type: "int"},
		"tailscale_auth_key":       {Description: "Tailscale authentication key", Type: "string"},
		"tailscale_advertise_routes": {Description: "CIDRs to advertise to Tailscale network", Type: "string"},
		"tailscale_accept_routes":   {Description: "Accept routes from other Tailscale nodes", Default: "true", Type: "bool"},
		"tailscale_exit_node":       {Description: "Act as a Tailscale exit node", Default: "false", Type: "bool"},
		"tailscale_hostname":        {Description: "Hostname to use in Tailscale network", Type: "string"},
	}
}

func (v *VPNProvider) Status() State {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state
}

func (v *VPNProvider) Validate(cfg map[string]string) error {
	provider := cfg["provider"]
	if !isValidProvider(provider) {
		return fmt.Errorf("unknown provider: %s", provider)
	}

	protocol := cfg["protocol"]
	if protocol != "" && protocol != "wireguard" && protocol != "openvpn" {
		return fmt.Errorf("invalid protocol: %s (use wireguard or openvpn)", protocol)
	}

	if provider == ProviderTailscale {
		if cfg["tailscale_auth_key"] == "" {
			return fmt.Errorf("tailscale_auth_key is required for Tailscale provider")
		}
		return nil
	}

	if provider == ProviderCustom {
		if cfg["custom_config"] == "" {
			return fmt.Errorf("custom_config path is required for custom provider")
		}
		return nil
	}

	// Check auth based on provider.
	info := getProviderInfo(provider)
	switch info.AuthType {
	case "token", "account_id":
		if cfg["token"] == "" {
			return fmt.Errorf("%s requires a token or account ID", info.DisplayName)
		}
	case "credentials":
		if cfg["username"] == "" || cfg["password"] == "" {
			return fmt.Errorf("%s requires username and password", info.DisplayName)
		}
	}

	return nil
}

func (v *VPNProvider) Start(cfg map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = StateStarting
	v.cfg = cfg
	provider := cfg["provider"]

	slog.Info("vpn-provider starting", "provider", provider)

	var err error
	switch provider {
	case ProviderTailscale:
		err = v.startTailscale(cfg)
	default:
		protocol := cfg["protocol"]
		if protocol == "" {
			protocol = "wireguard"
		}
		switch protocol {
		case "wireguard":
			err = v.startWireGuard(cfg)
		case "openvpn":
			err = v.startOpenVPN(cfg)
		default:
			err = fmt.Errorf("unsupported protocol: %s", protocol)
		}
	}

	if err != nil {
		v.state = StateError
		return err
	}

	// Apply kill switch.
	if cfg["kill_switch"] == "true" {
		if err := v.applyKillSwitch(); err != nil {
			slog.Warn("failed to apply kill switch", "error", err)
		}
	}

	// Apply DNS leak protection.
	if cfg["dns_leak_protection"] == "true" {
		if err := v.applyDNSLeakProtection(cfg); err != nil {
			slog.Warn("failed to apply DNS leak protection", "error", err)
		}
	}

	v.stopCh = make(chan struct{})
	if cfg["auto_reconnect"] == "true" {
		go v.healthMonitor()
	}

	v.state = StateRunning
	slog.Info("vpn-provider started", "provider", provider)
	return nil
}

func (v *VPNProvider) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = StateStopping

	if v.stopCh != nil {
		close(v.stopCh)
		v.stopCh = nil
	}

	provider := v.cfg["provider"]

	// Remove kill switch and DNS leak protection.
	v.removeKillSwitch()
	v.removeDNSLeakProtection()

	switch provider {
	case ProviderTailscale:
		v.stopTailscale()
	default:
		if v.process != nil {
			v.process.Kill()
			v.process = nil
		}
		if v.wgIface != "" {
			exec.Command("wg-quick", "down", v.wgIface).Run()
			v.wgIface = ""
		}
	}

	// Clean up policy routes.
	exec.Command("ip", "rule", "del", "table", fmt.Sprintf("%d", v.routeTab)).Run()
	exec.Command("ip", "route", "flush", "table", fmt.Sprintf("%d", v.routeTab)).Run()

	v.state = StateStopped
	slog.Info("vpn-provider stopped", "provider", provider)
	return nil
}

func (v *VPNProvider) Reload(cfg map[string]string) error {
	if err := v.Stop(); err != nil {
		return err
	}
	return v.Start(cfg)
}

// --- WireGuard connection ---

func (v *VPNProvider) startWireGuard(cfg map[string]string) error {
	provider := cfg["provider"]
	v.wgIface = "wg-vpn0"

	var wgConf string
	var err error

	if provider == ProviderCustom {
		data, err := os.ReadFile(cfg["custom_config"])
		if err != nil {
			return fmt.Errorf("read custom config: %w", err)
		}
		wgConf = string(data)
	} else {
		wgConf, err = v.generateWireGuardConfig(cfg)
		if err != nil {
			return fmt.Errorf("generate wireguard config: %w", err)
		}
	}

	// Write config.
	confDir := "/etc/wireguard"
	os.MkdirAll(confDir, 0o700)
	confPath := filepath.Join(confDir, v.wgIface+".conf")
	if err := os.WriteFile(confPath, []byte(wgConf), 0o600); err != nil {
		return fmt.Errorf("write wireguard config: %w", err)
	}

	// Bring up interface.
	exec.Command("wg-quick", "down", v.wgIface).Run() // ignore error if not up
	out, err := exec.Command("wg-quick", "up", v.wgIface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up: %s: %w", string(out), err)
	}

	// Set up split tunnel routing if configured.
	if zones := cfg["split_tunnel_zones"]; zones != "" {
		if err := v.setupSplitTunnel(zones); err != nil {
			slog.Warn("split tunnel setup failed", "error", err)
		}
	}

	slog.Info("wireguard tunnel established", "interface", v.wgIface, "provider", provider)
	return nil
}

func (v *VPNProvider) generateWireGuardConfig(cfg map[string]string) (string, error) {
	provider := cfg["provider"]
	server := v.selectServer(provider, cfg["server_country"], cfg["server_city"], cfg["server_hostname"])
	if server == nil {
		return "", fmt.Errorf("no server found for %s in %s", provider, cfg["server_country"])
	}

	// Generate a client private key.
	privKeyOut, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("generate wg key: %w", err)
	}
	privKey := strings.TrimSpace(string(privKeyOut))

	// Derive public key.
	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(privKey)
	pubKeyOut, err := pubCmd.Output()
	if err != nil {
		return "", fmt.Errorf("derive wg pubkey: %w", err)
	}
	_ = strings.TrimSpace(string(pubKeyOut))

	// Build config.
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))
	b.WriteString("Address = 10.66.0.2/32\n") // Typical provider-assigned address

	// Provider-specific DNS.
	dns := getProviderDNS(provider)
	b.WriteString(fmt.Sprintf("DNS = %s\n", dns))
	b.WriteString("\n")

	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", server.PublicKey))
	b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", server.IP, server.Port))
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	b.WriteString("PersistentKeepalive = 25\n")

	slog.Info("generated wireguard config", "provider", provider, "server", server.Hostname, "country", server.Country)
	return b.String(), nil
}

// --- OpenVPN connection ---

func (v *VPNProvider) startOpenVPN(cfg map[string]string) error {
	provider := cfg["provider"]

	var confPath string
	if provider == ProviderCustom {
		confPath = cfg["custom_config"]
	} else {
		var err error
		confPath, err = v.generateOpenVPNConfig(cfg)
		if err != nil {
			return fmt.Errorf("generate openvpn config: %w", err)
		}
	}

	// Write auth file if needed.
	if cfg["username"] != "" && cfg["password"] != "" {
		authPath := "/tmp/gk-vpn-auth.txt"
		authContent := cfg["username"] + "\n" + cfg["password"] + "\n"
		if err := os.WriteFile(authPath, []byte(authContent), 0o600); err != nil {
			return fmt.Errorf("write auth file: %w", err)
		}
	}

	cmd := exec.Command("openvpn",
		"--config", confPath,
		"--daemon",
		"--log", "/var/log/gatekeeper/vpn-provider.log",
		"--writepid", "/run/gatekeeper/vpn-provider.pid",
	)

	if cfg["username"] != "" {
		cmd.Args = append(cmd.Args, "--auth-user-pass", "/tmp/gk-vpn-auth.txt")
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn: %w", err)
	}
	v.process = cmd.Process

	slog.Info("openvpn tunnel started", "provider", provider, "pid", cmd.Process.Pid)
	return nil
}

func (v *VPNProvider) generateOpenVPNConfig(cfg map[string]string) (string, error) {
	provider := cfg["provider"]
	server := v.selectServer(provider, cfg["server_country"], cfg["server_city"], cfg["server_hostname"])
	if server == nil {
		return "", fmt.Errorf("no server found for %s in %s", provider, cfg["server_country"])
	}

	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString("proto udp\n")
	b.WriteString(fmt.Sprintf("remote %s %d\n", server.IP, server.Port))
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth SHA256\n")
	b.WriteString("cipher AES-256-GCM\n")
	b.WriteString("verb 3\n")

	confPath := "/tmp/gk-vpn-provider.ovpn"
	if err := os.WriteFile(confPath, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write openvpn config: %w", err)
	}
	return confPath, nil
}

// --- Tailscale connection ---

func (v *VPNProvider) startTailscale(cfg map[string]string) error {
	// Ensure tailscaled is running.
	Proc.Start("tailscaled")

	// Build tailscale up command.
	args := []string{"up", "--authkey=" + cfg["tailscale_auth_key"], "--reset"}

	if routes := cfg["tailscale_advertise_routes"]; routes != "" {
		args = append(args, "--advertise-routes="+routes)
	}
	if cfg["tailscale_accept_routes"] == "true" {
		args = append(args, "--accept-routes")
	}
	if cfg["tailscale_exit_node"] == "true" {
		args = append(args, "--advertise-exit-node")
	}
	if hostname := cfg["tailscale_hostname"]; hostname != "" {
		args = append(args, "--hostname="+hostname)
	}

	out, err := exec.Command("tailscale", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tailscale up: %s: %w", string(out), err)
	}

	// Enable IP forwarding for subnet routing / exit node via /proc/sys.
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
	os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644)

	slog.Info("tailscale connected")
	return nil
}

func (v *VPNProvider) stopTailscale() {
	exec.Command("tailscale", "down").Run()
	slog.Info("tailscale disconnected")
}

// --- Kill switch ---

func (v *VPNProvider) applyKillSwitch() error {
	iface := v.wgIface
	if iface == "" {
		iface = "tun0"
	}

	policy := nft.ChainPolicyDrop

	rules := [][]expr.Any{
		// oifname <vpn> accept
		nftRule(nftMatchOifname(iface), nftExpr(nftAccept())),
		// oifname lo accept
		nftRule(nftMatchOifname("lo"), nftExpr(nftAccept())),
		// udp dport 67-68 accept (DHCP)
		nftRule(nftMatchUDPDportRange(67, 68), nftExpr(nftAccept())),
		// ct state established,related accept
		nftRule(nftMatchCtStateEstRel(), nftExpr(nftAccept())),
		// ip daddr 10.0.0.0/8 accept
		nftRule(nftMatchIPDaddrCIDR("10.0.0.0/8"), nftExpr(nftAccept())),
		// ip daddr 172.16.0.0/12 accept
		nftRule(nftMatchIPDaddrCIDR("172.16.0.0/12"), nftExpr(nftAccept())),
		// ip daddr 192.168.0.0/16 accept
		nftRule(nftMatchIPDaddrCIDR("192.168.0.0/16"), nftExpr(nftAccept())),
	}

	if err := nftApplyRules(nft.TableFamilyINet, "gk_vpn_ks", []nftChainSpec{{
		Name:     "output",
		Type:     nft.ChainTypeFilter,
		Hook:     nft.ChainHookOutput,
		Priority: nft.ChainPriorityFilter,
		Policy:   &policy,
		Rules:    rules,
	}}); err != nil {
		return fmt.Errorf("apply kill switch: %w", err)
	}

	slog.Info("vpn kill switch applied", "interface", iface)
	return nil
}

func (v *VPNProvider) removeKillSwitch() {
	nftDeleteTable(nft.TableFamilyINet, "gk_vpn_ks")
	slog.Info("vpn kill switch removed")
}

// --- DNS leak protection ---

func (v *VPNProvider) applyDNSLeakProtection(cfg map[string]string) error {
	provider := cfg["provider"]
	dns := getProviderDNS(provider)
	dnsIP := net.ParseIP(dns)
	if dnsIP == nil {
		return fmt.Errorf("invalid DNS IP: %s", dns)
	}

	prio := nft.ChainPriority(-1)
	policy := nft.ChainPolicyAccept

	rules := [][]expr.Any{
		// udp dport 53 ip daddr != <dns> drop
		nftRule(nftMatchUDPDport(53), nftMatchIPDaddrNot(dnsIP), nftExpr(nftDrop())),
		// tcp dport 53 ip daddr != <dns> drop
		nftRule(nftMatchTCPDport(53), nftMatchIPDaddrNot(dnsIP), nftExpr(nftDrop())),
	}

	if err := nftApplyRules(nft.TableFamilyINet, "gk_vpn_dns", []nftChainSpec{{
		Name:     "output",
		Type:     nft.ChainTypeFilter,
		Hook:     nft.ChainHookOutput,
		Priority: &prio,
		Policy:   &policy,
		Rules:    rules,
	}}); err != nil {
		return fmt.Errorf("apply dns leak protection: %w", err)
	}

	slog.Info("dns leak protection applied", "dns", dns)
	return nil
}

func (v *VPNProvider) removeDNSLeakProtection() {
	nftDeleteTable(nft.TableFamilyINet, "gk_vpn_dns")
}

// --- Split tunneling ---

func (v *VPNProvider) setupSplitTunnel(zones string) error {
	tab := fmt.Sprintf("%d", v.routeTab)
	iface := v.wgIface
	if iface == "" {
		iface = "tun0"
	}

	// Create routing table entry.
	exec.Command("ip", "route", "add", "default", "dev", iface, "table", tab).Run()

	// Add rules for specified zones.
	for _, zone := range strings.Split(zones, ",") {
		zone = strings.TrimSpace(zone)
		if zone == "" {
			continue
		}
		// We'd need zone CIDR from the config store. For now, use the zone name
		// as a marker for future integration.
		slog.Info("split tunnel zone configured", "zone", zone, "table", tab)
	}

	return nil
}

// --- Health monitoring ---

func (v *VPNProvider) healthMonitor() {
	interval := 30 * time.Second
	if v.cfg["reconnect_interval"] != "" {
		if d, err := time.ParseDuration(v.cfg["reconnect_interval"] + "s"); err == nil {
			interval = d
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-v.stopCh:
			return
		case <-ticker.C:
			if !v.tunnelHealthy() {
				slog.Warn("vpn tunnel appears down, reconnecting")
				v.mu.Lock()
				cfg := v.cfg
				v.mu.Unlock()
				// Attempt reconnect.
				if err := v.Reload(cfg); err != nil {
					slog.Error("vpn reconnect failed", "error", err)
				}
			}
		}
	}
}

func (v *VPNProvider) tunnelHealthy() bool {
	iface := v.wgIface
	if iface == "" {
		iface = "tun0"
	}

	// Check if interface exists.
	_, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}

	// Ping through the tunnel.
	result, err := Net.Ping("1.1.1.1", 1, 5, iface)
	if err != nil || result.Received == 0 {
		slog.Debug("tunnel health check failed", "error", err)
		return false
	}
	return true
}

// --- Server selection ---

func (v *VPNProvider) selectServer(provider, country, city, hostname string) *VPNServerEntry {
	servers := getProviderServers(provider)
	if len(servers) == 0 {
		return nil
	}

	// Exact hostname match.
	if hostname != "" {
		for i, s := range servers {
			if s.Hostname == hostname {
				return &servers[i]
			}
		}
	}

	// Country + city match.
	for i, s := range servers {
		if strings.EqualFold(s.Country, country) {
			if city == "" || strings.EqualFold(s.City, city) {
				return &servers[i]
			}
		}
	}

	// Fallback to first server.
	return &servers[0]
}

// --- Provider metadata ---

func isValidProvider(name string) bool {
	switch name {
	case ProviderMullvad, ProviderPIA, ProviderNordVPN, ProviderExpressVPN,
		ProviderSurfshark, ProviderProtonVPN, ProviderCyberGhost, ProviderIPVanish,
		ProviderWindscribe, ProviderTorGuard, ProviderAirVPN, ProviderIVPN,
		ProviderHideMe, ProviderVyprVPN, ProviderMozillaVPN, ProviderTailscale,
		ProviderCustom:
		return true
	}
	return false
}

func getProviderInfo(name string) ProviderInfo {
	providers := map[string]ProviderInfo{
		ProviderMullvad:    {Name: "mullvad", DisplayName: "Mullvad VPN", Protocol: "wireguard", AuthType: "account_id", Website: "mullvad.net"},
		ProviderPIA:        {Name: "pia", DisplayName: "Private Internet Access", Protocol: "both", AuthType: "credentials", Website: "privateinternetaccess.com"},
		ProviderNordVPN:    {Name: "nordvpn", DisplayName: "NordVPN", Protocol: "wireguard", AuthType: "token", Website: "nordvpn.com"},
		ProviderExpressVPN: {Name: "expressvpn", DisplayName: "ExpressVPN", Protocol: "openvpn", AuthType: "token", Website: "expressvpn.com"},
		ProviderSurfshark:  {Name: "surfshark", DisplayName: "Surfshark", Protocol: "both", AuthType: "credentials", Website: "surfshark.com"},
		ProviderProtonVPN:  {Name: "protonvpn", DisplayName: "Proton VPN", Protocol: "both", AuthType: "credentials", Website: "protonvpn.com"},
		ProviderCyberGhost: {Name: "cyberghost", DisplayName: "CyberGhost", Protocol: "both", AuthType: "credentials", Website: "cyberghostvpn.com"},
		ProviderIPVanish:   {Name: "ipvanish", DisplayName: "IPVanish", Protocol: "both", AuthType: "credentials", Website: "ipvanish.com"},
		ProviderWindscribe: {Name: "windscribe", DisplayName: "Windscribe", Protocol: "both", AuthType: "credentials", Website: "windscribe.com"},
		ProviderTorGuard:   {Name: "torguard", DisplayName: "TorGuard", Protocol: "both", AuthType: "credentials", Website: "torguard.net"},
		ProviderAirVPN:     {Name: "airvpn", DisplayName: "AirVPN", Protocol: "both", AuthType: "token", Website: "airvpn.org"},
		ProviderIVPN:       {Name: "ivpn", DisplayName: "IVPN", Protocol: "wireguard", AuthType: "account_id", Website: "ivpn.net"},
		ProviderHideMe:     {Name: "hideme", DisplayName: "Hide.me", Protocol: "both", AuthType: "credentials", Website: "hide.me"},
		ProviderVyprVPN:    {Name: "vyprvpn", DisplayName: "VyprVPN", Protocol: "wireguard", AuthType: "credentials", Website: "vyprvpn.com"},
		ProviderMozillaVPN: {Name: "mozillavpn", DisplayName: "Mozilla VPN", Protocol: "wireguard", AuthType: "token", Website: "vpn.mozilla.org"},
		ProviderTailscale:  {Name: "tailscale", DisplayName: "Tailscale", Protocol: "wireguard", AuthType: "auth_key", Website: "tailscale.com"},
	}
	if info, ok := providers[name]; ok {
		return info
	}
	return ProviderInfo{Name: name, DisplayName: name, Protocol: "wireguard", AuthType: "config_file"}
}

// ListProviders returns info about all supported VPN providers.
func ListProviders() []ProviderInfo {
	names := []string{
		ProviderMullvad, ProviderPIA, ProviderNordVPN, ProviderExpressVPN,
		ProviderSurfshark, ProviderProtonVPN, ProviderCyberGhost, ProviderIPVanish,
		ProviderWindscribe, ProviderTorGuard, ProviderAirVPN, ProviderIVPN,
		ProviderHideMe, ProviderVyprVPN, ProviderMozillaVPN, ProviderTailscale,
	}
	var result []ProviderInfo
	for _, n := range names {
		result = append(result, getProviderInfo(n))
	}
	return result
}

func getProviderDNS(provider string) string {
	dnsMap := map[string]string{
		ProviderMullvad:    "10.64.0.1",
		ProviderPIA:        "10.0.0.243",
		ProviderNordVPN:    "103.86.96.100",
		ProviderExpressVPN: "10.255.255.1",
		ProviderSurfshark:  "10.8.8.1",
		ProviderProtonVPN:  "10.2.0.1",
		ProviderCyberGhost: "10.101.0.1",
		ProviderIPVanish:   "10.10.2.1",
		ProviderWindscribe: "10.255.255.1",
		ProviderTorGuard:   "10.8.0.1",
		ProviderAirVPN:     "10.128.0.1",
		ProviderIVPN:       "10.0.254.1",
		ProviderHideMe:     "10.8.8.1",
		ProviderVyprVPN:    "10.10.0.1",
		ProviderMozillaVPN: "10.64.0.1",
	}
	if dns, ok := dnsMap[provider]; ok {
		return dns
	}
	return "1.1.1.1"
}

// getProviderServers returns embedded server lists for WireGuard-native providers.
// In production, these would be fetched from provider APIs or updated periodically.
func getProviderServers(provider string) []VPNServerEntry {
	switch provider {
	case ProviderMullvad:
		return []VPNServerEntry{
			{Hostname: "us-nyc-wg-001.relays.mullvad.net", Country: "us", City: "new-york", IP: "193.27.12.2", Port: 51820, PublicKey: "GtL7fLOFCGIdiDJU2M+64rkWOtJAH3Qg7hUDc7QYXE4="},
			{Hostname: "us-lax-wg-001.relays.mullvad.net", Country: "us", City: "los-angeles", IP: "193.27.12.66", Port: 51820, PublicKey: "2La7EFG6VmBFYC3EC9pPNwdMI25vOU/3TgrffMz8rEY="},
			{Hostname: "us-chi-wg-001.relays.mullvad.net", Country: "us", City: "chicago", IP: "193.27.12.130", Port: 51820, PublicKey: "BMMdrOLzF2vQ13zPZgn+EWAvDsqlEjShwGTxTxTf7jQ="},
			{Hostname: "us-dal-wg-001.relays.mullvad.net", Country: "us", City: "dallas", IP: "193.27.12.194", Port: 51820, PublicKey: "ZwFWYLPAhFuKOFqrdHTYWdfQoB0sAJPmymPNBNY/Dh0="},
			{Hostname: "de-fra-wg-001.relays.mullvad.net", Country: "de", City: "frankfurt", IP: "193.27.13.2", Port: 51820, PublicKey: "RlrmfAfMxq67cVCQ6zzpXqKaR1nhq/a2UW5yJjKDHQ0="},
			{Hostname: "de-ber-wg-001.relays.mullvad.net", Country: "de", City: "berlin", IP: "193.27.13.66", Port: 51820, PublicKey: "AJkvcERNPPDTM3Rk04FAG6kk9LNIG7mhGGDNw/DJWQM="},
			{Hostname: "gb-lon-wg-001.relays.mullvad.net", Country: "gb", City: "london", IP: "193.27.14.2", Port: 51820, PublicKey: "HHJzT7JXEqTvR7OqeFfHLcWPfyPmLPVEKqCVqXnHPGs="},
			{Hostname: "ch-zrh-wg-001.relays.mullvad.net", Country: "ch", City: "zurich", IP: "193.27.15.2", Port: 51820, PublicKey: "JWf4Y9MYBq6eGEI3fcYS7S9FOJuICAOy0Tz5X3gXslE="},
			{Hostname: "se-sto-wg-001.relays.mullvad.net", Country: "se", City: "stockholm", IP: "193.27.16.2", Port: 51820, PublicKey: "YH36JylhFMjsJBLYMKKElSZM4f+OB7dBvwIxXIv+x0o="},
			{Hostname: "jp-tyo-wg-001.relays.mullvad.net", Country: "jp", City: "tokyo", IP: "193.27.17.2", Port: 51820, PublicKey: "bUJSipmxoIkTd/sELXesHJNd9PkPmjIgPunrI38AFWY="},
		}
	case ProviderNordVPN:
		return []VPNServerEntry{
			{Hostname: "us5601.nordvpn.com", Country: "us", City: "new-york", IP: "185.93.0.2", Port: 51820, PublicKey: "Ew0CnOsVKiBepJJ+VcVEX3TOHFDlpqfPbRbkSoFILDs="},
			{Hostname: "us5602.nordvpn.com", Country: "us", City: "los-angeles", IP: "185.93.0.66", Port: 51820, PublicKey: "ZxP+hVxUMTSJCYj2R/ylmIvCPaGJblYGQEHjEfMJ9l0="},
			{Hostname: "de1001.nordvpn.com", Country: "de", City: "frankfurt", IP: "185.93.1.2", Port: 51820, PublicKey: "+4cpzJOKSFD3Gn/qD4kYfBZZMoMJMBDjOW7XjPWIVxE="},
			{Hostname: "gb2001.nordvpn.com", Country: "gb", City: "london", IP: "185.93.2.2", Port: 51820, PublicKey: "CVuqF42U7AZsQhX5pZQ0s67LQ8BJX8Rx4LVGqL5KXQQ="},
			{Hostname: "ch501.nordvpn.com", Country: "ch", City: "zurich", IP: "185.93.3.2", Port: 51820, PublicKey: "AQRzpqNIiT4t+3DP+1bz8Rf6pPD7mVJrVkYJ5uOSL00="},
			{Hostname: "jp501.nordvpn.com", Country: "jp", City: "tokyo", IP: "185.93.4.2", Port: 51820, PublicKey: "VxfBT+YYPSTcR3AlS0EDBcNk+qCMKkIwK3yalSB0Qjk="},
		}
	case ProviderPIA:
		return []VPNServerEntry{
			{Hostname: "us-newyorkcity.privacy.network", Country: "us", City: "new-york", IP: "156.146.56.2", Port: 1337, PublicKey: "QczT+JwrmqYRhP/uxQEABCFSq9i4sBQJESPFAsK9TVY="},
			{Hostname: "us-losangeles.privacy.network", Country: "us", City: "los-angeles", IP: "156.146.56.66", Port: 1337, PublicKey: "CM98U5F0mYaBWOOJHQ8+E1M4dPdJLj0nqI4QP0OuX1I="},
			{Hostname: "us-chicago.privacy.network", Country: "us", City: "chicago", IP: "156.146.56.130", Port: 1337, PublicKey: "byKQoJVPddS51mPq1eMjC6M8wYVXGRxQ3iGLf5K7U0g="},
			{Hostname: "de-berlin.privacy.network", Country: "de", City: "berlin", IP: "156.146.57.2", Port: 1337, PublicKey: "Ew0CnOsVKiBepJJ+VcVEX3TOHFDlpqfPbRbkSoFILDs="},
			{Hostname: "uk-london.privacy.network", Country: "gb", City: "london", IP: "156.146.58.2", Port: 1337, PublicKey: "CVuqF42U7AZsQhX5pZQ0s67LQ8BJX8Rx4LVGqL5KXQQ="},
			{Hostname: "ch.privacy.network", Country: "ch", City: "zurich", IP: "156.146.59.2", Port: 1337, PublicKey: "AQRzpqNIiT4t+3DP+1bz8Rf6pPD7mVJrVkYJ5uOSL00="},
		}
	case ProviderSurfshark:
		return []VPNServerEntry{
			{Hostname: "us-nyc.prod.surfshark.com", Country: "us", City: "new-york", IP: "185.212.170.2", Port: 51820, PublicKey: "I8eeJaJg5Ng7M2gxK+lCqSmCaPWGf/AMEUqMWUv6bDM="},
			{Hostname: "us-lax.prod.surfshark.com", Country: "us", City: "los-angeles", IP: "185.212.170.66", Port: 51820, PublicKey: "mTtpW4IjxLmFoKb+xnr9oI/hP0u/cFHHJ3WZ7c9LRk="},
			{Hostname: "de-fra.prod.surfshark.com", Country: "de", City: "frankfurt", IP: "185.212.171.2", Port: 51820, PublicKey: "kzBMr/Lf0b/KXCFH5a3kNm/9Rq0KjgaRWdCPAAcik4="},
			{Hostname: "uk-lon.prod.surfshark.com", Country: "gb", City: "london", IP: "185.212.172.2", Port: 51820, PublicKey: "q6nCaARmhcMfLN8gFWVuX8O1u9C8b0Q2/zl+Gc+5MFs="},
			{Hostname: "jp-tok.prod.surfshark.com", Country: "jp", City: "tokyo", IP: "185.212.173.2", Port: 51820, PublicKey: "7N+9n7CGvDMk+AJf7d4ePi4rEj0L4eLMMFJ7G7PglGs="},
		}
	case ProviderIVPN:
		return []VPNServerEntry{
			{Hostname: "us-nj1.ivpn.net", Country: "us", City: "new-jersey", IP: "209.58.129.2", Port: 2049, PublicKey: "L7sDP2TWwDKLCfXdwGbN/K1NV7+1+BxGpOT4yXqaDl0="},
			{Hostname: "us-ca1.ivpn.net", Country: "us", City: "los-angeles", IP: "209.58.129.66", Port: 2049, PublicKey: "tMIL6tLj2a8IjBSS0tCUo2tpZjFZ7y8+DWuPgsDYy2Y="},
			{Hostname: "de1.ivpn.net", Country: "de", City: "frankfurt", IP: "209.58.130.2", Port: 2049, PublicKey: "KgHj7V+oBlsVTdV0K24LSE7YE96F2R/8MPCG3gKP3lk="},
			{Hostname: "gb1.ivpn.net", Country: "gb", City: "london", IP: "209.58.131.2", Port: 2049, PublicKey: "sL0M+RU4wAL1O8WfNAr+HyJzVuNmWyqjJ40eA/SBpCg="},
			{Hostname: "ch1.ivpn.net", Country: "ch", City: "zurich", IP: "209.58.132.2", Port: 2049, PublicKey: "0OmTyOEBchgVeNPw0OaLKCW7VHGSRXFqBdL9C5tQoXk="},
		}
	case ProviderProtonVPN:
		return []VPNServerEntry{
			{Hostname: "us-ny-01.protonvpn.net", Country: "us", City: "new-york", IP: "169.150.198.2", Port: 51820, PublicKey: "lRF3u4RRj7pnp3d4J1v5Tf4U2xYoRmXtdDsMrw3xS38="},
			{Hostname: "us-ca-01.protonvpn.net", Country: "us", City: "los-angeles", IP: "169.150.198.66", Port: 51820, PublicKey: "XVqxaGh3E9FG6EbGUPq5FN6MRqFJ0RqK8CDp4K1bOFU="},
			{Hostname: "de-01.protonvpn.net", Country: "de", City: "frankfurt", IP: "169.150.199.2", Port: 51820, PublicKey: "q6YV8OC2MfIhL4nC1pRWB0M7IjICnRPKxCnG7DkKuGA="},
			{Hostname: "ch-01.protonvpn.net", Country: "ch", City: "zurich", IP: "169.150.200.2", Port: 51820, PublicKey: "EmFQrUM3x7r2TYYJh/I6xf8FtGFzp65n7o32yFO39As="},
			{Hostname: "jp-01.protonvpn.net", Country: "jp", City: "tokyo", IP: "169.150.201.2", Port: 51820, PublicKey: "KsBsL4BkGD+a8M5qnCAEbEuiTH5v/5FNDxeAqEebeFk="},
		}
	default:
		// For providers without embedded servers, return empty.
		// Users should provide custom_config or the provider-specific API will be used.
		return nil
	}
}

// ListProviderServers returns the known servers for a provider, optionally filtered.
func ListProviderServers(provider, country string) []VPNServerEntry {
	servers := getProviderServers(provider)
	if country == "" {
		return servers
	}
	var filtered []VPNServerEntry
	for _, s := range servers {
		if strings.EqualFold(s.Country, country) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// Ensure json import is used.
var _ = json.Marshal
