package service

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Bridge provides network bridge management for combining physical/virtual
// interfaces into a single L2 domain. Common uses:
//   - Transparent bridging (two NICs as one LAN segment)
//   - VM bridge (give VMs direct LAN access)
//   - VLAN trunk bridging (multiple VLANs on one bridge)
//   - WiFi-to-Ethernet bridging
type Bridge struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewBridge(confDir string) *Bridge {
	return &Bridge{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (b *Bridge) Name() string           { return "bridge" }
func (b *Bridge) DisplayName() string    { return "Network Bridging" }
func (b *Bridge) Category() string       { return "network" }
func (b *Bridge) Dependencies() []string { return nil }

func (b *Bridge) Description() string {
	return "Network bridge management for combining interfaces into a single L2 domain. Supports transparent bridging, VLAN trunking, VM bridges, and STP."
}

func (b *Bridge) DefaultConfig() map[string]string {
	return map[string]string{
		"bridges":        "br0",
		"br0_ports":      "",
		"br0_address":    "",
		"br0_netmask":    "",
		"br0_gateway":    "",
		"br0_stp":        "false",
		"br0_fd":         "0",
		"br0_vlan_aware": "false",
		"br0_vlans":      "",
	}
}

func (b *Bridge) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"bridges":        {Description: "Comma-separated bridge names to create", Default: "br0", Type: "string", Required: true},
		"br0_ports":      {Description: "Comma-separated interfaces to add to br0", Type: "string"},
		"br0_address":    {Description: "IP address for br0 (empty = DHCP)", Type: "string"},
		"br0_netmask":    {Description: "Netmask for br0", Type: "string"},
		"br0_gateway":    {Description: "Gateway for br0", Type: "string"},
		"br0_stp":        {Description: "Enable Spanning Tree Protocol on br0", Default: "false", Type: "bool"},
		"br0_fd":         {Description: "Bridge forward delay (seconds)", Default: "0", Type: "int"},
		"br0_vlan_aware": {Description: "Enable VLAN-aware bridging on br0", Default: "false", Type: "bool"},
		"br0_vlans":      {Description: "VLAN IDs for br0 (e.g. 10,20,30)", Type: "string"},
	}
}

func (b *Bridge) Validate(cfg map[string]string) error {
	bridges := cfg["bridges"]
	if bridges == "" {
		return fmt.Errorf("at least one bridge name is required")
	}
	for _, br := range strings.Split(bridges, ",") {
		br = strings.TrimSpace(br)
		if br == "" {
			continue
		}
		if strings.ContainsAny(br, " \t\n/\\") {
			return fmt.Errorf("invalid bridge name: %s", br)
		}
	}
	return nil
}

func (b *Bridge) Start(cfg map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = cfg

	bridges := strings.Split(cfg["bridges"], ",")
	for _, brName := range bridges {
		brName = strings.TrimSpace(brName)
		if brName == "" {
			continue
		}

		if err := b.createBridge(brName, cfg); err != nil {
			return fmt.Errorf("create bridge %s: %w", brName, err)
		}
	}

	// Write persistent config for networkd.
	if err := b.generateNetworkdConfig(cfg); err != nil {
		slog.Warn("failed to write networkd config (bridges active but not persistent)", "error", err)
	}

	b.state = StateRunning
	return nil
}

func (b *Bridge) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cfg != nil {
		bridges := strings.Split(b.cfg["bridges"], ",")
		for _, brName := range bridges {
			brName = strings.TrimSpace(brName)
			if brName == "" {
				continue
			}
			b.deleteBridge(brName)
		}
	}

	b.state = StateStopped
	return nil
}

func (b *Bridge) Reload(cfg map[string]string) error {
	// Bridge changes often require tear-down/rebuild. Do full restart.
	if err := b.Stop(); err != nil {
		slog.Warn("bridge stop during reload", "error", err)
	}
	return b.Start(cfg)
}

func (b *Bridge) Status() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *Bridge) createBridge(name string, cfg map[string]string) error {
	prefix := name + "_"

	// Create bridge if it doesn't exist.
	if err := Net.LinkAdd(name, "bridge"); err != nil {
		// Already exists is OK.
		slog.Debug("bridge may already exist", "name", name, "error", err)
	}

	// VLAN-aware bridging.
	if cfg[prefix+"vlan_aware"] == "true" {
		Net.BridgeSetVlanFiltering(name, true)
	}

	// STP.
	Net.BridgeSetSTP(name, cfg[prefix+"stp"] == "true")

	// Forward delay.
	if fd := cfg[prefix+"fd"]; fd != "" {
		if v, err := strconv.Atoi(fd); err == nil {
			Net.BridgeSetForwardDelay(name, v)
		}
	}

	// Add ports.
	if ports := cfg[prefix+"ports"]; ports != "" {
		for _, port := range strings.Split(ports, ",") {
			port = strings.TrimSpace(port)
			if port == "" {
				continue
			}
			if err := Net.LinkSetMaster(port, name); err != nil {
				slog.Warn("failed to add port to bridge", "bridge", name, "port", port, "error", err)
			}
			Net.LinkSetUp(port)
		}
	}

	// Assign IP.
	if addr := cfg[prefix+"address"]; addr != "" {
		mask := cfg[prefix+"netmask"]
		if mask == "" {
			mask = "255.255.255.0"
		}
		cidr := addr + "/" + netmaskToCIDR(mask)
		Net.AddrFlush(name)
		if err := Net.AddrAdd(name, cidr); err != nil {
			return fmt.Errorf("assign address to %s: %w", name, err)
		}
	}

	// Bring up.
	if err := Net.LinkSetUp(name); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}

	// Add VLANs if VLAN-aware.
	if cfg[prefix+"vlan_aware"] == "true" && cfg[prefix+"vlans"] != "" {
		for _, vlan := range strings.Split(cfg[prefix+"vlans"], ",") {
			vlan = strings.TrimSpace(vlan)
			if vlan != "" {
				if v, err := strconv.Atoi(vlan); err == nil {
					Net.BridgeVlanAdd(name, v)
				}
			}
		}
	}

	// Default gateway.
	if gw := cfg[prefix+"gateway"]; gw != "" {
		Net.RouteAdd("default", gw, name)
	}

	slog.Info("bridge created", "name", name)
	return nil
}

func (b *Bridge) deleteBridge(name string) {
	Net.LinkSetDown(name)
	Net.LinkDel(name)
	slog.Info("bridge deleted", "name", name)
}

func (b *Bridge) generateNetworkdConfig(cfg map[string]string) error {
	if err := os.MkdirAll(b.confDir, 0o755); err != nil {
		return err
	}

	bridges := strings.Split(cfg["bridges"], ",")
	for _, brName := range bridges {
		brName = strings.TrimSpace(brName)
		if brName == "" {
			continue
		}
		prefix := brName + "_"

		// .netdev file.
		var netdev strings.Builder
		netdev.WriteString("[NetDev]\n")
		netdev.WriteString(fmt.Sprintf("Name=%s\n", brName))
		netdev.WriteString("Kind=bridge\n")

		netdevPath := filepath.Join(b.confDir, fmt.Sprintf("20-gk-%s.netdev", brName))
		if err := os.WriteFile(netdevPath, []byte(netdev.String()), 0o644); err != nil {
			return err
		}

		// .network file for the bridge itself.
		var network strings.Builder
		network.WriteString("[Match]\n")
		network.WriteString(fmt.Sprintf("Name=%s\n\n", brName))
		network.WriteString("[Network]\n")
		if addr := cfg[prefix+"address"]; addr != "" {
			mask := cfg[prefix+"netmask"]
			cidr := addr + "/" + netmaskToCIDR(mask)
			network.WriteString(fmt.Sprintf("Address=%s\n", cidr))
			if gw := cfg[prefix+"gateway"]; gw != "" {
				network.WriteString(fmt.Sprintf("Gateway=%s\n", gw))
			}
		} else {
			network.WriteString("DHCP=yes\n")
		}

		networkPath := filepath.Join(b.confDir, fmt.Sprintf("20-gk-%s.network", brName))
		if err := os.WriteFile(networkPath, []byte(network.String()), 0o644); err != nil {
			return err
		}

		// .network files for member ports.
		if ports := cfg[prefix+"ports"]; ports != "" {
			for _, port := range strings.Split(ports, ",") {
				port = strings.TrimSpace(port)
				if port == "" {
					continue
				}
				var portNet strings.Builder
				portNet.WriteString("[Match]\n")
				portNet.WriteString(fmt.Sprintf("Name=%s\n\n", port))
				portNet.WriteString("[Network]\n")
				portNet.WriteString(fmt.Sprintf("Bridge=%s\n", brName))

				portPath := filepath.Join(b.confDir, fmt.Sprintf("20-gk-%s-%s.network", brName, port))
				if err := os.WriteFile(portPath, []byte(portNet.String()), 0o644); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func netmaskToCIDR(mask string) string {
	if mask == "" {
		return "24"
	}
	// Common netmasks.
	switch mask {
	case "255.255.255.0":
		return "24"
	case "255.255.0.0":
		return "16"
	case "255.0.0.0":
		return "8"
	case "255.255.255.128":
		return "25"
	case "255.255.255.192":
		return "26"
	case "255.255.255.224":
		return "27"
	case "255.255.255.240":
		return "28"
	case "255.255.255.248":
		return "29"
	case "255.255.255.252":
		return "30"
	default:
		return "24"
	}
}
