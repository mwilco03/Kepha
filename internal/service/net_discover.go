package service

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
	"github.com/vishvananda/netlink"
)

// Interface kind classification for physical vs virtual detection.
const (
	linkKindDevice    = "device"
	linkKindLoopback  = "loopback"
	linkKindBridge    = "bridge"
	linkKindVeth      = "veth"
	linkKindVLAN      = "vlan"
	linkKindTun       = "tun"
	linkKindTap       = "tap"
	linkKindWireguard = "wireguard"
	linkKindBond      = "bond"
)

// virtualKinds is the set of interface types that are not physical hardware.
// O(1) membership test via map vs O(n) linear scan through slice.
var virtualKinds = map[string]struct{}{
	linkKindBridge:    {},
	linkKindVeth:      {},
	linkKindVLAN:      {},
	linkKindTun:       {},
	linkKindTap:       {},
	linkKindWireguard: {},
	linkKindBond:      {},
	linkKindLoopback:  {},
}

const (
	zeroMAC      = "00:00:00:00:00:00"
	resolvPath   = "/etc/resolv.conf"
	carrierSysfs = "/sys/class/net/%s/carrier"
)

// DiscoveredTopology is the result of auto-detecting the network layout.
type DiscoveredTopology struct {
	// WAN is the interface carrying the default route.
	WAN *backend.LinkInfo `json:"wan,omitempty"`

	// LAN contains physical interfaces that are not WAN.
	LAN []backend.LinkInfo `json:"lan"`

	// All is every interface on the system.
	All []backend.LinkInfo `json:"all"`

	// DefaultGateway is the upstream router IP from the default route.
	DefaultGateway string `json:"default_gateway,omitempty"`

	// UpstreamIP is the IP address assigned to the WAN interface.
	UpstreamIP string `json:"upstream_ip,omitempty"`

	// UpstreamSubnet is the dotted subnet mask from the WAN address.
	UpstreamSubnet string `json:"upstream_subnet,omitempty"`

	// UpstreamDNS is the first nameserver from /etc/resolv.conf.
	UpstreamDNS string `json:"upstream_dns,omitempty"`

	// Suggestion is the auto-pick for drop-in mode when topology is unambiguous.
	Suggestion *TopologySuggestion `json:"suggestion,omitempty"`
}

// TopologySuggestion is the zero-config recommendation for drop-in mode.
type TopologySuggestion struct {
	WANInterface string `json:"wan_interface"`
	LANInterface string `json:"lan_interface"`
	Gateway      string `json:"gateway"`
	Reason       string `json:"reason"`
}

// DiscoverTopology probes the system to build a complete picture of the
// network layout. Detection strategy:
//
//  1. Enumerate interfaces via netlink
//  2. Find default route → that interface is WAN, gateway is the upstream router
//  3. Read WAN interface's first address → upstream IP and subnet
//  4. Read /etc/resolv.conf → upstream DNS
//  5. Remaining physical interfaces with carrier → LAN candidates
//
// Time: O(I + R) where I = interfaces, R = routes. Single pass each.
// Space: O(I) for the result set.
func DiscoverTopology() (*DiscoveredTopology, error) {
	links, err := Net.LinkList()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}

	defaultGW, defaultIfIdx := findDefaultRoute()

	result := &DiscoveredTopology{
		All:            links,
		DefaultGateway: defaultGW,
		UpstreamDNS:    readFirstNameserver(),
	}

	// Single pass: classify each interface as WAN, LAN candidate, or skip.
	// O(n) where n = number of interfaces.
	for i := range links {
		link := &links[i]

		if link.Kind == linkKindLoopback {
			continue
		}

		if defaultIfIdx > 0 && isLinkIndex(link.Name, defaultIfIdx) {
			result.WAN = link
			if len(link.Addresses) > 0 {
				result.UpstreamIP, result.UpstreamSubnet = parseCIDRComponents(link.Addresses[0])
			}
			continue
		}

		if isPhysicalInterface(link) {
			result.LAN = append(result.LAN, *link)
		}
	}

	result.Suggestion = buildSuggestion(result)
	return result, nil
}

// findDefaultRoute returns the gateway IP and link index of the default route.
// Scans the IPv4 route table once: O(R) where R = number of routes.
func findDefaultRoute() (gateway string, linkIdx int) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		slog.Debug("discover: failed to list routes", "error", err)
		return "", 0
	}

	for _, r := range routes {
		if r.Dst != nil {
			continue // Not a default route.
		}
		gw := ""
		if r.Gw != nil {
			gw = r.Gw.String()
		}
		return gw, r.LinkIndex
	}
	return "", 0
}

// isLinkIndex checks if a named interface has the given netlink index.
func isLinkIndex(name string, idx int) bool {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false
	}
	return link.Attrs().Index == idx
}

// isPhysicalInterface returns true for real hardware NICs.
// O(1) map lookup for kind classification.
func isPhysicalInterface(link *backend.LinkInfo) bool {
	if link.Kind == linkKindDevice {
		return true
	}
	if _, virtual := virtualKinds[link.Kind]; virtual {
		return false
	}
	// Unknown kind — physical NICs have non-zero MAC addresses.
	return link.MACAddress != "" && link.MACAddress != zeroMAC
}

// buildSuggestion picks the best WAN/LAN pair when the topology is clear.
func buildSuggestion(topo *DiscoveredTopology) *TopologySuggestion {
	if topo.WAN == nil {
		slog.Debug("discover: no WAN detected (no default route)")
		return nil
	}

	// Prefer LAN candidates with carrier (cable connected).
	activeLAN := filterByCarrier(topo.LAN)
	if len(activeLAN) == 0 {
		activeLAN = topo.LAN // Fall back to all candidates.
	}
	if len(activeLAN) == 0 {
		slog.Debug("discover: no LAN candidates found")
		return nil
	}

	reason := fmt.Sprintf("%s has the default route (gateway %s), %s is the ",
		topo.WAN.Name, topo.DefaultGateway, activeLAN[0].Name)

	if len(activeLAN) == 1 {
		reason += "only other physical interface"
	} else {
		reason += fmt.Sprintf("first of %d candidates — verify this is correct", len(activeLAN))
	}

	return &TopologySuggestion{
		WANInterface: topo.WAN.Name,
		LANInterface: activeLAN[0].Name,
		Gateway:      topo.DefaultGateway,
		Reason:       reason,
	}
}

// filterByCarrier returns only interfaces with link detected.
func filterByCarrier(links []backend.LinkInfo) []backend.LinkInfo {
	var out []backend.LinkInfo
	for i := range links {
		if links[i].HasCarrier {
			out = append(out, links[i])
		}
	}
	return out
}

// readFirstNameserver extracts the first nameserver from /etc/resolv.conf.
func readFirstNameserver() string {
	f, err := os.Open(resolvPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && net.ParseIP(fields[1]) != nil {
			return fields[1]
		}
	}
	return ""
}
