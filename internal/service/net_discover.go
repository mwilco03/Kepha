package service

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
	"github.com/vishvananda/netlink"
)

// DiscoveredTopology is the result of auto-detecting the network layout.
type DiscoveredTopology struct {
	// WAN is the interface with the default route (connects to upstream router).
	WAN *backend.LinkInfo `json:"wan,omitempty"`

	// LAN candidates are physical interfaces that are NOT the WAN.
	LAN []backend.LinkInfo `json:"lan"`

	// All is every interface on the system.
	All []backend.LinkInfo `json:"all"`

	// DefaultGateway is the upstream router's IP (from the default route).
	DefaultGateway string `json:"default_gateway,omitempty"`

	// Suggestion is the auto-pick: the best WAN and LAN for drop-in mode.
	Suggestion *TopologySuggestion `json:"suggestion,omitempty"`
}

// TopologySuggestion is the zero-config recommendation.
type TopologySuggestion struct {
	WANInterface string `json:"wan_interface"`
	LANInterface string `json:"lan_interface"`
	Gateway      string `json:"gateway"`
	Reason       string `json:"reason"`
}

// DiscoverTopology probes the system to identify WAN and LAN interfaces.
//
// Detection logic:
//  1. Enumerate all interfaces via netlink (LinkList)
//  2. Find the default route — its interface is WAN
//  3. All other physical (non-loopback, non-virtual, non-bridge) interfaces
//     with carrier are LAN candidates
//  4. If exactly one WAN and one LAN candidate exist, suggest them automatically
func DiscoverTopology() (*DiscoveredTopology, error) {
	links, err := Net.LinkList()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}

	// Find the default route to identify WAN.
	defaultGW, defaultIfIdx := findDefaultRoute()

	result := &DiscoveredTopology{
		All:            links,
		DefaultGateway: defaultGW,
	}

	for i := range links {
		link := &links[i]

		if link.Kind == "loopback" {
			continue
		}

		// The interface carrying the default route is WAN.
		if defaultIfIdx > 0 && isLinkIndex(link.Name, defaultIfIdx) {
			result.WAN = link
			continue
		}

		// Only consider physical device interfaces as LAN candidates.
		if !isPhysicalInterface(link) {
			continue
		}

		result.LAN = append(result.LAN, *link)
	}

	// Build suggestion if topology is unambiguous.
	result.Suggestion = buildSuggestion(result)

	return result, nil
}

// findDefaultRoute returns the gateway IP and link index of the default route.
func findDefaultRoute() (gateway string, linkIdx int) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		slog.Debug("discover: failed to list routes", "error", err)
		return "", 0
	}

	for _, r := range routes {
		// Default route: Dst is nil or 0.0.0.0/0.
		if r.Dst == nil || (r.Dst.IP.Equal(net.IPv4zero) && r.Dst.Mask.String() == "00000000") {
			gw := ""
			if r.Gw != nil {
				gw = r.Gw.String()
			}
			return gw, r.LinkIndex
		}
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

// isPhysicalInterface returns true for real hardware NICs (not bridges,
// veth pairs, VLANs, tunnels, etc).
func isPhysicalInterface(link *backend.LinkInfo) bool {
	switch link.Kind {
	case "device":
		return true
	case "bridge", "veth", "vlan", "tun", "tap", "wireguard", "bond", "loopback":
		return false
	default:
		// Unknown kind — check if it has a MAC address (physical NICs do).
		return link.MACAddress != "" && link.MACAddress != "00:00:00:00:00:00"
	}
}

// buildSuggestion picks the best WAN/LAN pair if the topology is clear enough.
func buildSuggestion(topo *DiscoveredTopology) *TopologySuggestion {
	if topo.WAN == nil {
		slog.Debug("discover: no WAN detected (no default route)")
		return nil
	}

	// Filter LAN candidates to only those with carrier (cable plugged in).
	var activeLAN []backend.LinkInfo
	for _, l := range topo.LAN {
		if l.HasCarrier {
			activeLAN = append(activeLAN, l)
		}
	}

	if len(activeLAN) == 0 {
		// Fall back to all LAN candidates if none have carrier.
		activeLAN = topo.LAN
	}

	if len(activeLAN) == 0 {
		slog.Debug("discover: no LAN candidates found")
		return nil
	}

	if len(activeLAN) == 1 {
		return &TopologySuggestion{
			WANInterface: topo.WAN.Name,
			LANInterface: activeLAN[0].Name,
			Gateway:      topo.DefaultGateway,
			Reason:       fmt.Sprintf("%s has the default route (gateway %s), %s is the only other physical interface", topo.WAN.Name, topo.DefaultGateway, activeLAN[0].Name),
		}
	}

	// Multiple LAN candidates — can't auto-pick, but still suggest WAN.
	slog.Info("discover: multiple LAN candidates, manual selection needed",
		"wan", topo.WAN.Name, "lan_candidates", len(activeLAN))
	return &TopologySuggestion{
		WANInterface: topo.WAN.Name,
		LANInterface: activeLAN[0].Name,
		Gateway:      topo.DefaultGateway,
		Reason:       fmt.Sprintf("%s has the default route; picked %s as LAN (first of %d candidates — verify this is correct)", topo.WAN.Name, activeLAN[0].Name, len(activeLAN)),
	}
}
