package backend

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/vishvananda/netlink"
)

// This file implements the NetworkManager netlink-dependent methods
// using the vishvananda/netlink library. No exec.Command("ip", ...) calls.

// LinkAdd creates a network interface (bridge, veth, vlan, etc).
func (m *LinuxNetworkManager) LinkAdd(name string, kind string) error {
	var link netlink.Link
	switch kind {
	case "bridge":
		link = &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
	default:
		link = &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{Name: name},
			LinkType:  kind,
		}
	}
	return netlink.LinkAdd(link)
}

// LinkSetMTU sets the MTU on a network interface via netlink.
func (m *LinuxNetworkManager) LinkSetMTU(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	return netlink.LinkSetMTU(link, mtu)
}

// LinkGetMTU reads the current MTU of a network interface via netlink.
func (m *LinuxNetworkManager) LinkGetMTU(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("link %s: %w", name, err)
	}
	return link.Attrs().MTU, nil
}

// LinkDel deletes a network interface.
func (m *LinuxNetworkManager) LinkDel(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	return netlink.LinkDel(link)
}

// LinkSetUp brings an interface up.
func (m *LinuxNetworkManager) LinkSetUp(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	return netlink.LinkSetUp(link)
}

// LinkSetDown brings an interface down.
func (m *LinuxNetworkManager) LinkSetDown(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	return netlink.LinkSetDown(link)
}

// LinkSetMaster sets an interface's master (e.g., add port to bridge).
func (m *LinuxNetworkManager) LinkSetMaster(name string, master string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	masterLink, err := netlink.LinkByName(master)
	if err != nil {
		return fmt.Errorf("master %s: %w", master, err)
	}
	return netlink.LinkSetMaster(link, masterLink)
}

// AddrAdd adds an IP address to an interface.
func (m *LinuxNetworkManager) AddrAdd(name string, cidr string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse addr %s: %w", cidr, err)
	}
	return netlink.AddrAdd(link, addr)
}

// AddrFlush removes all addresses from an interface.
func (m *LinuxNetworkManager) AddrFlush(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addrs %s: %w", name, err)
	}
	for i := range addrs {
		netlink.AddrDel(link, &addrs[i])
	}
	return nil
}

// RouteAdd adds a route to the main routing table.
func (m *LinuxNetworkManager) RouteAdd(dst string, via string, dev string) error {
	return m.RouteAddTable(dst, via, dev, 0)
}

// RouteDel removes a route from the main routing table.
func (m *LinuxNetworkManager) RouteDel(dst string, via string, dev string) error {
	route := &netlink.Route{}

	if dst != "" && dst != "default" {
		_, dstNet, err := net.ParseCIDR(dst)
		if err != nil {
			return fmt.Errorf("parse dst %s: %w", dst, err)
		}
		route.Dst = dstNet
	}
	if via != "" {
		route.Gw = net.ParseIP(via)
	}
	if dev != "" {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return fmt.Errorf("link %s: %w", dev, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	return netlink.RouteDel(route)
}

// RouteAddTable adds a route in a specific routing table.
func (m *LinuxNetworkManager) RouteAddTable(dst string, via string, dev string, table int) error {
	route := &netlink.Route{}
	if table > 0 {
		route.Table = table
	}

	if dst != "" && dst != "default" {
		_, dstNet, err := net.ParseCIDR(dst)
		if err != nil {
			return fmt.Errorf("parse dst %s: %w", dst, err)
		}
		route.Dst = dstNet
	}
	if via != "" {
		route.Gw = net.ParseIP(via)
	}
	if dev != "" {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return fmt.Errorf("link %s: %w", dev, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	return netlink.RouteAdd(route)
}

// RouteFlushTable removes all routes from a routing table.
func (m *LinuxNetworkManager) RouteFlushTable(table int) error {
	filter := &netlink.Route{Table: table}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for i := range routes {
		netlink.RouteDel(&routes[i])
	}
	return nil
}

// RouteAddMetric adds a route via device with a specific metric.
func (m *LinuxNetworkManager) RouteAddMetric(dst string, dev string, metric int) error {
	route := &netlink.Route{Priority: metric}
	if dst != "" && dst != "default" {
		_, dstNet, err := net.ParseCIDR(dst)
		if err != nil {
			return fmt.Errorf("parse dst %s: %w", dst, err)
		}
		route.Dst = dstNet
	}
	if dev != "" {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return fmt.Errorf("link %s: %w", dev, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	return netlink.RouteAdd(route)
}

// RouteReplace atomically replaces the default route.
func (m *LinuxNetworkManager) RouteReplace(via string, dev string) error {
	route := &netlink.Route{}
	if via != "" {
		route.Gw = net.ParseIP(via)
	}
	if dev != "" {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return fmt.Errorf("link %s: %w", dev, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	return netlink.RouteReplace(route)
}

// RuleAdd adds a policy routing rule: traffic on oif goes to table with priority.
func (m *LinuxNetworkManager) RuleAdd(oif string, table int, priority int) error {
	rule := netlink.NewRule()
	rule.OifName = oif
	rule.Table = table
	rule.Priority = priority
	return netlink.RuleAdd(rule)
}

// RuleAddSrc adds a source-IP-based policy routing rule.
func (m *LinuxNetworkManager) RuleAddSrc(src string, table int, priority int) error {
	_, srcNet, err := net.ParseCIDR(src)
	if err != nil {
		// Try as bare IP.
		ip := net.ParseIP(src)
		if ip == nil {
			return fmt.Errorf("parse src %s: invalid", src)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		srcNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	rule := netlink.NewRule()
	rule.Src = srcNet
	rule.Table = table
	rule.Priority = priority
	return netlink.RuleAdd(rule)
}

// RuleAddFwmark adds a fwmark-based policy routing rule.
func (m *LinuxNetworkManager) RuleAddFwmark(mark uint32, table int, priority int) error {
	rule := netlink.NewRule()
	rule.Mark = int(mark)
	rule.Table = table
	rule.Priority = priority
	return netlink.RuleAdd(rule)
}

// RuleDel removes all policy routing rules for a table.
func (m *LinuxNetworkManager) RuleDel(table int) error {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range rules {
		if rules[i].Table == table {
			netlink.RuleDel(&rules[i])
		}
	}
	return nil
}

// BridgeVlanAdd adds a VLAN to a bridge (self mode).
func (m *LinuxNetworkManager) BridgeVlanAdd(bridge string, vid int) error {
	link, err := netlink.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("link %s: %w", bridge, err)
	}
	return netlink.BridgeVlanAdd(link, uint16(vid), false, false, true, false)
}

// BridgeSetSTP enables or disables STP on a bridge via sysfs.
func (m *LinuxNetworkManager) BridgeSetSTP(name string, enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	return os.WriteFile(fmt.Sprintf("/sys/class/net/%s/bridge/stp_state", name), []byte(val), 0o644)
}

// BridgeSetForwardDelay sets the forward delay on a bridge via sysfs (jiffies).
func (m *LinuxNetworkManager) BridgeSetForwardDelay(name string, delay int) error {
	return os.WriteFile(
		fmt.Sprintf("/sys/class/net/%s/bridge/forward_delay", name),
		[]byte(strconv.Itoa(delay)), 0o644,
	)
}

// BridgeSetVlanFiltering enables or disables VLAN filtering on a bridge via sysfs.
func (m *LinuxNetworkManager) BridgeSetVlanFiltering(name string, enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	return os.WriteFile(fmt.Sprintf("/sys/class/net/%s/bridge/vlan_filtering", name), []byte(val), 0o644)
}
