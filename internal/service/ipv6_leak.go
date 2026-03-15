package service

import (
	"fmt"
	"log/slog"
	"net"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// IPv6LeakPrevention blocks IPv6 traffic when a VPN tunnel is active.
//
// GL.iNet's own documentation warns: "If you use functions of both VPN and IPv6
// at the same time, it's likely to cause IPv6 data leakage." Their VPN tunnels
// don't handle IPv6, so IPv6 traffic bypasses the tunnel entirely.
//
// Gatekeeper solves this by:
//  1. Detecting when a VPN tunnel is active (wg-vpn0, tun0, etc.)
//  2. Installing ip6 family nftables rules that drop all IPv6 forwarded traffic
//     except for link-local (fe80::/10) and loopback
//  3. Automatically removing the rules when VPN goes down
//
// This is enabled via the existing VPNProvider kill switch config — when
// kill_switch=true, both IPv4 and IPv6 leak prevention are applied.

const ipv6LeakTable = "gk_vpn_ipv6_leak"

// applyIPv6LeakPrevention installs nftables rules to block IPv6 traffic
// that would bypass the VPN tunnel.
func applyIPv6LeakPrevention(vpnIface string) error {
	if vpnIface == "" {
		vpnIface = "wg-vpn0"
	}

	dropPolicy := nft.ChainPolicyDrop

	rules := [][]expr.Any{
		// Allow traffic on the VPN interface (if VPN itself carries IPv6).
		nftRule(nftMatchOifname(vpnIface), nftExpr(nftAccept())),
		// Allow loopback.
		nftRule(nftMatchOifname("lo"), nftExpr(nftAccept())),
		// Allow established/related connections.
		nftRule(nftMatchCtStateEstRel(), nftExpr(nftAccept())),
		// Allow link-local (fe80::/10) — needed for NDP, router solicitation.
		nftRule(nftMatchIP6DaddrCIDR("fe80::/10"), nftExpr(nftAccept())),
		// Allow multicast (ff00::/8) — needed for NDP.
		nftRule(nftMatchIP6DaddrCIDR("ff00::/8"), nftExpr(nftAccept())),
		// Allow DHCPv6 (UDP 546-547).
		nftRule(nftMatchUDPDportRange(546, 547), nftExpr(nftAccept())),
		// Allow ICMPv6 (needed for NDP, PMTUD).
		nftRule(nftMatchL4Proto(58), nftExpr(nftAccept())),
		// Everything else: dropped by chain policy.
	}

	hook := nft.ChainHookOutput
	prio := nft.ChainPriorityFilter

	outputChain := nftChainSpec{
		Name:     "output",
		Type:     nft.ChainTypeFilter,
		Hook:     hook,
		Priority: prio,
		Policy:   &dropPolicy,
		Rules:    rules,
	}

	// Forward chain: block forwarded IPv6 traffic from LAN devices.
	fwdHook := nft.ChainHookForward
	fwdRules := [][]expr.Any{
		nftRule(nftMatchOifname(vpnIface), nftExpr(nftAccept())),
		nftRule(nftMatchOifname("lo"), nftExpr(nftAccept())),
		nftRule(nftMatchCtStateEstRel(), nftExpr(nftAccept())),
		nftRule(nftMatchIP6DaddrCIDR("fe80::/10"), nftExpr(nftAccept())),
		nftRule(nftMatchIP6DaddrCIDR("ff00::/8"), nftExpr(nftAccept())),
		nftRule(nftMatchL4Proto(58), nftExpr(nftAccept())),
	}

	fwdChain := nftChainSpec{
		Name:     "forward",
		Type:     nft.ChainTypeFilter,
		Hook:     fwdHook,
		Priority: prio,
		Policy:   &dropPolicy,
		Rules:    fwdRules,
	}

	if err := nftApplyRules(nft.TableFamilyIPv6, ipv6LeakTable, []nftChainSpec{
		outputChain,
		fwdChain,
	}); err != nil {
		return fmt.Errorf("apply IPv6 leak prevention: %w", err)
	}

	slog.Info("ipv6 leak prevention applied", "vpn_iface", vpnIface)
	return nil
}

// removeIPv6LeakPrevention removes the IPv6 blocking rules.
func removeIPv6LeakPrevention() {
	nftDeleteTable(nft.TableFamilyIPv6, ipv6LeakTable)
	slog.Info("ipv6 leak prevention removed")
}

// nftMatchIP6DaddrCIDR matches IPv6 destination address against a CIDR.
func nftMatchIP6DaddrCIDR(cidr string) []expr.Any {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ip6 := ipnet.IP.To16()
	if ip6 == nil {
		return nil
	}
	mask := []byte(ipnet.Mask)
	if len(mask) != 16 {
		return nil
	}
	// Apply mask to get the network address.
	masked := make([]byte, 16)
	for i := range ip6 {
		masked[i] = ip6[i] & mask[i]
	}
	return []expr.Any{
		// IPv6 destination address is at offset 24, length 16 in the network header.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            16,
			Mask:           mask,
			Xor:            make([]byte, 16),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: masked},
	}
}
