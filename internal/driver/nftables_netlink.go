package driver

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// applyNetlink applies the gatekeeper ruleset via netlink instead of nft CLI.
func applyNetlink(input *compiler.Input) error {
	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables netlink connection: %w", err)
	}

	// Delete existing gatekeeper table and recreate atomically in a single batch.
	// Using delete+add in one Flush() ensures atomic replacement.
	conn.DelTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gatekeeper"})

	table := conn.AddTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gatekeeper"})

	// Build alias maps.
	aliasMap := make(map[string]*model.Alias)
	for i := range input.Aliases {
		aliasMap[input.Aliases[i].Name] = &input.Aliases[i]
	}

	// Add sets for aliases.
	setMap := make(map[string]*nft.Set)
	for _, a := range input.Aliases {
		members := resolveMembers(&a, aliasMap, 0)
		if len(members) == 0 {
			continue
		}
		setName := nlSanitizeName(a.Name)
		set, elems, err := buildSet(table, setName, a.Type, members)
		if err != nil {
			continue // Skip invalid sets.
		}
		if err := conn.AddSet(set, elems); err != nil {
			return fmt.Errorf("add set %s: %w", setName, err)
		}
		setMap[a.Name] = set
	}

	// Build lookup maps for zone/profile/policy routing.
	zoneProfiles := make(map[int64][]model.Profile)
	for i := range input.Profiles {
		zoneProfiles[input.Profiles[i].ZoneID] = append(zoneProfiles[input.Profiles[i].ZoneID], input.Profiles[i])
	}
	policyMap := make(map[string]*model.Policy)
	for i := range input.Policies {
		policyMap[input.Policies[i].Name] = &input.Policies[i]
	}

	// --- Input chain ---
	inputPolicy := nft.ChainPolicyDrop
	inputChain := conn.AddChain(&nft.Chain{
		Table:    table,
		Name:     "input",
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookInput,
		Priority: nft.ChainPriorityFilter,
		Policy:   &inputPolicy,
	})

	addInputRules(conn, table, inputChain, input)

	// --- Forward chain ---
	fwdPolicy := nft.ChainPolicyDrop
	fwdChain := conn.AddChain(&nft.Chain{
		Table:    table,
		Name:     "forward",
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookForward,
		Priority: nft.ChainPriorityFilter,
		Policy:   &fwdPolicy,
	})

	addForwardRules(conn, table, fwdChain, input, policyMap, aliasMap, zoneProfiles, setMap)

	// --- NAT postrouting chain ---
	var wanIface string
	for _, z := range input.Zones {
		if z.Name == "wan" {
			wanIface = z.Interface
			break
		}
	}
	if wanIface != "" {
		natPolicy := nft.ChainPolicyAccept
		natChain := conn.AddChain(&nft.Chain{
			Table:    table,
			Name:     "postrouting",
			Type:     nft.ChainTypeNAT,
			Hooknum:  nft.ChainHookPostrouting,
			Priority: nft.ChainPriorityNATSource,
			Policy:   &natPolicy,
		})
		// oifname <wan> masquerade
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: natChain,
			Exprs: nlRule(nlMatchOifname(wanIface), []expr.Any{&expr.Masq{}}),
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables netlink flush: %w", err)
	}
	return nil
}

// addInputRules adds the base input chain rules.
func addInputRules(conn *nft.Conn, table *nft.Table, chain *nft.Chain, input *compiler.Input) {
	addRule := func(exprs []expr.Any) {
		conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: exprs})
	}

	// ct state established,related accept
	addRule(nlRule(nlMatchCtState(0x06), nlVerdictAccept()))

	// ct state invalid drop
	addRule(nlRule(nlMatchCtState(0x01), nlVerdictDrop()))

	// iif lo accept
	addRule(nlRule(nlMatchIifname("lo"), nlVerdictAccept()))

	// ip protocol icmp accept
	addRule(nlRule(nlMatchIPProto(1), nlVerdictAccept())) // 1 = ICMP

	// Allow API access from full-trust zones.
	for _, z := range input.Zones {
		if z.TrustLevel == model.TrustFull && z.Interface != "" {
			addRule(nlRule(nlMatchIifname(z.Interface), nlMatchTCPDport(8080), nlVerdictAccept()))
		}
	}

	// Allow WireGuard if configured.
	if input.WGListenPort > 0 {
		addRule(nlRule(nlMatchUDPDport(uint16(input.WGListenPort)), nlVerdictAccept()))
	}

	// Allow DHCP/DNS from all internal zones.
	for _, z := range input.Zones {
		if z.Interface != "" && z.Name != "wan" {
			// UDP dport 53 (DNS)
			addRule(nlRule(nlMatchIifname(z.Interface), nlMatchUDPDport(53), nlVerdictAccept()))
			// UDP dport 67 (DHCP)
			addRule(nlRule(nlMatchIifname(z.Interface), nlMatchUDPDport(67), nlVerdictAccept()))
			// TCP dport 53 (DNS)
			addRule(nlRule(nlMatchIifname(z.Interface), nlMatchTCPDport(53), nlVerdictAccept()))
		}
	}
}

// addForwardRules adds per-zone/profile/policy forwarding rules.
func addForwardRules(conn *nft.Conn, table *nft.Table, chain *nft.Chain, input *compiler.Input,
	policyMap map[string]*model.Policy, aliasMap map[string]*model.Alias,
	zoneProfiles map[int64][]model.Profile, setMap map[string]*nft.Set) {

	addRule := func(exprs []expr.Any) {
		conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: exprs})
	}

	// ct state established,related accept
	addRule(nlRule(nlMatchCtState(0x06), nlVerdictAccept()))

	// ct state invalid drop
	addRule(nlRule(nlMatchCtState(0x01), nlVerdictDrop()))

	// Find WAN interface for outbound rules.
	var wanIface string
	for _, z := range input.Zones {
		if z.Name == "wan" {
			wanIface = z.Interface
			break
		}
	}

	// Per-zone forwarding rules.
	for _, zone := range input.Zones {
		if zone.Name == "wan" || zone.Interface == "" {
			continue
		}

		profiles := zoneProfiles[zone.ID]
		for _, profile := range profiles {
			policy := policyMap[profile.PolicyName]
			if policy == nil {
				continue
			}

			for _, rule := range policy.Rules {
				ruleExprs := compileRuleNetlink(rule, zone.Interface, wanIface, aliasMap, setMap, table)
				if len(ruleExprs) > 0 {
					addRule(ruleExprs)
				}
			}

			// Default action for this policy's unmatched traffic from this zone.
			switch policy.DefaultAction {
			case model.RuleActionAllow:
				addRule(nlRule(nlMatchIifname(zone.Interface), nlVerdictAccept()))
			case model.RuleActionReject:
				addRule(nlRule(nlMatchIifname(zone.Interface), []expr.Any{&expr.Reject{}}))
			}
		}
	}

	// TCP MSS clamping.
	if input.MSSClampPMTU {
		// tcp flags syn / syn,rst tcp option maxseg size set rt mtu
		// This is complex in netlink; add the syn flag match and MSS clamp.
		addRule([]expr.Any{
			// Match TCP SYN (flags & (SYN|RST) == SYN)
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x06}, Xor: []byte{0x00}}, // SYN|RST mask
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},                                     // SYN only
			// rt mtu → register
			&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
			// Set MSS option
			&expr.Exthdr{
				DestRegister:   1,
				Type:           2, // TCP option
				Offset:         2,
				Len:            2,
				Op:             expr.ExthdrOpTcpopt,
				SourceRegister: 1,
			},
		})
	}
}

// compileRuleNetlink translates a model.Rule to nftables netlink expressions.
func compileRuleNetlink(r model.Rule, srcIface, wanIface string,
	aliasMap map[string]*model.Alias, setMap map[string]*nft.Set, table *nft.Table) []expr.Any {

	var parts [][]expr.Any

	parts = append(parts, nlMatchIifname(srcIface))

	if wanIface != "" {
		parts = append(parts, nlMatchOifname(wanIface))
	}

	proto := strings.ToLower(r.Protocol)
	if proto != "" {
		if validate.Protocol(proto) != nil {
			return nil
		}
		switch proto {
		case "icmp":
			parts = append(parts, nlMatchIPProto(1))
		case "icmpv6":
			parts = append(parts, nlMatchIPProto(58))
		case "tcp":
			if r.Ports != "" && validate.Ports(r.Ports) == nil {
				parts = append(parts, nlMatchTCPDports(r.Ports))
			} else {
				parts = append(parts, nlMatchL4Proto(6))
			}
		case "udp":
			if r.Ports != "" && validate.Ports(r.Ports) == nil {
				parts = append(parts, nlMatchUDPDports(r.Ports))
			} else {
				parts = append(parts, nlMatchL4Proto(17))
			}
		default:
			// Generic L4 protocol matching not easily done without numeric value.
			return nil
		}
	}

	if r.SrcAlias != "" {
		if a, ok := aliasMap[r.SrcAlias]; ok && a.Type != model.AliasTypePort {
			if set, ok := setMap[r.SrcAlias]; ok {
				parts = append(parts, nlMatchSrcAddrSet(set))
			}
		}
	}

	if r.DstAlias != "" {
		if a, ok := aliasMap[r.DstAlias]; ok && a.Type != model.AliasTypePort {
			if set, ok := setMap[r.DstAlias]; ok {
				parts = append(parts, nlMatchDstAddrSet(set))
			}
		}
	}

	if r.Log {
		parts = append(parts, []expr.Any{&expr.Log{Key: 1 << 0, Data: []byte("gk:")}})
	}

	if !model.ValidActions[r.Action] {
		return nil
	}

	switch r.Action {
	case model.RuleActionAllow:
		parts = append(parts, nlVerdictAccept())
	case model.RuleActionDeny:
		parts = append(parts, nlVerdictDrop())
	case model.RuleActionReject:
		parts = append(parts, []expr.Any{&expr.Reject{}})
	case model.RuleActionLog:
		// Log-only rules already have the log expression above.
		if !r.Log {
			parts = append(parts, []expr.Any{&expr.Log{Key: 1 << 0, Data: []byte("gk:")}})
		}
	}

	return nlRule(parts...)
}

// --- Set construction ---

func buildSet(table *nft.Table, name string, aliasType model.AliasType, members []string) (*nft.Set, []nft.SetElement, error) {
	set := &nft.Set{
		Table: table,
		Name:  name,
	}

	// Pre-allocate: networks need 2 elements each (interval start+end), others need 1.
	capacity := len(members)
	if aliasType == model.AliasTypeNetwork {
		capacity *= 2
	}
	elems := make([]nft.SetElement, 0, capacity)

	switch aliasType {
	case model.AliasTypeHost:
		set.KeyType = nft.TypeIPAddr
		for _, m := range members {
			ip := net.ParseIP(m)
			if ip == nil {
				continue
			}
			elems = append(elems, nft.SetElement{Key: ip.To4()})
		}

	case model.AliasTypeNetwork:
		set.KeyType = nft.TypeIPAddr
		set.Interval = true
		for _, m := range members {
			_, ipnet, err := net.ParseCIDR(m)
			if err != nil {
				continue
			}
			// Interval sets require start and end elements.
			start := ipnet.IP.To4()
			end := cidrEnd(ipnet)
			elems = append(elems,
				nft.SetElement{Key: start, IntervalEnd: false},
				nft.SetElement{Key: end, IntervalEnd: true},
			)
		}

	case model.AliasTypePort:
		set.KeyType = nft.TypeInetService
		for _, m := range members {
			var port uint16
			if _, err := fmt.Sscanf(m, "%d", &port); err != nil {
				continue
			}
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, port)
			elems = append(elems, nft.SetElement{Key: portBytes})
		}

	case model.AliasTypeMAC:
		set.KeyType = nft.TypeEtherAddr
		for _, m := range members {
			mac, err := net.ParseMAC(m)
			if err != nil {
				continue
			}
			elems = append(elems, nft.SetElement{Key: []byte(mac)})
		}

	default:
		set.KeyType = nft.TypeIPAddr
		for _, m := range members {
			ip := net.ParseIP(m)
			if ip != nil {
				elems = append(elems, nft.SetElement{Key: ip.To4()})
			}
		}
	}

	if len(elems) == 0 {
		return nil, nil, fmt.Errorf("no valid elements for set %s", name)
	}
	return set, elems, nil
}

// cidrEnd computes the first address past the CIDR range (exclusive end for interval set).
func cidrEnd(ipnet *net.IPNet) []byte {
	ip := ipnet.IP.To4()
	mask := ipnet.Mask
	end := make([]byte, 4)
	for i := range ip {
		end[i] = ip[i] | ^mask[i]
	}
	// Increment by 1 for exclusive end.
	for i := 3; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			break
		}
	}
	return end
}

// --- Alias member resolution (mirrors compiler logic) ---

func resolveMembers(a *model.Alias, aliasMap map[string]*model.Alias, depth int) []string {
	seen := make(map[string]struct{})
	return resolveMembersDedup(a, aliasMap, depth, seen)
}

func resolveMembersDedup(a *model.Alias, aliasMap map[string]*model.Alias, depth int, seen map[string]struct{}) []string {
	if depth > 10 {
		return nil
	}
	if a.Type != model.AliasTypeNested {
		safe := make([]string, 0, len(a.Members))
		for _, m := range a.Members {
			if _, dup := seen[m]; dup {
				continue
			}
			if validate.AliasMember(m, string(a.Type)) == nil {
				seen[m] = struct{}{}
				safe = append(safe, m)
			}
		}
		return safe
	}
	var resolved []string
	for _, memberName := range a.Members {
		nested, ok := aliasMap[memberName]
		if !ok {
			continue
		}
		resolved = append(resolved, resolveMembersDedup(nested, aliasMap, depth+1, seen)...)
	}
	return resolved
}

func nlSanitizeName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// --- Netlink expression helpers ---

func nlPadIfname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

func nlBinaryPort(p uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, p)
	return b
}

func nlMatchIifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nlPadIfname(name)},
	}
}

func nlMatchOifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nlPadIfname(name)},
	}
}

func nlMatchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func nlMatchIPProto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func nlMatchTCPDport(port uint16) []expr.Any {
	return append(nlMatchL4Proto(6),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nlBinaryPort(port)},
	)
}

func nlMatchUDPDport(port uint16) []expr.Any {
	return append(nlMatchL4Proto(17),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nlBinaryPort(port)},
	)
}

// nlMatchTCPDports handles comma-separated port lists by matching each port.
// For simplicity, matches the first port. Multi-port matching via anonymous sets
// would be needed for full parity but adds complexity.
func nlMatchTCPDports(ports string) []expr.Any {
	port := parseFirstPort(ports)
	if port == 0 {
		return nlMatchL4Proto(6)
	}
	return nlMatchTCPDport(port)
}

func nlMatchUDPDports(ports string) []expr.Any {
	port := parseFirstPort(ports)
	if port == 0 {
		return nlMatchL4Proto(17)
	}
	return nlMatchUDPDport(port)
}

func parseFirstPort(ports string) uint16 {
	parts := strings.Split(ports, ",")
	if len(parts) == 0 {
		return 0
	}
	var p uint16
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &p); err != nil {
		return 0
	}
	return p
}

func nlMatchCtState(stateMask uint32) []expr.Any {
	mask := make([]byte, 4)
	binary.LittleEndian.PutUint32(mask, stateMask)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
	}
}

func nlMatchSrcAddrSet(set *nft.Set) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}
}

func nlMatchDstAddrSet(set *nft.Set) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}
}

func nlVerdictAccept() []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
}

func nlVerdictDrop() []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
}

func nlRule(groups ...[]expr.Any) []expr.Any {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	result := make([]expr.Any, 0, n)
	for _, g := range groups {
		result = append(result, g...)
	}
	return result
}
