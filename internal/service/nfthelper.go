package service

import (
	"fmt"
	"net"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// nftables netlink helpers for service-level rule management.
// These replace exec.Command("nft", ...) calls with pure netlink operations.

// nftDeleteTable deletes an nftables table and all its chains/rules.
// Silently succeeds if the table does not exist.
func nftDeleteTable(family nft.TableFamily, name string) {
	conn, err := nft.New()
	if err != nil {
		return
	}
	conn.DelTable(&nft.Table{Family: family, Name: name})
	conn.Flush() //nolint:errcheck // best-effort cleanup
}

// nftDeleteChain deletes a chain from a table.
// Silently succeeds if the chain or table does not exist.
func nftDeleteChain(family nft.TableFamily, tableName, chainName string) {
	conn, err := nft.New()
	if err != nil {
		return
	}
	conn.DelChain(&nft.Chain{
		Table: &nft.Table{Family: family, Name: tableName},
		Name:  chainName,
	})
	conn.Flush() //nolint:errcheck // best-effort cleanup
}

// nftApplyRules creates/replaces a table with the given chains and rules.
// Each chainSpec describes a chain and its rules. The table is created if needed.
func nftApplyRules(family nft.TableFamily, tableName string, chains []nftChainSpec) error {
	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables connection: %w", err)
	}

	table := conn.AddTable(&nft.Table{Family: family, Name: tableName})

	for _, cs := range chains {
		chain := conn.AddChain(&nft.Chain{
			Table:    table,
			Name:     cs.Name,
			Type:     cs.Type,
			Hooknum:  cs.Hook,
			Priority: cs.Priority,
			Policy:   cs.Policy,
		})
		for _, ruleExprs := range cs.Rules {
			conn.AddRule(&nft.Rule{
				Table: table,
				Chain: chain,
				Exprs: ruleExprs,
			})
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// nftAddRule appends a single rule to an existing chain.
func nftAddRule(family nft.TableFamily, tableName, chainName string, exprs []expr.Any) error {
	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables connection: %w", err)
	}

	table := &nft.Table{Family: family, Name: tableName}
	chain := &nft.Chain{Table: table, Name: chainName}

	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables add rule: %w", err)
	}
	return nil
}

// nftChainSpec describes a chain and its rules for nftApplyRules.
type nftChainSpec struct {
	Name     string
	Type     nft.ChainType
	Hook     *nft.ChainHook
	Priority *nft.ChainPriority
	Policy   *nft.ChainPolicy
	Rules    [][]expr.Any
}

// --- Expression builders for common nftables patterns ---

func nftPadIfname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

func nftBinaryPort(p uint16) []byte {
	return []byte{byte(p >> 8), byte(p & 0xff)}
}

// nftMatchOifname matches output interface name.
func nftMatchOifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftPadIfname(name)},
	}
}

// nftMatchIifname matches input interface name.
func nftMatchIifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftPadIfname(name)},
	}
}

// nftMatchL4Proto matches the L4 protocol (6=TCP, 17=UDP).
func nftMatchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// nftMatchDport matches transport layer destination port.
// Must be preceded by an L4 protocol match.
func nftMatchDport(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftBinaryPort(port)},
	}
}

// nftMatchDportRange matches transport layer destination port range.
// Must be preceded by an L4 protocol match.
func nftMatchDportRange(lo, hi uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: nftBinaryPort(lo)},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: nftBinaryPort(hi)},
	}
}

// nftMatchTCPDport matches TCP destination port.
func nftMatchTCPDport(port uint16) []expr.Any {
	return append(nftMatchL4Proto(6), nftMatchDport(port)...)
}

// nftMatchUDPDport(port) matches UDP destination port.
func nftMatchUDPDport(port uint16) []expr.Any {
	return append(nftMatchL4Proto(17), nftMatchDport(port)...)
}

// nftMatchUDPDportRange matches UDP destination port range.
func nftMatchUDPDportRange(lo, hi uint16) []expr.Any {
	return append(nftMatchL4Proto(17), nftMatchDportRange(lo, hi)...)
}

// nftMatchEtherSaddr matches Ethernet source address (MAC).
func nftMatchEtherSaddr(mac net.HardwareAddr) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(mac)},
	}
}

// nftMatchIPDaddrCIDR matches IPv4 destination against a CIDR.
func nftMatchIPDaddrCIDR(cidr string) []expr.Any {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte(ipnet.Mask),
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ipnet.IP.To4()},
	}
}

// nftMatchIPDaddrNot matches IPv4 destination NOT equal to given IP.
func nftMatchIPDaddrNot(ip net.IP) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ip.To4()},
	}
}

// nftMatchCtStateEstRel matches ct state established,related.
func nftMatchCtStateEstRel() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // established | related
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
	}
}

// nftAccept returns an accept verdict expression.
func nftAccept() expr.Any {
	return &expr.Verdict{Kind: expr.VerdictAccept}
}

// nftDrop returns a drop verdict expression.
func nftDrop() expr.Any {
	return &expr.Verdict{Kind: expr.VerdictDrop}
}

// nftCounter returns a counter expression.
func nftCounter() expr.Any {
	return &expr.Counter{}
}

// nftQueue sends packet to NFQUEUE with bypass flag.
func nftQueue(num uint16) expr.Any {
	return &expr.Queue{Num: num, Flag: expr.QueueFlagBypass}
}

// nftRedirectToPort creates a redirect-to-port expression (for DNAT).
func nftRedirectToPort(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: nftBinaryPort(port)},
		&expr.Redir{RegisterProtoMin: 1},
	}
}

// nftRule is a convenience to build a rule from multiple expression groups.
func nftRule(groups ...[]expr.Any) []expr.Any {
	var result []expr.Any
	for _, g := range groups {
		result = append(result, g...)
	}
	return result
}

// nftRuleV wraps a single verdict expression as a slice for nftRule.
func nftExpr(e expr.Any) []expr.Any {
	return []expr.Any{e}
}
