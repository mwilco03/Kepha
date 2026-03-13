package xdp

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// tableName is the dedicated nftables table for countermeasures.
// Kept separate from the main "gatekeeper" table so countermeasure
// lifecycle doesn't interfere with core firewall rules.
const tableName = "gk_countermeasures"

// Enforcer applies countermeasure policies as nftables rules via pure
// netlink syscalls. No exec.Command, no string building, no shell-outs.
//
// Architecture:
//
//	Table: gk_countermeasures (ip family)
//	  Chain: cm_input   (filter, input hook, priority filter+10)
//	    - Tarpit rules (TCP rate limit per source)
//	    - SYN cookie enforcement (SYN rate limit per source)
//	  Chain: cm_forward (filter, forward hook, priority filter+10)
//	    - Bandwidth throttle (packet rate limit per source)
//	    - Latency injection (NFQUEUE per source)
//	    - RST chaos (probabilistic drop on established TCP)
//	  Chain: cm_postrouting (filter, postrouting hook, priority mangle)
//	    - TTL randomization (rewrite TTL on responses to target)
type Enforcer struct {
	mu sync.Mutex
	// connFn creates a new nftables netlink connection.
	// Injectable for testing; defaults to nft.New.
	connFn func() (*nft.Conn, error)
}

// NewEnforcer creates a new countermeasure enforcer using real netlink.
func NewEnforcer() *Enforcer {
	return &Enforcer{
		connFn: func() (*nft.Conn, error) { return nft.New() },
	}
}

// Sync atomically rebuilds the entire countermeasures table from the
// given set of active policies. This is a full replace: the old table
// is deleted and a new one is built from scratch.
//
// If policies is empty, the table is removed entirely (clean state).
func (e *Enforcer) Sync(policies []CountermeasurePolicy, global CountermeasureConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	conn, err := e.connFn()
	if err != nil {
		return fmt.Errorf("netlink connection: %w", err)
	}

	// Delete existing countermeasures table (safe — we're about to recreate).
	e.deleteTable(conn)

	// If no policies, just flush the delete and return clean.
	if len(policies) == 0 {
		if err := conn.Flush(); err != nil {
			slog.Debug("flush delete (no policies)", "error", err)
		}
		return nil
	}

	// Create the countermeasures table.
	table := conn.AddTable(&nft.Table{
		Family: nft.TableFamilyIPv4,
		Name:   tableName,
	})

	// Build chains and populate rules.
	e.buildInputChain(conn, table, policies, global)
	e.buildForwardChain(conn, table, policies, global)
	e.buildPostroutingChain(conn, table, policies, global)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("atomic commit: %w", err)
	}

	slog.Info("countermeasures enforced via netlink",
		"policies", len(policies),
		"table", tableName,
	)
	return nil
}

// Teardown removes the countermeasures table entirely.
func (e *Enforcer) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	conn, err := e.connFn()
	if err != nil {
		return fmt.Errorf("netlink connection: %w", err)
	}

	e.deleteTable(conn)

	if err := conn.Flush(); err != nil {
		slog.Debug("teardown flush", "error", err)
	}
	return nil
}

// deleteTable removes the countermeasures table if it exists.
func (e *Enforcer) deleteTable(conn *nft.Conn) {
	conn.DelTable(&nft.Table{
		Family: nft.TableFamilyIPv4,
		Name:   tableName,
	})
}

// buildInputChain creates rules for techniques that apply to traffic
// destined for the gateway itself (tarpit, SYN cookie).
func (e *Enforcer) buildInputChain(conn *nft.Conn, table *nft.Table, policies []CountermeasurePolicy, global CountermeasureConfig) {
	var rules [][]expr.Any

	for _, p := range policies {
		saddr := matchIPv4Saddr(p.Target)
		if saddr == nil {
			continue
		}

		for _, tech := range p.Techniques {
			if !tech.Enabled {
				continue
			}
			switch tech.Type {
			case TechniqueTarpit:
				rules = append(rules, e.tarpitRules(saddr, global)...)
			case TechniqueSYNCookie:
				rules = append(rules, e.synCookieRules(saddr)...)
			}
		}
	}

	if len(rules) == 0 {
		return
	}

	prio := nft.ChainPriorityRef(nft.ChainPriority(10))
	chain := conn.AddChain(&nft.Chain{
		Name:     "cm_input",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookInput,
		Priority: prio,
	})

	for _, r := range rules {
		conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: r})
	}
}

// buildForwardChain creates rules for techniques that apply to forwarded
// traffic (bandwidth throttle, latency injection, RST chaos).
func (e *Enforcer) buildForwardChain(conn *nft.Conn, table *nft.Table, policies []CountermeasurePolicy, global CountermeasureConfig) {
	var rules [][]expr.Any

	for _, p := range policies {
		saddr := matchIPv4Saddr(p.Target)
		if saddr == nil {
			continue
		}

		for _, tech := range p.Techniques {
			if !tech.Enabled {
				continue
			}
			switch tech.Type {
			case TechniqueBandwidth:
				rules = append(rules, e.bandwidthRules(saddr, tech, global)...)
			case TechniqueLatency:
				rules = append(rules, e.latencyRule(saddr))
			case TechniqueRSTChaos:
				r := e.rstChaosRule(saddr, global)
				if r != nil {
					rules = append(rules, r)
				}
			}
		}
	}

	if len(rules) == 0 {
		return
	}

	prio := nft.ChainPriorityRef(nft.ChainPriority(10))
	chain := conn.AddChain(&nft.Chain{
		Name:     "cm_forward",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookForward,
		Priority: prio,
	})

	for _, r := range rules {
		conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: r})
	}
}

// buildPostroutingChain creates rules for TTL randomization on outgoing
// packets destined for countermeasure targets.
func (e *Enforcer) buildPostroutingChain(conn *nft.Conn, table *nft.Table, policies []CountermeasurePolicy, global CountermeasureConfig) {
	var rules [][]expr.Any

	for _, p := range policies {
		daddr := matchIPv4Daddr(p.Target)
		if daddr == nil {
			continue
		}

		for _, tech := range p.Techniques {
			if !tech.Enabled {
				continue
			}
			if tech.Type == TechniqueTTLRandomize {
				rules = append(rules, e.ttlRandomRule(daddr))
			}
		}
	}

	if len(rules) == 0 {
		return
	}

	prio := nft.ChainPriorityMangle
	chain := conn.AddChain(&nft.Chain{
		Name:     "cm_postrouting",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookPostrouting,
		Priority: prio,
	})

	for _, r := range rules {
		conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: r})
	}
}

// --- Technique rule builders ---

// tarpitRules creates two rules: rate-limited accept + drop excess.
// Accepts only 1 TCP packet/minute from the target, drops everything else.
func (e *Enforcer) tarpitRules(saddr []expr.Any, global CountermeasureConfig) [][]expr.Any {
	tcp := matchL4Proto(6) // TCP

	// Rule 1: match saddr + TCP + limit 1/minute → accept
	accept := concat(saddr, tcp,
		[]expr.Any{
			&expr.Limit{
				Type:  expr.LimitTypePkts,
				Rate:  1,
				Unit:  expr.LimitTimeMinute,
				Over:  false,
				Burst: 1,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	)

	// Rule 2: match saddr + TCP → drop (catches everything over the limit)
	drop := concat(saddr, tcp,
		[]expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	)

	return [][]expr.Any{accept, drop}
}

// synCookieRules enforces SYN rate limiting: 1 SYN/second, drop excess.
func (e *Enforcer) synCookieRules(saddr []expr.Any) [][]expr.Any {
	tcpSyn := concat(matchL4Proto(6), matchTCPSynFlag())

	// Rule 1: match saddr + TCP SYN + limit 1/second → accept
	accept := concat(saddr, tcpSyn,
		[]expr.Any{
			&expr.Limit{
				Type:  expr.LimitTypePkts,
				Rate:  1,
				Unit:  expr.LimitTimeSecond,
				Over:  false,
				Burst: 1,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	)

	// Rule 2: match saddr + TCP SYN → drop
	drop := concat(saddr, tcpSyn,
		[]expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	)

	return [][]expr.Any{accept, drop}
}

// bandwidthRules creates packet-rate limiting rules.
func (e *Enforcer) bandwidthRules(saddr []expr.Any, tech TechniqueConfig, global CountermeasureConfig) [][]expr.Any {
	limitBps := global.BandwidthLimitBps
	if v, ok := tech.Params["limit_bps"]; ok {
		fmt.Sscanf(v, "%d", &limitBps)
	}
	// Convert bytes/sec to packets/sec using configured or detected MTU.
	// Supports jumbo frames (9000) and VXLAN-reduced MTUs (1450).
	avgPktSize := global.AvgPacketSize
	if avgPktSize <= 0 {
		avgPktSize = DefaultAvgPacketSize
	}
	pps := uint64(limitBps / avgPktSize)
	if pps < 1 {
		pps = 1
	}

	// Rule 1: match saddr + limit N/second → accept
	accept := concat(saddr,
		[]expr.Any{
			&expr.Limit{
				Type:  expr.LimitTypePkts,
				Rate:  pps,
				Unit:  expr.LimitTimeSecond,
				Over:  false,
				Burst: uint32(pps),
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	)

	// Rule 2: match saddr → drop
	drop := concat(saddr,
		[]expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	)

	return [][]expr.Any{accept, drop}
}

// latencyRule sends packets from the target to NFQUEUE for userspace delay.
func (e *Enforcer) latencyRule(saddr []expr.Any) []expr.Any {
	return concat(saddr,
		[]expr.Any{
			&expr.Counter{},
			&expr.Queue{
				Num:  100,
				Flag: expr.QueueFlagBypass,
			},
		},
	)
}

// rstChaosRule probabilistically drops established TCP connections.
// Uses numgen random to achieve the configured probability.
func (e *Enforcer) rstChaosRule(saddr []expr.Any, global CountermeasureConfig) []expr.Any {
	prob := int(global.RSTChaosProbability * 100)
	if prob <= 0 || prob > 100 {
		return nil
	}

	return concat(saddr,
		matchL4Proto(6),         // TCP
		matchCtStateEstablished(),
		[]expr.Any{
			// Generate random 0..99
			&expr.Numgen{
				Register: 1,
				Modulus:  100,
				Type:     unix.NFT_NG_RANDOM,
				Offset:   0,
			},
			// Match if random < probability threshold
			&expr.Cmp{
				Op:       expr.CmpOpLt,
				Register: 1,
				Data:     uint32Bytes(uint32(prob)),
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	)
}

// ttlRandomRule rewrites the IP TTL to a random value between 32-128.
// This confuses OS fingerprinting and traceroute tools.
func (e *Enforcer) ttlRandomRule(daddr []expr.Any) []expr.Any {
	ttl := byte(32 + rand.Intn(96))

	return concat(daddr,
		[]expr.Any{
			// Load new TTL value into register 1.
			&expr.Immediate{
				Register: 1,
				Data:     []byte{ttl},
			},
			// Write register 1 to the IPv4 TTL field (offset 8, len 1).
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         8,
				Len:            1,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10, // IPv4 header checksum at offset 10
			},
			&expr.Counter{},
		},
	)
}

// --- Expression helpers ---

// matchIPv4Saddr builds expressions to match the IPv4 source address.
// Supports both single IPs ("10.0.0.1") and CIDRs ("10.0.0.0/24").
func matchIPv4Saddr(target string) []expr.Any {
	return matchIPv4Addr(target, 12) // IPv4 saddr at offset 12
}

// matchIPv4Daddr builds expressions to match the IPv4 destination address.
func matchIPv4Daddr(target string) []expr.Any {
	return matchIPv4Addr(target, 16) // IPv4 daddr at offset 16
}

// matchIPv4Addr builds expressions to match an IPv4 address field.
func matchIPv4Addr(target string, offset uint32) []expr.Any {
	// Try CIDR first.
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return nil // Not IPv4
		}
		if ones == 32 {
			// /32 is just a single IP.
			return []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ipnet.IP.To4()},
			}
		}
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
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

	// Try single IP.
	ip := net.ParseIP(target)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip4},
	}
}

// matchL4Proto matches the layer 4 protocol number.
func matchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// matchTCPSynFlag matches TCP packets with the SYN flag set.
func matchTCPSynFlag() []expr.Any {
	return []expr.Any{
		// Load TCP flags byte (offset 13 in TCP header).
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		// AND with SYN bit (0x02).
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x02},
			Xor:            []byte{0x00},
		},
		// SYN flag must be set (result != 0).
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00}},
	}
}

// matchCtStateEstablished matches packets in established connection state.
func matchCtStateEstablished() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0x02, 0x00, 0x00, 0x00}, // established
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0x00, 0x00, 0x00, 0x00},
		},
	}
}

// concat joins multiple expression slices into one.
func concat(groups ...[]expr.Any) []expr.Any {
	var result []expr.Any
	for _, g := range groups {
		result = append(result, g...)
	}
	return result
}

// uint32Bytes encodes a uint32 in big-endian for nftables register comparisons.
func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
