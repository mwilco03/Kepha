package backend

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// NftablesBackend implements FirewallBackend using the google/nftables
// netlink library. No exec.Command("nft", ...) — pure netlink syscalls.
type NftablesBackend struct {
	mu         sync.Mutex
	rulesetDir string // Directory for human-readable ruleset dumps (for audit/debug).
	lastApply  *Artifact
}

// NewNftablesBackend creates a new nftables backend.
func NewNftablesBackend(rulesetDir string) *NftablesBackend {
	return &NftablesBackend{
		rulesetDir: rulesetDir,
	}
}

// Compile transforms the policy model into an nftables artifact.
// The artifact contains both the human-readable text (for DryRun/logging)
// and the compiled netlink data (for Apply).
func (b *NftablesBackend) Compile(input *compiler.Input) (*Artifact, error) {
	// Use the existing compiler to generate the text representation.
	// This is the same compiler that was used with the old nft -f approach.
	ruleset, err := compiler.Compile(input)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(ruleset.Text)))

	return &Artifact{
		Text:      ruleset.Text,
		Data:      input, // Store the input for netlink-based apply.
		Checksum:  checksum,
		CreatedAt: time.Now(),
	}, nil
}

// Apply atomically installs the compiled artifact using netlink.
func (b *NftablesBackend) Apply(artifact *Artifact) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Write human-readable ruleset for audit trail.
	if b.rulesetDir != "" {
		if err := b.writeRulesetFile(artifact); err != nil {
			slog.Warn("failed to write ruleset file", "error", err)
		}
	}

	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables netlink connection: %w", err)
	}
	defer conn.CloseLasting()

	// Delete existing gatekeeper table if present.
	// This is safe — we're about to recreate it atomically.
	tables, err := conn.ListTables()
	if err == nil {
		for _, t := range tables {
			if t.Name == "gatekeeper" {
				conn.DelTable(t)
			}
		}
	}

	// Create the gatekeeper table in inet (dual-stack) family.
	table := conn.AddTable(&nft.Table{
		Family: nft.TableFamilyINet,
		Name:   "gatekeeper",
	})

	// Get the input from the artifact.
	input, ok := artifact.Data.(*compiler.Input)
	if !ok {
		return fmt.Errorf("artifact data is not *compiler.Input")
	}

	// Build the chains and rules.
	if err := b.buildInputChain(conn, table, input); err != nil {
		return fmt.Errorf("build input chain: %w", err)
	}

	if err := b.buildForwardChain(conn, table, input); err != nil {
		return fmt.Errorf("build forward chain: %w", err)
	}

	if err := b.buildPostroutingChain(conn, table, input); err != nil {
		return fmt.Errorf("build postrouting chain: %w", err)
	}

	// Flush: atomic commit of all changes.
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush (atomic commit): %w", err)
	}

	slog.Info("nftables ruleset applied via netlink", "checksum", artifact.Checksum)
	b.lastApply = artifact
	return nil
}

// Verify checks that the gatekeeper table exists in the kernel.
func (b *NftablesBackend) Verify(artifact *Artifact) (bool, []Drift, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	conn, err := nft.New()
	if err != nil {
		return false, nil, fmt.Errorf("netlink connection: %w", err)
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return false, nil, fmt.Errorf("list tables: %w", err)
	}

	var found bool
	for _, t := range tables {
		if t.Name == "gatekeeper" && t.Family == nft.TableFamilyINet {
			found = true
			break
		}
	}

	if !found {
		return false, []Drift{{
			Type:     DriftMissing,
			Resource: "table inet gatekeeper",
			Expected: "present",
			Actual:   "",
		}}, nil
	}

	// Verify chains exist.
	var drifts []Drift
	table := &nft.Table{Family: nft.TableFamilyINet, Name: "gatekeeper"}
	chains, err := conn.ListChainsOfTableFamily(nft.TableFamilyINet)
	if err != nil {
		return false, nil, fmt.Errorf("list chains: %w", err)
	}

	expectedChains := map[string]bool{"input": false, "forward": false, "postrouting": false}
	for _, c := range chains {
		if c.Table.Name == table.Name {
			if _, ok := expectedChains[c.Name]; ok {
				expectedChains[c.Name] = true
			}
		}
	}

	for name, found := range expectedChains {
		if !found {
			drifts = append(drifts, Drift{
				Type:     DriftMissing,
				Resource: "chain " + name,
				Expected: "present",
			})
		}
	}

	if len(drifts) > 0 {
		return false, drifts, nil
	}

	slog.Info("post-apply verification passed (netlink)")
	return true, nil, nil
}

// Rollback reverts to a previously-compiled artifact.
func (b *NftablesBackend) Rollback(previous *Artifact) error {
	return b.Apply(previous)
}

// DryRun returns the human-readable ruleset without applying.
func (b *NftablesBackend) DryRun(input *compiler.Input) (string, error) {
	artifact, err := b.Compile(input)
	if err != nil {
		return "", err
	}
	return artifact.Text, nil
}

// Capabilities reports nftables feature support.
func (b *NftablesBackend) Capabilities() BackendCaps {
	version := "unknown"
	// Try to read kernel nftables version from /proc.
	if data, err := os.ReadFile("/proc/version"); err == nil {
		version = strings.Fields(string(data))[2] // kernel version
	}

	return BackendCaps{
		Name:            "nftables",
		Version:         version,
		Sets:            true,
		IncrementalSets: true,
		Flowtables:      true,
		AtomicReplace:   true,
		NAT:             true,
		IPv6:            true,
		Conntrack:       true,
		HardwareOffload: false, // Detected at runtime.
	}
}

// AddToSet adds a member to a named nftables set.
func (b *NftablesBackend) AddToSet(setName string, member string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer conn.CloseLasting()

	table := &nft.Table{Family: nft.TableFamilyINet, Name: "gatekeeper"}
	set, err := conn.GetSetByName(table, setName)
	if err != nil {
		return fmt.Errorf("get set %s: %w", setName, err)
	}

	element, err := parseSetElement(member, set.KeyType)
	if err != nil {
		return fmt.Errorf("parse element %q: %w", member, err)
	}

	if err := conn.SetAddElements(set, []nft.SetElement{element}); err != nil {
		return fmt.Errorf("add to set %s: %w", setName, err)
	}

	return conn.Flush()
}

// RemoveFromSet removes a member from a named nftables set.
func (b *NftablesBackend) RemoveFromSet(setName string, member string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer conn.CloseLasting()

	table := &nft.Table{Family: nft.TableFamilyINet, Name: "gatekeeper"}
	set, err := conn.GetSetByName(table, setName)
	if err != nil {
		return fmt.Errorf("get set %s: %w", setName, err)
	}

	element, err := parseSetElement(member, set.KeyType)
	if err != nil {
		return fmt.Errorf("parse element %q: %w", member, err)
	}

	if err := conn.SetDeleteElements(set, []nft.SetElement{element}); err != nil {
		return fmt.Errorf("remove from set %s: %w", setName, err)
	}

	return conn.Flush()
}

// FlushSet removes all members from a named nftables set.
func (b *NftablesBackend) FlushSet(setName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer conn.CloseLasting()

	table := &nft.Table{Family: nft.TableFamilyINet, Name: "gatekeeper"}
	set, err := conn.GetSetByName(table, setName)
	if err != nil {
		return fmt.Errorf("get set %s: %w", setName, err)
	}

	conn.FlushSet(set)
	return conn.Flush()
}

// writeRulesetFile writes the human-readable ruleset to disk for audit.
func (b *NftablesBackend) writeRulesetFile(artifact *Artifact) error {
	if err := os.MkdirAll(b.rulesetDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(b.rulesetDir, "gatekeeper.nft")
	return os.WriteFile(path, []byte(artifact.Text), 0o640)
}

// buildInputChain creates the input chain with standard Gatekeeper rules.
func (b *NftablesBackend) buildInputChain(conn *nft.Conn, table *nft.Table, input *compiler.Input) error {
	policy := nft.ChainPolicyDrop
	chain := conn.AddChain(&nft.Chain{
		Name:     "input",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookInput,
		Priority: nft.ChainPriorityFilter,
		Policy:   &policy,
	})

	// ct state established,related accept
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // established | related
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// ct state invalid drop
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x01, 0x00, 0x00, 0x00}, // invalid
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// iif lo accept
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("lo"),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// ip protocol icmp accept
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x02}, // NFPROTO_IPV4
			},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{1}, // IPPROTO_ICMP
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Per-zone: allow API (8080), DHCP (67), DNS (53) on LAN interfaces.
	for _, z := range input.Zones {
		if z.Name == "wan" || z.Interface == "" {
			continue
		}

		// Allow TCP 8080 (API) from this zone.
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(z.Interface)},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2, // destination port
					Len:          2,
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(8080)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})

		// Allow UDP 53 (DNS) and 67 (DHCP).
		for _, port := range []uint16{53, 67} {
			conn.AddRule(&nft.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(z.Interface)},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(port)},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}

		// Allow TCP 53 (DNS over TCP).
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(z.Interface)},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(53)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	// Allow WireGuard if configured.
	if input.WGListenPort > 0 {
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(uint16(input.WGListenPort))},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	return nil
}

// buildForwardChain creates the forward chain with zone policy rules.
func (b *NftablesBackend) buildForwardChain(conn *nft.Conn, table *nft.Table, input *compiler.Input) error {
	policy := nft.ChainPolicyDrop
	chain := conn.AddChain(&nft.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookForward,
		Priority: nft.ChainPriorityFilter,
		Policy:   &policy,
	})

	// ct state established,related accept
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00},
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// ct state invalid drop
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x01, 0x00, 0x00, 0x00},
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Build zone lookup by ID — O(1) instead of nested loop.
	zoneByID := make(map[int64]*model.Zone, len(input.Zones))
	for i := range input.Zones {
		zoneByID[input.Zones[i].ID] = &input.Zones[i]
	}

	// Build policy lookup (name → full Policy with Rules).
	policyByName := make(map[string]*model.Policy, len(input.Policies))
	for i := range input.Policies {
		policyByName[input.Policies[i].Name] = &input.Policies[i]
	}

	// C1 fix: Per-zone/profile forward rules — iterate individual policy rules,
	// not just the default action. Mirrors the text compiler's writeForwardChain().
	wanIface := ""
	for _, z := range input.Zones {
		if z.Name == "wan" && z.Interface != "" {
			wanIface = z.Interface
			break
		}
	}

	for _, zone := range input.Zones {
		if zone.Name == "wan" || zone.Interface == "" {
			continue
		}
		// Find profiles for this zone.
		for _, profile := range input.Profiles {
			if profile.ZoneID != zone.ID {
				continue
			}
			policy, ok := policyByName[profile.PolicyName]
			if !ok || policy == nil {
				continue
			}

			// Emit each rule in the policy.
			for _, rule := range policy.Rules {
				ruleExprs := b.compileRuleExprs(rule, zone.Interface, wanIface)
				if len(ruleExprs) > 0 {
					conn.AddRule(&nft.Rule{
						Table: table,
						Chain: chain,
						Exprs: ruleExprs,
					})
				}
			}

			// Default action for unmatched traffic from this zone.
			switch policy.DefaultAction {
			case model.RuleActionAllow:
				conn.AddRule(&nft.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{
						&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(zone.Interface)},
						&expr.Verdict{Kind: expr.VerdictAccept},
					},
				})
			case model.RuleActionReject:
				conn.AddRule(&nft.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{
						&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(zone.Interface)},
						&expr.Verdict{Kind: expr.VerdictDrop}, // netlink has no reject verdict; drop is safest
					},
				})
			}
			// deny = chain default (drop), no explicit rule needed.
		}
	}

	return nil
}

// buildPostroutingChain creates the NAT postrouting chain.
func (b *NftablesBackend) buildPostroutingChain(conn *nft.Conn, table *nft.Table, input *compiler.Input) error {
	policy := nft.ChainPolicyAccept
	chain := conn.AddChain(&nft.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nft.ChainTypeNAT,
		Hooknum:  nft.ChainHookPostrouting,
		Priority: nft.ChainPriorityNATSource,
		Policy:   &policy,
	})

	// Find WAN interface for masquerade.
	for _, z := range input.Zones {
		if z.Name == "wan" && z.Interface != "" {
			// oifname <wan> masquerade
			conn.AddRule(&nft.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(z.Interface)},
					&expr.Masq{},
				},
			})
			break
		}
	}

	return nil
}

// compileRuleExprs converts a model.Rule into nftables netlink expressions.
// Mirrors the text compiler's compileRule() function.
func (b *NftablesBackend) compileRuleExprs(r model.Rule, srcIface, wanIface string) []expr.Any {
	var exprs []expr.Any

	// Match source interface.
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(srcIface)},
	)

	// Match output interface (WAN) if available.
	if wanIface != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(wanIface)},
		)
	}

	// Protocol matching.
	proto := strings.ToLower(r.Protocol)
	switch proto {
	case "tcp":
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		)
		if r.Ports != "" {
			if portExprs := b.compilePortMatch(r.Ports); len(portExprs) > 0 {
				exprs = append(exprs, portExprs...)
			}
		}
	case "udp":
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
		)
		if r.Ports != "" {
			if portExprs := b.compilePortMatch(r.Ports); len(portExprs) > 0 {
				exprs = append(exprs, portExprs...)
			}
		}
	case "icmp":
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		)
	case "":
		// No protocol filter — match all.
	default:
		return nil // Unsupported protocol, skip rule.
	}

	// Verdict.
	if !model.ValidActions[r.Action] {
		return nil
	}
	switch r.Action {
	case model.RuleActionAllow:
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	case model.RuleActionDeny:
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	case model.RuleActionReject:
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop}) // netlink: drop as fallback
	case model.RuleActionLog:
		exprs = append(exprs, &expr.Log{Key: 0}) // log and continue
	}

	return exprs
}

// compilePortMatch builds nftables expressions matching a destination port.
// Supports single port or first port from comma-separated list.
func (b *NftablesBackend) compilePortMatch(ports string) []expr.Any {
	// Parse first port (multi-port requires anonymous sets — future enhancement).
	portStr := strings.Split(ports, ",")[0]
	portStr = strings.TrimSpace(portStr)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // Destination port offset.
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(uint16(port))},
	}
}

// ifname converts a string interface name to the 16-byte padded format
// expected by nftables netlink.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name+"\x00")
	return b
}

// binaryPort converts a port number to network byte order (big-endian).
func binaryPort(port uint16) []byte {
	return []byte{byte(port >> 8), byte(port & 0xff)}
}

// parseSetElement converts a string member into an nftables set element.
func parseSetElement(member string, keyType nft.SetDatatype) (nft.SetElement, error) {
	// Try IPv4 via stdlib net.ParseIP.
	if ip := net.ParseIP(member); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return nft.SetElement{Key: []byte(v4)}, nil
		}
	}

	// Generic: use raw bytes.
	return nft.SetElement{Key: []byte(member)}, nil
}
