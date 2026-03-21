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
	conn       *nft.Conn // Persistent netlink connection (M-BA7).
}

// NewNftablesBackend creates a new nftables backend.
func NewNftablesBackend(rulesetDir string) *NftablesBackend {
	return &NftablesBackend{
		rulesetDir: rulesetDir,
	}
}

// getConn returns the persistent netlink connection, creating one if needed.
// Caller must hold b.mu.
func (b *NftablesBackend) getConn() (*nft.Conn, error) {
	if b.conn != nil {
		return b.conn, nil
	}
	conn, err := nft.New()
	if err != nil {
		return nil, fmt.Errorf("nftables netlink connection: %w", err)
	}
	b.conn = conn
	return conn, nil
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

	conn, err := b.getConn()
	if err != nil {
		return err
	}

	// Delete existing gatekeeper table if present.
	// This is safe — we're about to recreate it atomically.
	tables, err := conn.ListTables()
	if err == nil {
		for _, t := range tables {
			if t.Name == model.NFTablesTableName {
				conn.DelTable(t)
			}
		}
	}

	// Create the gatekeeper table in inet (dual-stack) family.
	table := conn.AddTable(&nft.Table{
		Family: nft.TableFamilyINet,
		Name:   model.NFTablesTableName,
	})

	// Get the input from the artifact.
	input, ok := artifact.Data.(*compiler.Input)
	if !ok {
		return fmt.Errorf("artifact data is not *compiler.Input")
	}

	// Anti-spoof set: RFC1918 + bogon ranges.
	if err := b.buildBogonSet(conn, table); err != nil {
		slog.Warn("failed to build bogon set", "error", err)
	}

	// Build alias sets so rules referencing SrcAlias/DstAlias can match.
	aliasSets := b.buildAliasSets(conn, table, input)

	// Build the chains and rules.
	if err := b.buildInputChain(conn, table, input); err != nil {
		return fmt.Errorf("build input chain: %w", err)
	}

	if err := b.buildForwardChain(conn, table, input, aliasSets); err != nil {
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

	conn, err := b.getConn()
	if err != nil {
		return false, nil, err
	}

	tables, err := conn.ListTables()
	if err != nil {
		return false, nil, fmt.Errorf("list tables: %w", err)
	}

	var found bool
	for _, t := range tables {
		if t.Name == model.NFTablesTableName && t.Family == nft.TableFamilyINet {
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
	table := &nft.Table{Family: nft.TableFamilyINet, Name: model.NFTablesTableName}
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

	conn, err := b.getConn()
	if err != nil {
		return err
	}

	table := &nft.Table{Family: nft.TableFamilyINet, Name: model.NFTablesTableName}
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

	conn, err := b.getConn()
	if err != nil {
		return err
	}

	table := &nft.Table{Family: nft.TableFamilyINet, Name: model.NFTablesTableName}
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

	conn, err := b.getConn()
	if err != nil {
		return err
	}

	table := &nft.Table{Family: nft.TableFamilyINet, Name: model.NFTablesTableName}
	set, err := conn.GetSetByName(table, setName)
	if err != nil {
		return fmt.Errorf("get set %s: %w", setName, err)
	}

	conn.FlushSet(set)
	return conn.Flush()
}

// EmergencyFlush deletes the entire gatekeeper table from nftables.
// This is a last resort when rollback + re-apply both fail, to prevent
// lockout with broken rules. The system enters a permissive state.
func (b *NftablesBackend) EmergencyFlush() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	conn, err := b.getConn()
	if err != nil {
		return fmt.Errorf("emergency flush: connect: %w", err)
	}

	conn.DelTable(&nft.Table{Family: nft.TableFamilyINet, Name: model.NFTablesTableName})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("emergency flush: %w", err)
	}
	slog.Warn("emergency flush: deleted inet gatekeeper table")
	return nil
}

// writeRulesetFile writes the human-readable ruleset to disk for audit.
func (b *NftablesBackend) writeRulesetFile(artifact *Artifact) error {
	if err := os.MkdirAll(b.rulesetDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(b.rulesetDir, "gatekeeper.nft")
	return os.WriteFile(path, []byte(artifact.Text), 0o640)
}

// buildAliasSets creates nftables sets for each alias in the input.
// Returns a map from alias name to the created *nft.Set for use in rules.
func (b *NftablesBackend) buildAliasSets(conn *nft.Conn, table *nft.Table, input *compiler.Input) map[string]*nft.Set {
	aliasMap := make(map[string]*model.Alias, len(input.Aliases))
	for i := range input.Aliases {
		aliasMap[input.Aliases[i].Name] = &input.Aliases[i]
	}

	sets := make(map[string]*nft.Set)
	for _, a := range input.Aliases {
		members := resolveAliasMembers(&a, aliasMap, 0)
		if len(members) == 0 {
			continue
		}
		setName := model.SanitizeName(a.Name)
		set := &nft.Set{Table: table, Name: setName}
		var elems []nft.SetElement

		switch a.Type {
		case model.AliasTypeHost:
			set.KeyType = nft.TypeIPAddr
			for _, m := range members {
				ip := net.ParseIP(m)
				if ip != nil {
					elems = append(elems, nft.SetElement{Key: ip.To4()})
				}
			}
		case model.AliasTypeNetwork:
			set.KeyType = nft.TypeIPAddr
			set.Interval = true
			for _, m := range members {
				_, ipnet, err := net.ParseCIDR(m)
				if err != nil {
					continue
				}
				start := ipnet.IP.To4()
				end := cidrEnd(ipnet)
				elems = append(elems,
					nft.SetElement{Key: start},
					nft.SetElement{Key: end, IntervalEnd: true},
				)
			}
		default:
			continue // Port/MAC aliases not used in forward chain src/dst matching.
		}

		if len(elems) == 0 {
			continue
		}
		if err := conn.AddSet(set, elems); err != nil {
			slog.Warn("failed to add alias set", "name", setName, "error", err)
			continue
		}
		sets[a.Name] = set
	}
	return sets
}

// resolveAliasMembers recursively resolves alias members with depth limit,
// deduplication, and 10K expansion cap. Mirrors the compiler's implementation.
func resolveAliasMembers(a *model.Alias, aliasMap map[string]*model.Alias, depth int) []string {
	seen := make(map[string]struct{})
	return resolveAliasMembersDedup(a, aliasMap, depth, seen)
}

func resolveAliasMembersDedup(a *model.Alias, aliasMap map[string]*model.Alias, depth int, seen map[string]struct{}) []string {
	if depth > 10 {
		return nil
	}
	if a.Type != model.AliasTypeNested {
		result := make([]string, 0, len(a.Members))
		for _, m := range a.Members {
			if _, dup := seen[m]; !dup {
				seen[m] = struct{}{}
				result = append(result, m)
			}
		}
		return result
	}
	var resolved []string
	for _, name := range a.Members {
		nested, ok := aliasMap[name]
		if !ok {
			continue
		}
		resolved = append(resolved, resolveAliasMembersDedup(nested, aliasMap, depth+1, seen)...)
		if len(resolved) > 10000 {
			return resolved[:10000]
		}
	}
	return resolved
}

// buildBogonSet creates the anti-spoof set with RFC1918 and bogon CIDR ranges.
func (b *NftablesBackend) buildBogonSet(conn *nft.Conn, table *nft.Table) error {
	bogons := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
		"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
		"240.0.0.0/4",
	}

	set := &nft.Set{
		Table:    table,
		Name:     "bogons",
		KeyType:  nft.TypeIPAddr,
		Interval: true,
	}
	elems := make([]nft.SetElement, 0, len(bogons)*2)
	for _, cidr := range bogons {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		start := ipnet.IP.To4()
		end := cidrEnd(ipnet)
		elems = append(elems,
			nft.SetElement{Key: start},
			nft.SetElement{Key: end, IntervalEnd: true},
		)
	}
	return conn.AddSet(set, elems)
}

// cidrEnd computes the first address past the CIDR range (exclusive end for interval set).
func cidrEnd(ipnet *net.IPNet) []byte {
	ip := ipnet.IP.To4()
	mask := ipnet.Mask
	end := make([]byte, 4)
	for i := range ip {
		end[i] = ip[i] | ^mask[i]
	}
	for i := 3; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			break
		}
	}
	return end
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

	// Allow only safe ICMP types: echo-reply(0), dest-unreachable(3),
	// echo-request(8), time-exceeded(11).
	for _, icmpType := range []byte{0, 3, 8, 11} {
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}}, // NFPROTO_IPV4
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // IPPROTO_ICMP
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, // ICMP type field
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmpType}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	// Allow management API from all interfaces.
	// The API enforces its own authentication (API key / RBAC),
	// so the firewall must not block the management plane.
	if input.APIPort > 0 {
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2, // destination port
					Len:          2,
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(uint16(input.APIPort))},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	// Per-zone: allow DHCP (67), DNS (53) on LAN interfaces.
	for _, z := range input.Zones {
		if z.Name == "wan" || z.Interface == "" {
			continue
		}

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
func (b *NftablesBackend) buildForwardChain(conn *nft.Conn, table *nft.Table, input *compiler.Input, aliasSets map[string]*nft.Set) error {
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

	// Anti-spoof: drop packets from WAN with bogon source addresses.
	if wanIface != "" {
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(wanIface)},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Lookup{SourceRegister: 1, SetName: "bogons"},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
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

			// Emit each rule in the policy (multi-port rules expand to one nft rule per port).
			for _, rule := range policy.Rules {
				for _, ruleExprs := range b.compileRuleExprsList(rule, zone.Interface, wanIface, aliasSets) {
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

// compileRuleExprsList converts a model.Rule into one or more nftables netlink
// expression slices. Multi-port rules (e.g. "80,443") expand to one nft rule
// per port — this is the correct netlink approach without anonymous sets.
func (b *NftablesBackend) compileRuleExprsList(r model.Rule, srcIface, wanIface string, aliasSets map[string]*nft.Set) [][]expr.Any {
	// Build the common prefix: interface match + optional WAN output.
	var prefix []expr.Any
	prefix = append(prefix,
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(srcIface)},
	)
	if wanIface != "" {
		prefix = append(prefix,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(wanIface)},
		)
	}

	// Source alias set lookup.
	if r.SrcAlias != "" {
		if set, ok := aliasSets[r.SrcAlias]; ok {
			prefix = append(prefix,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			)
		}
	}
	// Destination alias set lookup.
	if r.DstAlias != "" {
		if set, ok := aliasSets[r.DstAlias]; ok {
			prefix = append(prefix,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			)
		}
	}

	// Build the verdict suffix.
	if !model.ValidActions[r.Action] {
		return nil
	}
	var verdict []expr.Any
	switch r.Action {
	case model.RuleActionAllow:
		verdict = []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	case model.RuleActionDeny:
		verdict = []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	case model.RuleActionReject:
		verdict = []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	case model.RuleActionLog:
		verdict = []expr.Any{&expr.Log{Key: 0}}
	}

	// Protocol and port matching.
	proto := strings.ToLower(r.Protocol)
	var protoByte byte
	switch proto {
	case "tcp":
		protoByte = 6
	case "udp":
		protoByte = 17
	case "icmp":
		protoByte = 1
	case "":
		// No protocol — single rule, no port matching.
		rule := make([]expr.Any, 0, len(prefix)+len(verdict))
		rule = append(rule, prefix...)
		rule = append(rule, verdict...)
		return [][]expr.Any{rule}
	default:
		return nil
	}

	protoMatch := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoByte}},
	}

	// If no ports or ICMP, emit a single rule.
	if r.Ports == "" || proto == "icmp" {
		rule := make([]expr.Any, 0, len(prefix)+len(protoMatch)+len(verdict))
		rule = append(rule, prefix...)
		rule = append(rule, protoMatch...)
		rule = append(rule, verdict...)
		return [][]expr.Any{rule}
	}

	// Multi-port: emit one rule per port.
	ports := parsePortList(r.Ports)
	if len(ports) == 0 {
		rule := make([]expr.Any, 0, len(prefix)+len(protoMatch)+len(verdict))
		rule = append(rule, prefix...)
		rule = append(rule, protoMatch...)
		rule = append(rule, verdict...)
		return [][]expr.Any{rule}
	}

	rules := make([][]expr.Any, 0, len(ports))
	for _, port := range ports {
		portMatch := []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryPort(port)},
		}
		rule := make([]expr.Any, 0, len(prefix)+len(protoMatch)+len(portMatch)+len(verdict))
		rule = append(rule, prefix...)
		rule = append(rule, protoMatch...)
		rule = append(rule, portMatch...)
		rule = append(rule, verdict...)
		rules = append(rules, rule)
	}
	return rules
}

// parsePortList parses a comma-separated port string into port numbers.
func parsePortList(ports string) []uint16 {
	parts := strings.Split(ports, ",")
	result := make([]uint16, 0, len(parts))
	for _, s := range parts {
		s = strings.TrimSpace(s)
		port, err := strconv.ParseUint(s, 10, 16)
		if err == nil && port > 0 {
			result = append(result, uint16(port))
		}
	}
	return result
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
