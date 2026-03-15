package service

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

// Common MTU values for reference:
//
//	1500  - Standard Ethernet
//	9000  - Jumbo frames (common in datacenter/Proxmox internal networks)
//	9216  - Baby jumbo (some switch vendors)
//	1450  - VXLAN overlay on 1500 physical (50-byte VXLAN header overhead)
//	1400  - GENEVE overlay (54-byte header overhead)
//	1420  - WireGuard tunnel on 1500 physical (80-byte overhead)
//	1280  - IPv6 minimum MTU
//	8950  - VXLAN overlay on 9000 physical
const (
	MTUStandard    = 1500
	MTUJumbo       = 9000
	MTUBabyJumbo   = 9216
	MTUVXLAN1500   = 1450 // 1500 - 50 (VXLAN overhead)
	MTUGENEVE1500  = 1400 // 1500 - 54 (GENEVE + options) - conservative
	MTUWireGuard   = 1420 // 1500 - 80 (WireGuard overhead)
	MTUIPv6Min     = 1280
	MTUVXLAN9000   = 8950 // 9000 - 50 (VXLAN on jumbo)
	OverheadVXLAN  = 50   // 8 VXLAN + 8 UDP + 20 IP + 14 Ethernet
	OverheadGENEVE = 54   // 8 GENEVE base + 12 options + 8 UDP + 20 IP + 14 Ethernet (conservative)
	OverheadWG     = 80   // WireGuard overhead
)

// MTUManager handles MTU configuration, TCP MSS clamping, Path MTU Discovery
// tuning, and MTU mismatch detection across zones.
//
// Why this matters in virtualized/Proxmox environments:
//
//  1. Proxmox internal bridges (vmbr1+) can use jumbo frames (9000 MTU)
//     for VM-to-VM and storage traffic, but the WAN interface stays at 1500.
//     Without MSS clamping, TCP connections crossing zone boundaries with
//     different MTUs will experience silent packet drops ("MTU blackholes").
//
//  2. VXLAN overlays (used by Proxmox SDN) add 50 bytes of encapsulation.
//     The inner MTU must be reduced accordingly or packets fragment/drop.
//
//  3. GRO/GSO offloads (already managed by PerformanceTuner) aggregate
//     packets into super-frames internally. This is fine — the kernel handles
//     re-segmentation on egress. But nftables rate-limit rules that assume
//     1500-byte packets will miscalculate packet rates when the real MTU
//     is 9000 (jumbo) or 1450 (overlay).
type MTUManager struct {
	mu    sync.Mutex
	state State
	cfg   map[string]string
}

func NewMTUManager() *MTUManager {
	return &MTUManager{state: StateStopped}
}

func (m *MTUManager) Name() string           { return "mtu-manager" }
func (m *MTUManager) DisplayName() string    { return "MTU Manager" }
func (m *MTUManager) Category() string       { return "network" }
func (m *MTUManager) Dependencies() []string { return nil }

func (m *MTUManager) Description() string {
	return "MTU management for inter-zone traffic. Handles jumbo frames, " +
		"TCP MSS clamping, PMTUD tuning, overlay MTU adjustment (VXLAN/GENEVE), " +
		"and MTU mismatch detection between zones."
}

func (m *MTUManager) DefaultConfig() map[string]string {
	return map[string]string{
		"mss_clamping":       "true", // Clamp TCP MSS on forwarded traffic
		"mss_clamp_to_pmtu":  "true", // Use PMTU-based MSS (recommended)
		"mss_clamp_value":    "0",    // Manual MSS value (0 = auto from PMTU)
		"pmtud":              "true", // Enable Path MTU Discovery sysctls
		"zone_mtu_enforce":   "true", // Apply per-zone MTU to interfaces via netlink
		"overlay_adjustment": "",     // "vxlan", "geneve", "wireguard", or empty
		"mtu_mismatch_log":   "true", // Log warnings when zone MTUs don't match
	}
}

func (m *MTUManager) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mss_clamping":       {Description: "Enable TCP MSS clamping in nftables forward chain", Default: "true", Type: "bool"},
		"mss_clamp_to_pmtu":  {Description: "Clamp MSS to path MTU (recommended for mixed-MTU zones)", Default: "true", Type: "bool"},
		"mss_clamp_value":    {Description: "Manual MSS clamp value in bytes (0 = auto from PMTU)", Default: "0", Type: "int"},
		"pmtud":              {Description: "Tune PMTUD sysctls for reliable path MTU discovery", Default: "true", Type: "bool"},
		"zone_mtu_enforce":   {Description: "Apply configured zone MTU to interfaces via netlink", Default: "true", Type: "bool"},
		"overlay_adjustment": {Description: "Auto-adjust inner MTU for overlay type: vxlan, geneve, wireguard, or empty", Type: "string"},
		"mtu_mismatch_log":   {Description: "Log warnings when forwarding between zones with different MTUs", Default: "true", Type: "bool"},
	}
}

func (m *MTUManager) Validate(cfg map[string]string) error {
	if v := cfg["mss_clamp_value"]; v != "" && v != "0" {
		mss, err := strconv.Atoi(v)
		if err != nil || mss < 536 || mss > 65535 {
			return fmt.Errorf("mss_clamp_value must be 0 (auto) or 536-65535, got %s", v)
		}
	}
	overlay := cfg["overlay_adjustment"]
	if overlay != "" && overlay != "vxlan" && overlay != "geneve" && overlay != "wireguard" {
		return fmt.Errorf("overlay_adjustment must be empty, vxlan, geneve, or wireguard")
	}
	return nil
}

func (m *MTUManager) Start(cfg map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg

	if cfg["pmtud"] == "true" {
		m.tunePMTUD()
	}

	if cfg["mss_clamping"] == "true" {
		if err := m.applyMSSClamping(cfg); err != nil {
			slog.Warn("MSS clamping failed", "error", err)
		}
	}

	m.state = StateRunning
	slog.Info("mtu manager started")
	return nil
}

func (m *MTUManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nftDeleteTable(nft.TableFamilyINet, "gk_mtu")
	m.state = StateStopped
	slog.Info("mtu manager stopped")
	return nil
}

func (m *MTUManager) Reload(cfg map[string]string) error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start(cfg)
}

func (m *MTUManager) Status() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// ApplyZoneMTUs sets the MTU on each zone's interface and detects mismatches.
// Called by the daemon after zones are loaded from the database.
func (m *MTUManager) ApplyZoneMTUs(zones []model.Zone) []MTUDiagnostic {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	var diags []MTUDiagnostic
	overlay := ""
	if cfg != nil {
		overlay = cfg["overlay_adjustment"]
	}

	for _, z := range zones {
		if z.Interface == "" {
			continue
		}

		targetMTU := z.MTU
		if targetMTU == 0 {
			continue // No explicit MTU configured for this zone; leave as-is.
		}

		// Adjust for overlay overhead if configured.
		if overlay != "" {
			overhead := overlayOverhead(overlay)
			if overhead > 0 && targetMTU > overhead {
				adjusted := targetMTU - overhead
				slog.Info("overlay MTU adjustment",
					"zone", z.Name, "iface", z.Interface,
					"configured_mtu", targetMTU, "overlay", overlay,
					"overhead", overhead, "effective_mtu", adjusted)
				targetMTU = adjusted
			}
		}

		if cfg != nil && cfg["zone_mtu_enforce"] == "true" {
			if err := Net.LinkSetMTU(z.Interface, targetMTU); err != nil {
				slog.Warn("failed to set zone MTU", "zone", z.Name,
					"iface", z.Interface, "mtu", targetMTU, "error", err)
				diags = append(diags, MTUDiagnostic{
					Zone:      z.Name,
					Interface: z.Interface,
					Severity:  "error",
					Message:   fmt.Sprintf("failed to set MTU %d: %v", targetMTU, err),
				})
			} else {
				slog.Info("zone MTU set", "zone", z.Name,
					"iface", z.Interface, "mtu", targetMTU)
			}
		}
	}

	// Detect MTU mismatches between zones.
	if cfg != nil && cfg["mtu_mismatch_log"] == "true" {
		diags = append(diags, m.detectMismatches(zones)...)
	}

	return diags
}

// detectMismatches finds zones with different effective MTUs that can
// forward traffic to each other, which risks silent packet drops.
func (m *MTUManager) detectMismatches(zones []model.Zone) []MTUDiagnostic {
	var diags []MTUDiagnostic

	type zoneMTU struct {
		name string
		mtu  int
	}

	var withMTU []zoneMTU
	for _, z := range zones {
		if z.Interface == "" {
			continue
		}
		effectiveMTU := z.MTU
		if effectiveMTU == 0 {
			// Read actual MTU from interface.
			actual, err := Net.LinkGetMTU(z.Interface)
			if err != nil {
				continue
			}
			effectiveMTU = actual
		}
		withMTU = append(withMTU, zoneMTU{name: z.Name, mtu: effectiveMTU})
	}

	// Compare all pairs.
	for i := 0; i < len(withMTU); i++ {
		for j := i + 1; j < len(withMTU); j++ {
			a, b := withMTU[i], withMTU[j]
			if a.mtu != b.mtu {
				msg := fmt.Sprintf("MTU mismatch: zone %s (%d) vs zone %s (%d) — "+
					"TCP MSS clamping is critical to prevent packet blackholes",
					a.name, a.mtu, b.name, b.mtu)
				slog.Warn(msg)
				diags = append(diags, MTUDiagnostic{
					Zone:     a.name + "/" + b.name,
					Severity: "warning",
					Message:  msg,
				})
			}
		}
	}

	return diags
}

// tunePMTUD applies kernel sysctls for reliable Path MTU Discovery.
func (m *MTUManager) tunePMTUD() {
	tunings := []struct{ key, val string }{
		// Enable PMTUD: the kernel sends "don't fragment" and learns the path MTU
		// from ICMP "fragmentation needed" responses. Essential for jumbo frames.
		{"net.ipv4.ip_no_pmtu_disc", "0"},
		// Enable MTU probing: if PMTUD blackholes are detected (ICMP blocked),
		// the kernel falls back to probing with progressively smaller packets.
		{"net.ipv4.tcp_mtu_probing", "1"},
		// Start probing from the interface MTU rather than a low default.
		// Probing ramps down from this value when blackholes are detected.
		{"net.ipv4.tcp_base_mss", "1024"},
		// Minimum MSS the kernel will accept. 536 is the TCP standard minimum.
		{"net.ipv4.tcp_min_snd_mss", "536"},
	}

	for _, t := range tunings {
		if err := Net.SysctlSet(t.key, t.val); err != nil {
			slog.Warn("PMTUD sysctl failed", "key", t.key, "error", err)
		} else {
			slog.Debug("PMTUD sysctl applied", "key", t.key, "val", t.val)
		}
	}

	slog.Info("PMTUD tuning applied")
}

// applyMSSClamping installs nftables rules to clamp TCP MSS on all
// forwarded traffic. This prevents packet blackholes when traffic crosses
// between zones with different MTUs (e.g., jumbo frame LAN → 1500 WAN,
// or Proxmox VXLAN overlay → physical network).
//
// Equivalent nftables text:
//
//	table inet gk_mtu {
//	    chain forward {
//	        type filter hook forward priority mangle;
//	        tcp flags syn / syn,rst tcp option maxseg size set rt mtu
//	    }
//	}
func (m *MTUManager) applyMSSClamping(cfg map[string]string) error {
	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables connection: %w", err)
	}

	// Clean up any previous gk_mtu table.
	conn.DelTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gk_mtu"})
	conn.Flush() //nolint:errcheck

	conn, err = nft.New()
	if err != nil {
		return fmt.Errorf("nftables reconnect: %w", err)
	}

	table := conn.AddTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gk_mtu"})

	// Forward chain at mangle priority — runs after routing decision
	// but before the packet leaves, so we can modify the MSS.
	prio := nft.ChainPriorityMangle
	chain := conn.AddChain(&nft.Chain{
		Table:    table,
		Name:     "forward",
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookForward,
		Priority: prio,
	})

	// Build the MSS clamping rule.
	// Match: tcp flags syn / syn,rst  (SYN packets only)
	// Action: tcp option maxseg size set <value>
	ruleExprs := mssClampRule(cfg)

	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: ruleExprs,
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush (MSS clamping): %w", err)
	}

	if cfg["mss_clamp_to_pmtu"] == "true" {
		slog.Info("MSS clamping enabled (clamp to PMTU)")
	} else {
		slog.Info("MSS clamping enabled", "mss_value", cfg["mss_clamp_value"])
	}
	return nil
}

// mssClampRule builds the nftables expressions for TCP MSS clamping.
//
// This matches TCP SYN packets (the only packets that carry the MSS option)
// and rewrites the MSS to either the path MTU (recommended) or a fixed value.
func mssClampRule(cfg map[string]string) []expr.Any {
	// Match TCP protocol.
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP
	}

	// Match SYN flag (tcp flags & (syn|rst) == syn).
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13, // TCP flags byte
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x06}, // SYN(0x02) | RST(0x04)
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0x02}, // Only SYN set, RST clear
		},
	)

	// Set MSS value.
	if cfg["mss_clamp_to_pmtu"] == "true" || cfg["mss_clamp_value"] == "0" || cfg["mss_clamp_value"] == "" {
		// Clamp to route MTU: `tcp option maxseg size set rt mtu`
		// Load route MTU into register, then write it as MSS.
		exprs = append(exprs,
			// Load the route/path MTU into register 1.
			&expr.Rt{Key: expr.RtTCPMSS, Register: 1},
			// Overwrite the TCP MSS option with the PMTU-derived MSS.
			&expr.Exthdr{
				SourceRegister: 1,
				Type:           2, // TCP option type 2 = Maximum Segment Size
				Offset:         2, // MSS value is at offset 2 within the option
				Len:            2,
				Op:             expr.ExthdrOpTcpopt,
			},
		)
	} else {
		// Fixed MSS value: `tcp option maxseg size set <N>`
		mssVal, _ := strconv.Atoi(cfg["mss_clamp_value"])
		mssBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(mssBytes, uint16(mssVal))

		exprs = append(exprs,
			&expr.Immediate{Register: 1, Data: mssBytes},
			&expr.Exthdr{
				SourceRegister: 1,
				Type:           2,
				Offset:         2,
				Len:            2,
				Op:             expr.ExthdrOpTcpopt,
			},
		)
	}

	return exprs
}

// overlayOverhead returns the encapsulation overhead in bytes for an overlay type.
func overlayOverhead(overlay string) int {
	switch strings.ToLower(overlay) {
	case "vxlan":
		return OverheadVXLAN
	case "geneve":
		return OverheadGENEVE
	case "wireguard":
		return OverheadWG
	default:
		return 0
	}
}

// EffectiveMTU calculates the effective MTU for a zone, accounting for
// overlay overhead. Returns the zone's configured MTU (or the interface
// default) minus any overlay encapsulation overhead.
func EffectiveMTU(zone model.Zone, overlay string) int {
	mtu := zone.MTU
	if mtu == 0 {
		mtu = MTUStandard
	}
	overhead := overlayOverhead(overlay)
	if overhead > 0 && mtu > overhead {
		return mtu - overhead
	}
	return mtu
}

// MTUDiagnostic reports an MTU issue detected during zone analysis.
type MTUDiagnostic struct {
	Zone      string `json:"zone"`
	Interface string `json:"interface,omitempty"`
	Severity  string `json:"severity"` // "warning", "error"
	Message   string `json:"message"`
}

// MTUStatus returns the current MTU state for all zones.
type MTUStatus struct {
	Zones       []ZoneMTUInfo   `json:"zones"`
	MSSClamping bool            `json:"mss_clamping"`
	PMTUD       bool            `json:"pmtud"`
	Overlay     string          `json:"overlay,omitempty"`
	Diagnostics []MTUDiagnostic `json:"diagnostics,omitempty"`
}

// ZoneMTUInfo reports the MTU state of a single zone.
type ZoneMTUInfo struct {
	Zone          string `json:"zone"`
	Interface     string `json:"interface"`
	ConfiguredMTU int    `json:"configured_mtu"` // From zone config (0 = not set)
	ActualMTU     int    `json:"actual_mtu"`     // From interface
	EffectiveMTU  int    `json:"effective_mtu"`  // After overlay adjustment
}

// GetMTUStatus builds a status snapshot for all zones.
func (m *MTUManager) GetMTUStatus(zones []model.Zone) MTUStatus {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	st := MTUStatus{}
	if cfg != nil {
		st.MSSClamping = cfg["mss_clamping"] == "true"
		st.PMTUD = cfg["pmtud"] == "true"
		st.Overlay = cfg["overlay_adjustment"]
	}

	for _, z := range zones {
		if z.Interface == "" {
			continue
		}
		info := ZoneMTUInfo{
			Zone:          z.Name,
			Interface:     z.Interface,
			ConfiguredMTU: z.MTU,
		}
		if actual, err := Net.LinkGetMTU(z.Interface); err == nil {
			info.ActualMTU = actual
		}
		info.EffectiveMTU = EffectiveMTU(z, st.Overlay)
		st.Zones = append(st.Zones, info)
	}

	st.Diagnostics = m.detectMismatches(zones)
	return st
}

// GetMTUStatusFromZones returns a basic MTU status snapshot without requiring
// the MTU Manager instance. Used by MCP and other callers that don't hold a
// reference to the service.
func GetMTUStatusFromZones(zones []model.Zone) MTUStatus {
	st := MTUStatus{}
	for _, z := range zones {
		if z.Interface == "" {
			continue
		}
		info := ZoneMTUInfo{
			Zone:          z.Name,
			Interface:     z.Interface,
			ConfiguredMTU: z.MTU,
		}
		if actual, err := Net.LinkGetMTU(z.Interface); err == nil {
			info.ActualMTU = actual
		}
		info.EffectiveMTU = EffectiveMTU(z, "")
		st.Zones = append(st.Zones, info)
	}

	// Detect mismatches.
	type zoneMTU struct {
		name string
		mtu  int
	}
	var withMTU []zoneMTU
	for _, info := range st.Zones {
		mtu := info.ActualMTU
		if mtu == 0 {
			mtu = info.ConfiguredMTU
		}
		if mtu == 0 {
			mtu = MTUStandard
		}
		withMTU = append(withMTU, zoneMTU{name: info.Zone, mtu: mtu})
	}
	for i := 0; i < len(withMTU); i++ {
		for j := i + 1; j < len(withMTU); j++ {
			a, b := withMTU[i], withMTU[j]
			if a.mtu != b.mtu {
				st.Diagnostics = append(st.Diagnostics, MTUDiagnostic{
					Zone:     a.name + "/" + b.name,
					Severity: "warning",
					Message: fmt.Sprintf("MTU mismatch: zone %s (%d) vs zone %s (%d) — "+
						"enable MSS clamping to prevent packet blackholes",
						a.name, a.mtu, b.name, b.mtu),
				})
			}
		}
	}
	return st
}
