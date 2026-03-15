package service

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// PerformanceTuner applies kernel and nftables performance optimizations.
//
// Features:
//   - nftables flowtables: bypass full rule evaluation for established flows
//   - Per-zone flowtable control: choose which zones get flow offload
//   - Per-zone conntrack bypass (notrack): skip connection tracking on trusted zones
//   - Conntrack auto-tuning: scale nf_conntrack_max/buckets to available RAM
//   - Sysctl tuning: BBR congestion control, TCP fast open, backlog sizing
//   - IRQ affinity distribution: pin NIC IRQs to different CPUs round-robin
//   - NIC offload optimization: TSO, GRO, GSO, checksum offloads
type PerformanceTuner struct {
	mu    sync.Mutex
	state State
	cfg   map[string]string
}

func NewPerformanceTuner() *PerformanceTuner {
	return &PerformanceTuner{state: StateStopped}
}

func (p *PerformanceTuner) Name() string        { return "performance-tuner" }
func (p *PerformanceTuner) DisplayName() string { return "Performance Tuner" }
func (p *PerformanceTuner) Category() string    { return "system" }
func (p *PerformanceTuner) Dependencies() []string { return nil }

func (p *PerformanceTuner) Description() string {
	return "Kernel and nftables performance tuning. Flowtables, conntrack auto-scaling, sysctl tuning, IRQ affinity distribution, and NIC offload optimization (TSO, GRO, GSO, checksums)."
}

func (p *PerformanceTuner) DefaultConfig() map[string]string {
	return map[string]string{
		"flowtables":           "true",
		"flowtable_interfaces": "",      // empty = auto-detect non-loopback
		"flowtable_hw_offload": "false", // NIC hardware offload (requires driver support)
		"flowtable_zones":      "",      // empty = all zones; comma-separated zone interfaces to offload
		"conntrack_auto":       "true",
		"conntrack_max":        "0",     // 0 = auto (RAM-based: 256 entries per MB)
		"conntrack_notrack_zones": "",   // comma-separated zone interfaces to skip conntrack (trusted zones)
		"sysctl_tuning":        "true",
		"tcp_bbr":              "true",
		"tcp_fastopen":         "true",
		"netdev_backlog":       "4096",
		"somaxconn":            "16384",
		"irq_affinity":         "true",
		"nic_offloads":         "true",
	}
}

func (p *PerformanceTuner) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"flowtables":             {Description: "Enable nftables flowtables for established flow bypass", Default: "true", Type: "bool"},
		"flowtable_interfaces":   {Description: "Interfaces for flowtable (comma-separated, empty = auto-detect)", Type: "string"},
		"flowtable_hw_offload":   {Description: "Enable hardware flow offload (requires NIC support)", Default: "false", Type: "bool"},
		"flowtable_zones":        {Description: "Zone interfaces to offload (comma-separated, empty = all)", Type: "string"},
		"conntrack_auto":         {Description: "Auto-scale conntrack table based on RAM", Default: "true", Type: "bool"},
		"conntrack_max":          {Description: "Manual conntrack_max (0 = auto)", Default: "0", Type: "int"},
		"conntrack_notrack_zones": {Description: "Zone interfaces to skip conntrack (comma-separated, trusted zones only)", Type: "string"},
		"sysctl_tuning":          {Description: "Apply optimized sysctl settings", Default: "true", Type: "bool"},
		"tcp_bbr":                {Description: "Enable BBR congestion control", Default: "true", Type: "bool"},
		"tcp_fastopen":           {Description: "Enable TCP Fast Open (client + server)", Default: "true", Type: "bool"},
		"netdev_backlog":         {Description: "net.core.netdev_max_backlog value", Default: "4096", Type: "int"},
		"somaxconn":              {Description: "net.core.somaxconn value", Default: "16384", Type: "int"},
		"irq_affinity":           {Description: "Distribute NIC IRQs across CPUs", Default: "true", Type: "bool"},
		"nic_offloads":           {Description: "Enable TSO/GRO/GSO/checksum offloads", Default: "true", Type: "bool"},
	}
}

func (p *PerformanceTuner) Validate(cfg map[string]string) error {
	return nil
}

func (p *PerformanceTuner) Start(cfg map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg

	if cfg["sysctl_tuning"] == "true" {
		p.applySysctlTuning(cfg)
	}

	if cfg["conntrack_auto"] == "true" {
		p.autoScaleConntrack(cfg)
	}

	if cfg["flowtables"] == "true" {
		p.enableFlowtables(cfg)
	}

	if notrackZones := cfg["conntrack_notrack_zones"]; notrackZones != "" {
		p.applyConntrackBypass(notrackZones)
	}

	if cfg["irq_affinity"] == "true" || cfg["nic_offloads"] == "true" {
		p.tuneNICs(cfg)
	}

	p.state = StateRunning
	slog.Info("performance tuner started")
	return nil
}

func (p *PerformanceTuner) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove flowtable nft table.
	nftDeleteTable(nft.TableFamilyINet, "gk_perf")
	// Remove conntrack bypass nft table.
	nftDeleteTable(nft.TableFamilyINet, "gk_notrack")

	p.state = StateStopped
	slog.Info("performance tuner stopped")
	return nil
}

func (p *PerformanceTuner) Reload(cfg map[string]string) error {
	if err := p.Stop(); err != nil {
		return err
	}
	return p.Start(cfg)
}

func (p *PerformanceTuner) Status() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// --- sysctl tuning ---

func (p *PerformanceTuner) applySysctlTuning(cfg map[string]string) {
	tunings := []struct {
		key string
		val string
	}{
		// Increase the backlog queue for incoming packets.
		// Default 1000 is too low for multi-gigabit forwarding.
		{"net.core.netdev_max_backlog", cfg["netdev_backlog"]},
		// Increase listen backlog for high-connection servers.
		{"net.core.somaxconn", cfg["somaxconn"]},
		// Enable IP forwarding (should already be on, but ensure it).
		{"net.ipv4.ip_forward", "1"},
		// Disable rp_filter on forwarding paths (allows asymmetric routing).
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf.default.rp_filter", "0"},
	}

	// TCP Fast Open: 3 = enable for both client and server.
	if cfg["tcp_fastopen"] == "true" {
		tunings = append(tunings, struct{ key, val string }{
			"net.ipv4.tcp_fastopen", "3",
		})
	}

	// BBR congestion control: better throughput and latency than cubic.
	if cfg["tcp_bbr"] == "true" {
		tunings = append(tunings, struct{ key, val string }{
			"net.ipv4.tcp_congestion_control", "bbr",
		})
	}

	for _, t := range tunings {
		if err := Net.SysctlSet(t.key, t.val); err != nil {
			slog.Warn("sysctl tuning failed", "key", t.key, "val", t.val, "error", err)
		} else {
			slog.Debug("sysctl applied", "key", t.key, "val", t.val)
		}
	}

	slog.Info("sysctl tuning applied")
}

// --- conntrack auto-scaling ---

func (p *PerformanceTuner) autoScaleConntrack(cfg map[string]string) {
	var maxEntries int

	if v := cfg["conntrack_max"]; v != "" && v != "0" {
		maxEntries, _ = strconv.Atoi(v)
	}

	if maxEntries == 0 {
		// Auto-calculate: 256 entries per MB of RAM.
		// 1 GB → 262144, 4 GB → 1048576, 8 GB → 2097152
		ramMB := totalRAMMB()
		if ramMB > 0 {
			maxEntries = ramMB * 256
		} else {
			maxEntries = 262144 // safe default for 1 GB
		}
	}

	// Buckets = max / 4 (kernel recommendation).
	buckets := maxEntries / 4

	if err := Net.SysctlSet("net.netfilter.nf_conntrack_max", strconv.Itoa(maxEntries)); err != nil {
		slog.Warn("failed to set conntrack_max", "error", err)
	}

	// Buckets are set via the hashsize file, not sysctl.
	hashPath := "/sys/module/nf_conntrack/parameters/hashsize"
	if err := os.WriteFile(hashPath, []byte(strconv.Itoa(buckets)), 0o644); err != nil {
		slog.Warn("failed to set conntrack hashsize", "error", err)
	}

	slog.Info("conntrack auto-scaled", "max", maxEntries, "buckets", buckets)
}

// totalRAMMB reads total RAM in megabytes from /proc/meminfo.
func totalRAMMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kB, err := strconv.Atoi(fields[1])
				if err == nil {
					return kB / 1024
				}
			}
		}
	}
	return 0
}

// --- nftables flowtables ---

func (p *PerformanceTuner) enableFlowtables(cfg map[string]string) {
	// Determine interfaces for the flowtable.
	var devices []string
	if ifaces := cfg["flowtable_interfaces"]; ifaces != "" {
		for _, iface := range strings.Split(ifaces, ",") {
			iface = strings.TrimSpace(iface)
			if iface != "" {
				devices = append(devices, iface)
			}
		}
	} else {
		// Auto-detect: all non-loopback interfaces.
		devices = detectForwardInterfaces()
	}

	if len(devices) < 2 {
		slog.Info("flowtables: need at least 2 interfaces, skipping", "devices", devices)
		return
	}

	// Zone-aware flowtable: if flowtable_zones is set, only offload traffic
	// entering from those zone interfaces. Otherwise offload all forward traffic.
	var zoneIfaces []string
	if zones := cfg["flowtable_zones"]; zones != "" {
		for _, z := range strings.Split(zones, ",") {
			z = strings.TrimSpace(z)
			if z != "" {
				zoneIfaces = append(zoneIfaces, z)
			}
		}
	}

	if err := p.applyFlowtableRules(devices, cfg["flowtable_hw_offload"] == "true", zoneIfaces); err != nil {
		slog.Warn("failed to apply flowtable rules", "error", err)
	} else {
		slog.Info("flowtables enabled", "devices", devices, "hw_offload", cfg["flowtable_hw_offload"], "zone_filter", zoneIfaces)
	}
}

func (p *PerformanceTuner) applyFlowtableRules(devices []string, hwOffload bool, zoneIfaces []string) error {
	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables connection: %w", err)
	}

	// Delete any previous perf table.
	conn.DelTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gk_perf"})
	conn.Flush() //nolint:errcheck

	conn, err = nft.New()
	if err != nil {
		return fmt.Errorf("nftables reconnect: %w", err)
	}

	table := conn.AddTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gk_perf"})

	// Create flowtable.
	ft := &nft.Flowtable{
		Table:    table,
		Name:     "ft",
		Hooknum:  nft.FlowtableHookIngress,
		Priority: nft.FlowtablePriorityFilter,
		Devices:  devices,
	}
	if hwOffload {
		ft.Flags = nft.FlowtableFlagsHWOffload
	}
	conn.AddFlowtable(ft)

	// Forward chain: offload established/related connections to the flowtable.
	policy := nft.ChainPolicyAccept
	chain := conn.AddChain(&nft.Chain{
		Table:    table,
		Name:     "forward",
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookForward,
		Priority: nft.ChainPriorityFilter,
		Policy:   &policy,
	})

	if len(zoneIfaces) > 0 {
		// Per-zone flowtable: only offload traffic entering from specified zone interfaces.
		// This lets you keep full inspection on untrusted zones while offloading trusted ones.
		for _, iface := range zoneIfaces {
			ruleExprs := []expr.Any{
				// Match input interface = zone interface
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftPadIfname(iface)},
				// Match ct state established,related
				&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           []byte{0x06, 0x00, 0x00, 0x00},
					Xor:            []byte{0x00, 0x00, 0x00, 0x00},
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
				// flow offload @ft
				&expr.FlowOffload{Name: "ft"},
			}
			conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: ruleExprs})
		}
	} else {
		// Global flowtable: offload all established/related forward traffic.
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
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
				&expr.FlowOffload{Name: "ft"},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// --- conntrack bypass (notrack) for trusted zones ---

// applyConntrackBypass adds nftables raw/prerouting rules that skip connection
// tracking for traffic on specified zone interfaces. This eliminates the per-packet
// conntrack overhead on trusted/high-throughput zones while preserving full stateful
// inspection on untrusted zones.
func (p *PerformanceTuner) applyConntrackBypass(notrackZones string) {
	var ifaces []string
	for _, z := range strings.Split(notrackZones, ",") {
		z = strings.TrimSpace(z)
		if z != "" {
			ifaces = append(ifaces, z)
		}
	}
	if len(ifaces) == 0 {
		return
	}

	conn, err := nft.New()
	if err != nil {
		slog.Warn("conntrack bypass: nftables connection failed", "error", err)
		return
	}

	// Use inet family so it covers both IPv4 and IPv6.
	table := conn.AddTable(&nft.Table{Family: nft.TableFamilyINet, Name: "gk_notrack"})

	// Raw prerouting chain — runs before conntrack.
	prio := nft.ChainPriorityRaw
	chain := conn.AddChain(&nft.Chain{
		Table:    table,
		Name:     "prerouting",
		Type:     nft.ChainTypeFilter,
		Hooknum:  nft.ChainHookPrerouting,
		Priority: prio,
	})

	// For each trusted zone interface, add a notrack rule.
	for _, iface := range ifaces {
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftPadIfname(iface)},
				&expr.Notrack{},
			},
		})
		slog.Info("conntrack bypass (notrack) added", "iface", iface)
	}

	if err := conn.Flush(); err != nil {
		slog.Warn("conntrack bypass: nftables flush failed", "error", err)
	} else {
		slog.Info("conntrack bypass applied", "zones", ifaces)
	}
}

// detectForwardInterfaces returns all non-loopback network interfaces.
func detectForwardInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		result = append(result, iface.Name)
	}
	return result
}

// --- NIC tuning: IRQ affinity + hardware offloads ---

func (p *PerformanceTuner) tuneNICs(cfg map[string]string) {
	ifaces := detectForwardInterfaces()

	for _, iface := range ifaces {
		info, err := Net.NICInfo(iface)
		if err != nil {
			slog.Warn("NIC info failed", "iface", iface, "error", err)
			continue
		}

		if cfg["irq_affinity"] == "true" && len(info.IRQs) > 0 {
			p.distributeIRQAffinity(info.Name, info.IRQs)
		}

		if cfg["nic_offloads"] == "true" {
			p.enableOffloads(iface)
		}
	}
}

// distributeIRQAffinity pins each NIC IRQ to a different CPU, round-robin.
// This prevents all interrupts from landing on CPU 0 (the kernel default).
func (p *PerformanceTuner) distributeIRQAffinity(iface string, irqs []int) {
	numCPU := runtime.NumCPU()
	for i, irq := range irqs {
		cpu := i % numCPU
		if err := Net.SetIRQAffinity(irq, strconv.Itoa(cpu)); err != nil {
			slog.Warn("IRQ affinity failed", "irq", irq, "cpu", cpu, "error", err)
		} else {
			slog.Debug("IRQ affinity set", "irq", irq, "cpu", cpu, "iface", iface)
		}
	}
	slog.Info("IRQ affinity distributed", "iface", iface, "irqs", len(irqs), "cpus", numCPU)
}

// enableOffloads turns on TSO, GRO, GSO, and checksum offloads.
// These are almost always beneficial for a router/firewall — they let the
// NIC coalesce/segment packets in hardware instead of the CPU.
func (p *PerformanceTuner) enableOffloads(iface string) {
	features := []string{"tso", "gro", "gso", "rx_checksum", "tx_checksum"}
	for _, feat := range features {
		if err := Net.NICSetOffload(iface, feat, true); err != nil {
			slog.Warn("offload enable failed", "iface", iface, "feature", feat, "error", err)
		} else {
			slog.Debug("offload enabled", "iface", iface, "feature", feat)
		}
	}
	slog.Info("NIC offloads applied", "iface", iface)
}

// --- Status / diagnostics ---

// ConntrackStatus returns current conntrack table sizing.
type ConntrackStatus struct {
	Max     int `json:"max"`
	Buckets int `json:"buckets"`
	Count   int `json:"count"`
	RAMMB   int `json:"ram_mb"`
}

// GetConntrackStatus reads current conntrack parameters from the kernel.
func GetConntrackStatus() ConntrackStatus {
	st := ConntrackStatus{RAMMB: totalRAMMB()}

	if v, err := Net.SysctlGet("net.netfilter.nf_conntrack_max"); err == nil {
		st.Max, _ = strconv.Atoi(v)
	}
	if data, err := os.ReadFile("/sys/module/nf_conntrack/parameters/hashsize"); err == nil {
		st.Buckets, _ = strconv.Atoi(strings.TrimSpace(string(data)))
	}
	if v, err := Net.SysctlGet("net.netfilter.nf_conntrack_count"); err == nil {
		st.Count, _ = strconv.Atoi(v)
	}
	return st
}

// PerfStatus returns a summary of all performance tuning state.
type PerfStatus struct {
	Conntrack      ConntrackStatus   `json:"conntrack"`
	Flowtables     bool              `json:"flowtables"`
	FlowtableZones []string          `json:"flowtable_zones,omitempty"`
	NotrackZones   []string          `json:"notrack_zones,omitempty"`
	TCPCongestion  string            `json:"tcp_congestion"`
	TCPFastOpen    string            `json:"tcp_fastopen"`
	IRQAffinity    bool              `json:"irq_affinity"`
	NICOffloads    bool              `json:"nic_offloads"`
	NICs           []NICPerfInfo     `json:"nics,omitempty"`
}

// NICPerfInfo is a summary of NIC performance state for the CLI.
type NICPerfInfo struct {
	Name      string          `json:"name"`
	Driver    string          `json:"driver"`
	SpeedMbps int             `json:"speed_mbps"`
	RxQueues  int             `json:"rx_queues"`
	TxQueues  int             `json:"tx_queues"`
	IRQs      int             `json:"irqs"`
	Offloads  map[string]bool `json:"offloads"`
}

// GetPerfStatus builds a complete performance status snapshot.
func (p *PerformanceTuner) GetPerfStatus() PerfStatus {
	p.mu.Lock()
	cfg := p.cfg
	p.mu.Unlock()

	st := PerfStatus{
		Conntrack: GetConntrackStatus(),
	}

	if cfg != nil {
		st.Flowtables = cfg["flowtables"] == "true"
		st.IRQAffinity = cfg["irq_affinity"] == "true"
		st.NICOffloads = cfg["nic_offloads"] == "true"

		if zones := cfg["flowtable_zones"]; zones != "" {
			for _, z := range strings.Split(zones, ",") {
				z = strings.TrimSpace(z)
				if z != "" {
					st.FlowtableZones = append(st.FlowtableZones, z)
				}
			}
		}
		if zones := cfg["conntrack_notrack_zones"]; zones != "" {
			for _, z := range strings.Split(zones, ",") {
				z = strings.TrimSpace(z)
				if z != "" {
					st.NotrackZones = append(st.NotrackZones, z)
				}
			}
		}
	}

	if v, err := Net.SysctlGet("net.ipv4.tcp_congestion_control"); err == nil {
		st.TCPCongestion = v
	}
	if v, err := Net.SysctlGet("net.ipv4.tcp_fastopen"); err == nil {
		st.TCPFastOpen = v
	}

	// Collect NIC info for all forward interfaces.
	for _, iface := range detectForwardInterfaces() {
		info, err := Net.NICInfo(iface)
		if err != nil {
			continue
		}
		st.NICs = append(st.NICs, NICPerfInfo{
			Name:      info.Name,
			Driver:    info.Driver,
			SpeedMbps: info.SpeedMbps,
			RxQueues:  info.RxQueues,
			TxQueues:  info.TxQueues,
			IRQs:      len(info.IRQs),
			Offloads:  info.Offloads,
		})
	}

	return st
}
