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
//   - Conntrack auto-tuning: scale nf_conntrack_max/buckets to available RAM
//   - Sysctl tuning: BBR congestion control, TCP fast open, backlog sizing
//
// These are the easy wins that get 80% of the throughput benefit with minimal
// complexity. More advanced optimizations (XDP, IRQ affinity) are Phase 13b.
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
		"conntrack_auto":       "true",
		"conntrack_max":        "0",  // 0 = auto (RAM-based: 256 entries per MB)
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
		"flowtables":           {Description: "Enable nftables flowtables for established flow bypass", Default: "true", Type: "bool"},
		"flowtable_interfaces": {Description: "Interfaces for flowtable (comma-separated, empty = auto-detect)", Type: "string"},
		"flowtable_hw_offload": {Description: "Enable hardware flow offload (requires NIC support)", Default: "false", Type: "bool"},
		"conntrack_auto":       {Description: "Auto-scale conntrack table based on RAM", Default: "true", Type: "bool"},
		"conntrack_max":        {Description: "Manual conntrack_max (0 = auto)", Default: "0", Type: "int"},
		"sysctl_tuning":        {Description: "Apply optimized sysctl settings", Default: "true", Type: "bool"},
		"tcp_bbr":              {Description: "Enable BBR congestion control", Default: "true", Type: "bool"},
		"tcp_fastopen":         {Description: "Enable TCP Fast Open (client + server)", Default: "true", Type: "bool"},
		"netdev_backlog":       {Description: "net.core.netdev_max_backlog value", Default: "4096", Type: "int"},
		"somaxconn":            {Description: "net.core.somaxconn value", Default: "16384", Type: "int"},
		"irq_affinity":         {Description: "Distribute NIC IRQs across CPUs", Default: "true", Type: "bool"},
		"nic_offloads":         {Description: "Enable TSO/GRO/GSO/checksum offloads", Default: "true", Type: "bool"},
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

	if err := p.applyFlowtableRules(devices, cfg["flowtable_hw_offload"] == "true"); err != nil {
		slog.Warn("failed to apply flowtable rules", "error", err)
	} else {
		slog.Info("flowtables enabled", "devices", devices, "hw_offload", cfg["flowtable_hw_offload"])
	}
}

func (p *PerformanceTuner) applyFlowtableRules(devices []string, hwOffload bool) error {
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

	// Rule: ct state established,related flow offload @ft
	conn.AddRule(&nft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// Match ct state established,related
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // established(2) | related(4)
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
			// flow offload @ft
			&expr.FlowOffload{Name: "ft"},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
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
