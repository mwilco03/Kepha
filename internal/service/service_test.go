package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
)

// ---------------------------------------------------------------------------
// Mock NetworkManager — records SysctlSet calls and returns preset conntrack.
// ---------------------------------------------------------------------------

type sysctlCall struct{ Key, Val string }

type offloadCall struct{ Iface, Feature string; Enabled bool }
type irqAffinityCall struct{ IRQ int; CPUList string }

type mockNetworkManager struct {
	mu              sync.Mutex
	SysctlCalls     []sysctlCall
	Conntrack       []backend.ConntrackEntry
	NICInfoResult   *backend.NICInfo // returned by NICInfo()
	OffloadCalls    []offloadCall
	IRQAffinityCalls []irqAffinityCall
}

func (m *mockNetworkManager) SysctlSet(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SysctlCalls = append(m.SysctlCalls, sysctlCall{key, value})
	return nil
}

func (m *mockNetworkManager) SysctlGet(key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.SysctlCalls) - 1; i >= 0; i-- {
		if m.SysctlCalls[i].Key == key {
			return m.SysctlCalls[i].Val, nil
		}
	}
	return "", nil
}

func (m *mockNetworkManager) ConntrackList(proto string) ([]backend.ConntrackEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Conntrack, nil
}

// Stubs — unused by PerformanceTuner and BandwidthMonitor.
func (m *mockNetworkManager) LinkAdd(string, string) error                    { return nil }
func (m *mockNetworkManager) LinkDel(string) error                            { return nil }
func (m *mockNetworkManager) LinkSetUp(string) error                          { return nil }
func (m *mockNetworkManager) LinkSetDown(string) error                        { return nil }
func (m *mockNetworkManager) LinkSetMaster(string, string) error              { return nil }
func (m *mockNetworkManager) AddrAdd(string, string) error                    { return nil }
func (m *mockNetworkManager) AddrFlush(string) error                          { return nil }
func (m *mockNetworkManager) RouteAdd(string, string, string) error           { return nil }
func (m *mockNetworkManager) RouteDel(string, string, string) error           { return nil }
func (m *mockNetworkManager) RouteAddTable(string, string, string, int) error { return nil }
func (m *mockNetworkManager) RouteFlushTable(int) error                       { return nil }
func (m *mockNetworkManager) RouteAddMetric(string, string, int) error        { return nil }
func (m *mockNetworkManager) RouteReplace(string, string) error               { return nil }
func (m *mockNetworkManager) BridgeVlanAdd(string, int) error                 { return nil }
func (m *mockNetworkManager) BridgeSetSTP(string, bool) error                 { return nil }
func (m *mockNetworkManager) BridgeSetForwardDelay(string, int) error         { return nil }
func (m *mockNetworkManager) BridgeSetVlanFiltering(string, bool) error       { return nil }
func (m *mockNetworkManager) RuleAdd(string, int, int) error                  { return nil }
func (m *mockNetworkManager) RuleDel(int) error                               { return nil }

func (m *mockNetworkManager) Ping(string, int, int, string) (backend.PingResult, error) {
	return backend.PingResult{}, nil
}
func (m *mockNetworkManager) Connections() ([]backend.Connection, error) { return nil, nil }

func (m *mockNetworkManager) NICInfo(iface string) (*backend.NICInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.NICInfoResult != nil {
		info := *m.NICInfoResult
		info.Name = iface
		return &info, nil
	}
	return &backend.NICInfo{Name: iface, Offloads: map[string]bool{}}, nil
}

func (m *mockNetworkManager) SetIRQAffinity(irq int, cpuList string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IRQAffinityCalls = append(m.IRQAffinityCalls, irqAffinityCall{irq, cpuList})
	return nil
}

func (m *mockNetworkManager) NICSetOffload(iface string, feature string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OffloadCalls = append(m.OffloadCalls, offloadCall{iface, feature, enabled})
	return nil
}

func (m *mockNetworkManager) getIRQAffinityCalls() []irqAffinityCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]irqAffinityCall, len(m.IRQAffinityCalls))
	copy(out, m.IRQAffinityCalls)
	return out
}

func (m *mockNetworkManager) getOffloadCalls() []offloadCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]offloadCall, len(m.OffloadCalls))
	copy(out, m.OffloadCalls)
	return out
}

// ---------------------------------------------------------------------------
// Helper: swap Net for the duration of a test.
// ---------------------------------------------------------------------------

func withMockNet(t *testing.T, mock *mockNetworkManager) {
	t.Helper()
	orig := Net
	Net = mock
	t.Cleanup(func() { Net = orig })
}

func (m *mockNetworkManager) getSysctlCalls() []sysctlCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sysctlCall, len(m.SysctlCalls))
	copy(out, m.SysctlCalls)
	return out
}

func findSysctl(calls []sysctlCall, key string) (string, bool) {
	for _, c := range calls {
		if c.Key == key {
			return c.Val, true
		}
	}
	return "", false
}

// ===================================================================
// PerformanceTuner tests
// ===================================================================

func TestPerformanceTunerSysctlDefaults(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg := pt.DefaultConfig()
	// Disable subsystems that touch nftables/kernel directly.
	cfg["flowtables"] = "false"
	cfg["conntrack_auto"] = "false"

	if err := pt.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pt.Stop()

	calls := mock.getSysctlCalls()

	// All expected sysctl writes from applySysctlTuning with default config.
	expected := map[string]string{
		"net.core.netdev_max_backlog":     "4096",
		"net.core.somaxconn":              "16384",
		"net.ipv4.ip_forward":             "1",
		"net.ipv4.conf.all.rp_filter":     "0",
		"net.ipv4.conf.default.rp_filter": "0",
		"net.ipv4.tcp_fastopen":           "3",
		"net.ipv4.tcp_congestion_control": "bbr",
	}

	for key, wantVal := range expected {
		gotVal, ok := findSysctl(calls, key)
		if !ok {
			t.Errorf("missing sysctl call for %s", key)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("sysctl %s = %q, want %q", key, gotVal, wantVal)
		}
	}
}

func TestPerformanceTunerSysctlDisabled(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg := map[string]string{
		"sysctl_tuning":  "false",
		"conntrack_auto": "false",
		"flowtables":     "false",
	}

	if err := pt.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pt.Stop()

	calls := mock.getSysctlCalls()
	if len(calls) != 0 {
		t.Errorf("expected no sysctl calls when disabled, got %d: %v", len(calls), calls)
	}
}

func TestPerformanceTunerSysctlCustomValues(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg := map[string]string{
		"sysctl_tuning":  "true",
		"conntrack_auto": "false",
		"flowtables":     "false",
		"tcp_bbr":        "false",
		"tcp_fastopen":   "false",
		"netdev_backlog": "8192",
		"somaxconn":      "32768",
	}

	if err := pt.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pt.Stop()

	calls := mock.getSysctlCalls()

	// Custom values applied.
	if v, ok := findSysctl(calls, "net.core.netdev_max_backlog"); !ok || v != "8192" {
		t.Errorf("netdev_max_backlog = %q, want 8192", v)
	}
	if v, ok := findSysctl(calls, "net.core.somaxconn"); !ok || v != "32768" {
		t.Errorf("somaxconn = %q, want 32768", v)
	}

	// BBR and TFO should NOT be set.
	if _, ok := findSysctl(calls, "net.ipv4.tcp_congestion_control"); ok {
		t.Error("tcp_congestion_control should not be set when tcp_bbr=false")
	}
	if _, ok := findSysctl(calls, "net.ipv4.tcp_fastopen"); ok {
		t.Error("tcp_fastopen should not be set when tcp_fastopen=false")
	}
}

func TestPerformanceTunerConntrackManual(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg := map[string]string{
		"sysctl_tuning":  "false",
		"conntrack_auto": "true",
		"conntrack_max":  "500000",
		"flowtables":     "false",
	}

	if err := pt.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pt.Stop()

	calls := mock.getSysctlCalls()
	v, ok := findSysctl(calls, "net.netfilter.nf_conntrack_max")
	if !ok {
		t.Fatal("expected conntrack_max sysctl call")
	}
	if v != "500000" {
		t.Errorf("conntrack_max = %s, want 500000", v)
	}
}

func TestPerformanceTunerConntrackAuto(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg := map[string]string{
		"sysctl_tuning":  "false",
		"conntrack_auto": "true",
		"conntrack_max":  "0", // auto
		"flowtables":     "false",
	}

	if err := pt.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pt.Stop()

	calls := mock.getSysctlCalls()
	v, ok := findSysctl(calls, "net.netfilter.nf_conntrack_max")
	if !ok {
		t.Fatal("expected conntrack_max sysctl call")
	}
	// Auto-calculated from RAM: should be > 0.
	if v == "0" || v == "" {
		t.Errorf("auto conntrack_max should be > 0, got %q", v)
	}
}

func TestPerformanceTunerLifecycle(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	if pt.Status() != StateStopped {
		t.Fatalf("initial state = %s, want stopped", pt.Status())
	}

	cfg := map[string]string{
		"sysctl_tuning":  "false",
		"conntrack_auto": "false",
		"flowtables":     "false",
	}
	if err := pt.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if pt.Status() != StateRunning {
		t.Fatalf("after Start state = %s, want running", pt.Status())
	}

	if err := pt.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if pt.Status() != StateStopped {
		t.Fatalf("after Stop state = %s, want stopped", pt.Status())
	}
}

func TestPerformanceTunerReload(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg1 := map[string]string{
		"sysctl_tuning":  "true",
		"conntrack_auto": "false",
		"flowtables":     "false",
		"tcp_bbr":        "false",
		"tcp_fastopen":   "false",
		"netdev_backlog": "4096",
		"somaxconn":      "16384",
	}
	if err := pt.Start(cfg1); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Reload with new values.
	cfg2 := map[string]string{
		"sysctl_tuning":  "true",
		"conntrack_auto": "false",
		"flowtables":     "false",
		"tcp_bbr":        "true",
		"tcp_fastopen":   "false",
		"netdev_backlog": "8192",
		"somaxconn":      "32768",
	}
	if err := pt.Reload(cfg2); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	calls := mock.getSysctlCalls()
	// After reload, the new backlog value should appear.
	found := false
	for _, c := range calls {
		if c.Key == "net.core.netdev_max_backlog" && c.Val == "8192" {
			found = true
		}
	}
	if !found {
		t.Error("reload did not apply netdev_max_backlog=8192")
	}

	pt.Stop()
}

func TestPerformanceTunerMetadata(t *testing.T) {
	pt := NewPerformanceTuner()
	if pt.Name() != "performance-tuner" {
		t.Errorf("Name = %q", pt.Name())
	}
	if pt.Category() != "system" {
		t.Errorf("Category = %q", pt.Category())
	}
	schema := pt.ConfigSchema()
	for _, key := range []string{"flowtables", "conntrack_auto", "sysctl_tuning", "tcp_bbr"} {
		if _, ok := schema[key]; !ok {
			t.Errorf("schema missing key %q", key)
		}
	}
	if err := pt.Validate(pt.DefaultConfig()); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// ===================================================================
// BandwidthMonitor tests
// ===================================================================

func TestBandwidthMonitorConntrackAggregation(t *testing.T) {
	mock := &mockNetworkManager{
		Conntrack: []backend.ConntrackEntry{
			{SrcAddr: "192.168.1.10", DstAddr: "8.8.8.8", Bytes: 1000},
			{SrcAddr: "192.168.1.10", DstAddr: "1.1.1.1", Bytes: 500},
			{SrcAddr: "192.168.1.20", DstAddr: "8.8.8.8", Bytes: 2000},
			{SrcAddr: "8.8.8.8", DstAddr: "192.168.1.10", Bytes: 3000},
		},
	}
	withMockNet(t, mock)

	bm := NewBandwidthMonitor(t.TempDir())
	bm.cfg = map[string]string{"conntrack": "true"}
	bm.current = make(map[string]*DeviceTraffic)

	bm.sampleConntrack()

	// Trace the aggregation logic:
	//
	// Entry 1: src=.10 dst=8.8.8.8 bytes=1000
	//   .10 out += 1000 → .10 out=1000
	//   8.8.8.8 in += 1000
	//
	// Entry 2: src=.10 dst=1.1.1.1 bytes=500
	//   .10 out += 500 → .10 out=1500
	//   1.1.1.1 in += 500
	//
	// Entry 3: src=.20 dst=8.8.8.8 bytes=2000
	//   .20 out += 2000
	//   8.8.8.8 in += 2000 → 8.8.8.8 in=3000
	//
	// Entry 4: src=8.8.8.8 dst=.10 bytes=3000
	//   8.8.8.8 out += 3000
	//   .10 in += 3000

	tests := []struct {
		ip       string
		wantIn   uint64
		wantOut  uint64
	}{
		{"192.168.1.10", 3000, 1500},
		{"192.168.1.20", 0, 2000},
		{"8.8.8.8", 3000, 3000},
		{"1.1.1.1", 500, 0},
	}

	for _, tc := range tests {
		dt := bm.current[tc.ip]
		if dt == nil {
			t.Errorf("%s: not found in current map", tc.ip)
			continue
		}
		if dt.BytesIn != tc.wantIn {
			t.Errorf("%s: BytesIn = %d, want %d", tc.ip, dt.BytesIn, tc.wantIn)
		}
		if dt.BytesOut != tc.wantOut {
			t.Errorf("%s: BytesOut = %d, want %d", tc.ip, dt.BytesOut, tc.wantOut)
		}
	}
}

func TestBandwidthMonitorSnapshot(t *testing.T) {
	dir := t.TempDir()
	bm := NewBandwidthMonitor(dir)
	bm.current = map[string]*DeviceTraffic{
		"10.0.0.1": {
			IP:       "10.0.0.1",
			Hostname: "desktop",
			BytesIn:  5000,
			BytesOut: 12000,
			LastSeen: "2026-01-01T00:00:00Z",
		},
		"10.0.0.2": {
			IP:       "10.0.0.2",
			BytesIn:  100,
			BytesOut: 200,
			LastSeen: "2026-01-01T00:00:00Z",
		},
	}

	bm.persistSnapshot()

	data, err := os.ReadFile(filepath.Join(dir, "latest.json"))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	var snap struct {
		Timestamp string          `json:"timestamp"`
		Devices   []DeviceTraffic `json:"devices"`
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Timestamp == "" {
		t.Error("snapshot missing timestamp")
	}
	if len(snap.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(snap.Devices))
	}

	// Build a map for order-independent comparison.
	byIP := make(map[string]DeviceTraffic)
	for _, d := range snap.Devices {
		byIP[d.IP] = d
	}
	if d, ok := byIP["10.0.0.1"]; !ok || d.BytesIn != 5000 || d.BytesOut != 12000 {
		t.Errorf("10.0.0.1 unexpected: %+v", d)
	}
	if d, ok := byIP["10.0.0.2"]; !ok || d.BytesIn != 100 {
		t.Errorf("10.0.0.2 unexpected: %+v", d)
	}
}

func TestBandwidthMonitorGetDeviceTraffic(t *testing.T) {
	mock := &mockNetworkManager{
		Conntrack: []backend.ConntrackEntry{
			{SrcAddr: "10.0.0.5", DstAddr: "1.1.1.1", Bytes: 777},
		},
	}
	withMockNet(t, mock)

	bm := NewBandwidthMonitor(t.TempDir())
	bm.cfg = map[string]string{"conntrack": "true"}
	bm.current = make(map[string]*DeviceTraffic)

	bm.sampleConntrack()

	devices := bm.GetDeviceTraffic()
	found := false
	for _, d := range devices {
		if d.IP == "10.0.0.5" && d.BytesOut == 777 {
			found = true
		}
	}
	if !found {
		t.Errorf("10.0.0.5 not found in GetDeviceTraffic: %+v", devices)
	}
}

func TestBandwidthMonitorLifecycle(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	dir := t.TempDir()
	bm := NewBandwidthMonitor(dir)
	if bm.Status() != StateStopped {
		t.Fatalf("initial state = %s", bm.Status())
	}

	cfg := map[string]string{
		"nftables_accounting": "false", // skip nft calls
		"conntrack":           "false",
		"sample_interval":     "60", // long interval so the goroutine doesn't fire
	}
	if err := bm.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if bm.Status() != StateRunning {
		t.Fatalf("after Start state = %s", bm.Status())
	}

	// Data dir should exist.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("data dir not created")
	}

	if err := bm.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if bm.Status() != StateStopped {
		t.Fatalf("after Stop state = %s", bm.Status())
	}
}

func TestBandwidthMonitorReloadUpdatesConfig(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	bm := NewBandwidthMonitor(t.TempDir())
	cfg := map[string]string{
		"nftables_accounting": "false",
		"conntrack":           "false",
		"sample_interval":     "60",
		"top_talkers":         "10",
	}
	if err := bm.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer bm.Stop()

	newCfg := map[string]string{
		"top_talkers": "50",
	}
	if err := bm.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// After reload the internal config should be updated.
	bm.mu.Lock()
	got := bm.cfg["top_talkers"]
	bm.mu.Unlock()
	if got != "50" {
		t.Errorf("after Reload top_talkers = %q, want 50", got)
	}
}

func TestBandwidthMonitorMetadata(t *testing.T) {
	bm := NewBandwidthMonitor("/tmp/bw")
	if bm.Name() != "bandwidth-monitor" {
		t.Errorf("Name = %q", bm.Name())
	}
	if bm.Category() != "monitoring" {
		t.Errorf("Category = %q", bm.Category())
	}
	defaults := bm.DefaultConfig()
	if defaults["sample_interval"] != "5" {
		t.Errorf("default sample_interval = %q", defaults["sample_interval"])
	}
}

func TestBandwidthMonitorEmptyConntrack(t *testing.T) {
	mock := &mockNetworkManager{Conntrack: nil}
	withMockNet(t, mock)

	bm := NewBandwidthMonitor(t.TempDir())
	bm.cfg = map[string]string{"conntrack": "true"}
	bm.current = make(map[string]*DeviceTraffic)

	// Should not panic with empty conntrack.
	bm.sampleConntrack()

	if len(bm.current) != 0 {
		t.Errorf("expected empty current, got %d entries", len(bm.current))
	}
}

func TestBandwidthMonitorAccumulatesAcrossSamples(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	bm := NewBandwidthMonitor(t.TempDir())
	bm.cfg = map[string]string{"conntrack": "true"}
	bm.current = make(map[string]*DeviceTraffic)

	// First sample.
	mock.mu.Lock()
	mock.Conntrack = []backend.ConntrackEntry{
		{SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", Bytes: 100},
	}
	mock.mu.Unlock()
	bm.sampleConntrack()

	first := bm.current["10.0.0.1"]
	if first == nil || first.BytesOut != 100 {
		t.Fatalf("first sample: BytesOut = %v", first)
	}
	if first.LastSeen == "" {
		t.Fatal("first sample: LastSeen is empty")
	}

	// Second sample — conntrack shows new totals.
	mock.mu.Lock()
	mock.Conntrack = []backend.ConntrackEntry{
		{SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", Bytes: 500},
	}
	mock.mu.Unlock()
	bm.sampleConntrack()

	// The implementation REPLACES BytesOut (not accumulates), since
	// conntrack entries are absolute counters. Verify latest value.
	dt := bm.current["10.0.0.1"]
	if dt.BytesOut != 500 {
		t.Errorf("second sample: BytesOut = %d, want 500", dt.BytesOut)
	}
	if dt.LastSeen == "" {
		t.Error("LastSeen should not be empty after second sample")
	}
}

// ===================================================================
// NIC tuning tests (IRQ affinity + offloads)
// ===================================================================

func TestPerformanceTunerIRQAffinity(t *testing.T) {
	mock := &mockNetworkManager{
		NICInfoResult: &backend.NICInfo{
			IRQs: []int{30, 31, 32, 33},
		},
	}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	// Test the IRQ distribution directly (avoids detectForwardInterfaces
	// which depends on real system interfaces).
	pt.distributeIRQAffinity("eth0", []int{30, 31, 32, 33})

	calls := mock.getIRQAffinityCalls()
	if len(calls) != 4 {
		t.Fatalf("expected 4 IRQ affinity calls, got %d", len(calls))
	}

	// Round-robin: IRQ 30→CPU 0, 31→CPU 1, 32→CPU 2, 33→CPU 3
	// (or wraps if fewer CPUs, but we verify sequential assignment).
	for i, call := range calls {
		if call.IRQ != 30+i {
			t.Errorf("call[%d]: IRQ = %d, want %d", i, call.IRQ, 30+i)
		}
		// CPU should be i % runtime.NumCPU()
		wantCPU := i % numCPUForTest()
		if call.CPUList != strconv.Itoa(wantCPU) {
			t.Errorf("call[%d]: cpu = %q, want %q", i, call.CPUList, strconv.Itoa(wantCPU))
		}
	}
}

func TestPerformanceTunerIRQAffinityWraps(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	// Create more IRQs than CPUs to verify wrapping.
	numCPU := numCPUForTest()
	irqs := make([]int, numCPU+2)
	for i := range irqs {
		irqs[i] = 100 + i
	}

	pt := NewPerformanceTuner()
	pt.distributeIRQAffinity("eth0", irqs)

	calls := mock.getIRQAffinityCalls()
	if len(calls) != len(irqs) {
		t.Fatalf("expected %d calls, got %d", len(irqs), len(calls))
	}

	// Last two should wrap back to CPU 0 and 1.
	secondToLast := calls[numCPU]
	if secondToLast.CPUList != "0" {
		t.Errorf("IRQ %d should wrap to CPU 0, got %q", secondToLast.IRQ, secondToLast.CPUList)
	}
	last := calls[numCPU+1]
	if last.CPUList != "1" {
		t.Errorf("IRQ %d should wrap to CPU 1, got %q", last.IRQ, last.CPUList)
	}
}

func TestPerformanceTunerOffloads(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	pt.enableOffloads("eth0")

	calls := mock.getOffloadCalls()

	// Should enable all 5 offload features.
	expected := map[string]bool{
		"tso": false, "gro": false, "gso": false,
		"rx_checksum": false, "tx_checksum": false,
	}
	for _, call := range calls {
		if call.Iface != "eth0" {
			t.Errorf("unexpected iface %q", call.Iface)
		}
		if !call.Enabled {
			t.Errorf("feature %q should be enabled", call.Feature)
		}
		expected[call.Feature] = true
	}
	for feat, seen := range expected {
		if !seen {
			t.Errorf("missing offload call for %q", feat)
		}
	}
}

func TestPerformanceTunerNICDisabled(t *testing.T) {
	mock := &mockNetworkManager{}
	withMockNet(t, mock)

	pt := NewPerformanceTuner()
	cfg := map[string]string{
		"sysctl_tuning":  "false",
		"conntrack_auto": "false",
		"flowtables":     "false",
		"irq_affinity":   "false",
		"nic_offloads":   "false",
	}
	if err := pt.Start(cfg); err != nil {
		t.Fatal(err)
	}
	defer pt.Stop()

	if len(mock.getIRQAffinityCalls()) != 0 {
		t.Error("IRQ affinity calls should be empty when disabled")
	}
	if len(mock.getOffloadCalls()) != 0 {
		t.Error("offload calls should be empty when disabled")
	}
}

func TestPerformanceTunerNICConfigSchema(t *testing.T) {
	pt := NewPerformanceTuner()
	schema := pt.ConfigSchema()
	for _, key := range []string{"irq_affinity", "nic_offloads"} {
		if _, ok := schema[key]; !ok {
			t.Errorf("schema missing key %q", key)
		}
	}
	defaults := pt.DefaultConfig()
	if defaults["irq_affinity"] != "true" {
		t.Errorf("irq_affinity default = %q", defaults["irq_affinity"])
	}
	if defaults["nic_offloads"] != "true" {
		t.Errorf("nic_offloads default = %q", defaults["nic_offloads"])
	}
}

// numCPUForTest returns runtime.NumCPU() — extracted for readability.
func numCPUForTest() int { return runtime.NumCPU() }
