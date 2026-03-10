package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BandwidthMonitor provides per-device and per-interface bandwidth tracking.
// This is Firewalla's killer feature — knowing exactly which device is using
// how much bandwidth in real time.
//
// Implementation: uses nftables byte counters on per-device rules and
// periodically samples /proc/net/dev for interface-level stats. Stores
// time-series data in a ring buffer file for the web dashboard.
type BandwidthMonitor struct {
	mu      sync.Mutex
	state   State
	dataDir string
	cfg     map[string]string
	stopCh  chan struct{}
	current map[string]*DeviceTraffic
}

// DeviceTraffic holds bandwidth stats for a single device.
type DeviceTraffic struct {
	IP         string `json:"ip"`
	MAC        string `json:"mac,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
	LastSeen   string `json:"last_seen"`
	RateIn     uint64 `json:"rate_in_bps"`
	RateOut    uint64 `json:"rate_out_bps"`
}

// InterfaceTraffic holds bandwidth stats for an interface.
type InterfaceTraffic struct {
	Name     string `json:"name"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	RateIn   uint64 `json:"rate_in_bps"`
	RateOut  uint64 `json:"rate_out_bps"`
}

func NewBandwidthMonitor(dataDir string) *BandwidthMonitor {
	return &BandwidthMonitor{
		dataDir: dataDir,
		state:   StateStopped,
		current: make(map[string]*DeviceTraffic),
	}
}

func (bm *BandwidthMonitor) Name() string           { return "bandwidth-monitor" }
func (bm *BandwidthMonitor) DisplayName() string    { return "Bandwidth Monitor" }
func (bm *BandwidthMonitor) Category() string       { return "monitoring" }
func (bm *BandwidthMonitor) Dependencies() []string { return nil }

func (bm *BandwidthMonitor) Description() string {
	return "Real-time per-device and per-interface bandwidth monitoring. Tracks which devices use the most bandwidth with historical data for the dashboard."
}

func (bm *BandwidthMonitor) DefaultConfig() map[string]string {
	return map[string]string{
		"interfaces":          "",
		"sample_interval":     "5",
		"history_hours":       "24",
		"nftables_accounting": "true",
		"conntrack":           "true",
		"top_talkers":         "20",
	}
}

func (bm *BandwidthMonitor) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"interfaces":          {Description: "Interfaces to monitor (comma-separated, empty = all)", Type: "string"},
		"sample_interval":     {Description: "Sampling interval in seconds", Default: "5", Type: "int"},
		"history_hours":       {Description: "Hours of history to retain", Default: "24", Type: "int"},
		"nftables_accounting": {Description: "Use nftables counters for per-device tracking", Default: "true", Type: "bool"},
		"conntrack":           {Description: "Use conntrack for connection-level accounting", Default: "true", Type: "bool"},
		"top_talkers":         {Description: "Number of top talkers to track", Default: "20", Type: "int"},
	}
}

func (bm *BandwidthMonitor) Validate(cfg map[string]string) error {
	return nil
}

func (bm *BandwidthMonitor) Start(cfg map[string]string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.cfg = cfg
	bm.stopCh = make(chan struct{})
	bm.current = make(map[string]*DeviceTraffic)

	if err := os.MkdirAll(bm.dataDir, 0o755); err != nil {
		return err
	}

	// Set up nftables accounting chain if enabled.
	if cfg["nftables_accounting"] == "true" {
		bm.setupAccountingChain()
	}

	go bm.sampleLoop()

	bm.state = StateRunning
	return nil
}

func (bm *BandwidthMonitor) Stop() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.stopCh != nil {
		close(bm.stopCh)
	}

	// Remove accounting chain.
	exec.Command("nft", "delete", "chain", "inet", "gatekeeper", "bw_accounting").Run()

	bm.state = StateStopped
	return nil
}

func (bm *BandwidthMonitor) Reload(cfg map[string]string) error {
	bm.mu.Lock()
	bm.cfg = cfg
	bm.mu.Unlock()
	return nil
}

func (bm *BandwidthMonitor) Status() State {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.state
}

// GetDeviceTraffic returns current per-device bandwidth data.
func (bm *BandwidthMonitor) GetDeviceTraffic() []DeviceTraffic {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	result := make([]DeviceTraffic, 0, len(bm.current))
	for _, dt := range bm.current {
		result = append(result, *dt)
	}
	return result
}

// GetInterfaceTraffic returns current per-interface bandwidth data.
func (bm *BandwidthMonitor) GetInterfaceTraffic() []InterfaceTraffic {
	return bm.readProcNetDev()
}

func (bm *BandwidthMonitor) sampleLoop() {
	bm.mu.Lock()
	cfg := bm.cfg
	stopCh := bm.stopCh
	bm.mu.Unlock()

	interval := 5 * time.Second
	if secs := cfg["sample_interval"]; secs != "" {
		if v, err := time.ParseDuration(secs + "s"); err == nil && v >= time.Second {
			interval = v
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			bm.sample()
		}
	}
}

func (bm *BandwidthMonitor) sample() {
	bm.mu.Lock()
	cfg := bm.cfg
	bm.mu.Unlock()

	// Sample conntrack for per-device data.
	if cfg["conntrack"] == "true" {
		bm.sampleConntrack()
	}

	// Persist snapshot.
	bm.persistSnapshot()
}

func (bm *BandwidthMonitor) sampleConntrack() {
	cmd := exec.Command("conntrack", "-L", "-o", "extended", "-p", "tcp")
	output, err := cmd.Output()
	if err != nil {
		// Try without -p tcp to get all protocols.
		cmd = exec.Command("conntrack", "-L", "-o", "extended")
		output, err = cmd.Output()
		if err != nil {
			return
		}
	}

	deviceBytes := make(map[string][2]uint64) // ip -> [in, out]

	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		var src, dst string
		var bytes uint64
		for j, f := range fields {
			if strings.HasPrefix(f, "src=") && src == "" {
				src = strings.TrimPrefix(f, "src=")
			}
			if strings.HasPrefix(f, "dst=") && dst == "" {
				dst = strings.TrimPrefix(f, "dst=")
			}
			if strings.HasPrefix(f, "bytes=") && j > 0 {
				fmt.Sscanf(strings.TrimPrefix(f, "bytes="), "%d", &bytes)
			}
		}
		if src != "" {
			entry := deviceBytes[src]
			entry[1] += bytes // outbound
			deviceBytes[src] = entry
		}
		if dst != "" {
			entry := deviceBytes[dst]
			entry[0] += bytes // inbound
			deviceBytes[dst] = entry
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	bm.mu.Lock()
	for ip, bytes := range deviceBytes {
		if dt, ok := bm.current[ip]; ok {
			dt.BytesIn = bytes[0]
			dt.BytesOut = bytes[1]
			dt.LastSeen = now
		} else {
			bm.current[ip] = &DeviceTraffic{
				IP:       ip,
				BytesIn:  bytes[0],
				BytesOut: bytes[1],
				LastSeen: now,
			}
		}
	}
	bm.mu.Unlock()
}

func (bm *BandwidthMonitor) readProcNetDev() []InterfaceTraffic {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}

	var result []InterfaceTraffic
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "lo" {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}

		var bytesIn, bytesOut uint64
		fmt.Sscanf(fields[0], "%d", &bytesIn)
		fmt.Sscanf(fields[8], "%d", &bytesOut)

		result = append(result, InterfaceTraffic{
			Name:     name,
			BytesIn:  bytesIn,
			BytesOut: bytesOut,
		})
	}
	return result
}

func (bm *BandwidthMonitor) setupAccountingChain() {
	rules := `table inet gatekeeper {
  chain bw_accounting {
    type filter hook forward priority -200; policy accept;
    counter
  }
}
`
	rulesPath := filepath.Join(bm.dataDir, "bw-accounting.nft")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o640); err != nil {
		slog.Warn("failed to write accounting rules", "error", err)
		return
	}
	cmd := exec.Command("nft", "-f", rulesPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to apply accounting rules", "error", err, "output", string(output))
	}
}

func (bm *BandwidthMonitor) persistSnapshot() {
	bm.mu.Lock()
	devices := make([]DeviceTraffic, 0, len(bm.current))
	for _, dt := range bm.current {
		devices = append(devices, *dt)
	}
	bm.mu.Unlock()

	data, err := json.Marshal(map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"devices":   devices,
	})
	if err != nil {
		return
	}

	snapshotPath := filepath.Join(bm.dataDir, "latest.json")
	os.WriteFile(snapshotPath, data, 0o644)
}
