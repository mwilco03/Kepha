package xdp

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// EBPFLoader implements the BPFLoader interface using a dual-map atomic
// swap strategy for zero-downtime blocklist updates.
//
// # Dual-Map Architecture
//
// The loader maintains two copies of the blocklist map: "active" and "standby".
// At any moment, the XDP program reads from the active map. During an update:
//
//  1. Populate the standby map with the new blocklist
//  2. Atomically swap the prog_array tail-call entry to point to a program
//     that reads from the standby map
//  3. The standby map becomes active; the old active becomes standby
//  4. Clear the now-standby map (ready for next update)
//
// This guarantees:
//   - No window where the blocklist is partially populated
//   - No packet drops during update (XDP_PASS continues working)
//   - Instant rollback: swap back to the previous map
//
// # Failover Strategy
//
// If map population fails mid-update:
//   - The active map remains active (no swap occurs)
//   - The failed standby map is cleared
//   - An error is logged but packet processing continues uninterrupted
//
// If program attachment fails:
//   - Fall back to generic mode if native mode fails
//   - Fall back to no-XDP (pure nftables) if generic also fails
//   - Log the degradation so the operator knows
//
// # Failback Strategy
//
// After a failover to degraded mode, the loader periodically retries:
//   - Every 30 seconds, attempt to re-attach in the preferred mode
//   - On success, transparently upgrade back to optimal mode
//   - Rate-limited to prevent retry storms
type EBPFLoader struct {
	mu sync.Mutex

	// Dual maps: two blocklist versions for atomic swap.
	maps [2]*BlocklistMap
	// activeIdx is 0 or 1, indicating which map is currently active.
	activeIdx atomic.Int32

	// Attachment state.
	programs  map[string]*AttachedProgram // ifname -> program state
	preferred AttachMode
	actual    AttachMode
	degraded  bool

	// Failback retry state.
	lastRetry    time.Time
	retryBackoff time.Duration

	// Lifecycle.
	loaded bool
	stopCh chan struct{}
}

// BlocklistMap represents one side of the dual-map pair.
// In a real implementation this wraps a *ebpf.Map handle.
// Here we use the control-plane representation.
type BlocklistMap struct {
	mu      sync.RWMutex
	entries map[[4]byte]uint8   // IPv4: network-order key -> blocked flag
	entries6 map[[16]byte]uint8 // IPv6
	version uint64              // monotonic version counter
	updated time.Time
	dirty   bool
}

// AttachedProgram tracks an XDP program attached to an interface.
type AttachedProgram struct {
	IfName   string
	IfIndex  int
	Mode     AttachMode
	FD       int       // BPF program FD (or simulated)
	Attached bool
	Since    time.Time
}

// SwapResult records the outcome of a dual-map swap operation.
type SwapResult struct {
	Success     bool      `json:"success"`
	PreviousMap int       `json:"previous_map"`  // 0 or 1
	ActiveMap   int       `json:"active_map"`     // 0 or 1
	EntriesOld  int       `json:"entries_old"`
	EntriesNew  int       `json:"entries_new"`
	SwapTime    time.Time `json:"swap_time"`
	Duration    time.Duration `json:"duration"`
	Error       string    `json:"error,omitempty"`
}

// NewEBPFLoader creates a new eBPF program loader with dual-map support.
func NewEBPFLoader(preferredMode AttachMode) *EBPFLoader {
	l := &EBPFLoader{
		programs:     make(map[string]*AttachedProgram),
		preferred:    preferredMode,
		actual:       preferredMode,
		retryBackoff: 30 * time.Second,
		stopCh:       make(chan struct{}),
	}

	// Initialize dual maps.
	l.maps[0] = newBlocklistMap()
	l.maps[1] = newBlocklistMap()

	return l
}

func newBlocklistMap() *BlocklistMap {
	return &BlocklistMap{
		entries:  make(map[[4]byte]uint8),
		entries6: make(map[[16]byte]uint8),
	}
}

// Load initializes the BPF programs and maps.
//
// EXPERIMENTAL: XDP/eBPF support is a control-plane stub. Load() and Attach()
// validate configuration and track state, but no BPF programs are actually
// loaded or attached to interfaces. Real attachment requires the cilium/ebpf
// dependency and compiled BPF ELF objects, which are not yet included.
//
// A full implementation would:
//  1. Load compiled BPF ELF via cilium/ebpf
//  2. Pin maps to /sys/fs/bpf/gatekeeper/
//  3. Set up the prog_array for tail calls
func (l *EBPFLoader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return nil
	}

	slog.Warn("XDP loader is EXPERIMENTAL: no BPF programs are attached (control-plane stub only)",
		"preferred_mode", l.preferred.String(),
	)

	l.loaded = true
	return nil
}

// Attach attaches the XDP program to an interface with failover.
//
// Attach order:
//  1. Try preferred mode (e.g. native)
//  2. If native fails, fall back to generic
//  3. If generic fails, return error (no XDP possible)
func (l *EBPFLoader) Attach(ifName string, ifIndex int, mode AttachMode) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("programs not loaded — call Load() first")
	}

	// Try preferred mode first.
	err := l.tryAttach(ifName, ifIndex, mode)
	if err == nil {
		l.programs[ifName] = &AttachedProgram{
			IfName:   ifName,
			IfIndex:  ifIndex,
			Mode:     mode,
			Attached: true,
			Since:    time.Now(),
		}
		l.actual = mode
		l.degraded = false
		slog.Info("XDP program attached",
			"interface", ifName,
			"mode", mode.String(),
		)
		return nil
	}

	// Failover: try generic mode if native failed.
	if mode != AttachModeGeneric {
		slog.Warn("preferred XDP mode failed, falling back to generic",
			"interface", ifName,
			"preferred", mode.String(),
			"error", err,
		)

		err2 := l.tryAttach(ifName, ifIndex, AttachModeGeneric)
		if err2 == nil {
			l.programs[ifName] = &AttachedProgram{
				IfName:   ifName,
				IfIndex:  ifIndex,
				Mode:     AttachModeGeneric,
				Attached: true,
				Since:    time.Now(),
			}
			l.actual = AttachModeGeneric
			l.degraded = true
			slog.Warn("XDP running in degraded mode (generic instead of native)",
				"interface", ifName,
			)
			return nil
		}
		err = fmt.Errorf("native: %v; generic: %v", err, err2)
	}

	return fmt.Errorf("attach XDP to %s: %w", ifName, err)
}

// tryAttach attempts to attach the XDP program in a specific mode.
//
// EXPERIMENTAL: This is a stub. No BPF programs are actually attached.
// Real attachment requires cilium/ebpf link.AttachXDP(). This stub validates
// parameters and records state so the rest of the control plane works correctly.
func (l *EBPFLoader) tryAttach(ifName string, ifIndex int, mode AttachMode) error {
	if ifIndex <= 0 {
		return fmt.Errorf("invalid interface index: %d", ifIndex)
	}
	slog.Warn("XDP tryAttach is a stub — no BPF program attached",
		"interface", ifName, "index", ifIndex, "mode", mode.String())
	return nil
}

// Detach removes the XDP program from an interface.
func (l *EBPFLoader) Detach(ifName string, ifIndex int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	prog, ok := l.programs[ifName]
	if !ok {
		return fmt.Errorf("interface %q not attached", ifName)
	}

	prog.Attached = false
	delete(l.programs, ifName)

	slog.Info("XDP program detached", "interface", ifName)
	return nil
}

// UpdateBlocklist performs an atomic dual-map swap to update the blocklist.
//
// The sequence is:
//  1. Identify the standby map (opposite of active)
//  2. Clear the standby map
//  3. Populate the standby map with new entries
//  4. Atomically swap: standby becomes active
//  5. The old active (now standby) is available for rollback
//
// If population fails at step 3, the active map is untouched.
func (l *EBPFLoader) UpdateBlocklist(entries map[[4]byte]uint8) error {
	result := l.atomicSwapV4(entries)
	if !result.Success {
		return fmt.Errorf("blocklist swap failed: %s", result.Error)
	}

	slog.Info("blocklist updated via atomic swap",
		"previous_map", result.PreviousMap,
		"active_map", result.ActiveMap,
		"entries_old", result.EntriesOld,
		"entries_new", result.EntriesNew,
		"swap_duration", result.Duration,
	)
	return nil
}

// atomicSwapV4 performs the dual-map atomic swap for IPv4 blocklist.
func (l *EBPFLoader) atomicSwapV4(entries map[[4]byte]uint8) SwapResult {
	start := time.Now()
	currentActive := int(l.activeIdx.Load())
	standbyIdx := 1 - currentActive

	result := SwapResult{
		PreviousMap: currentActive,
		SwapTime:    start,
	}

	activeMap := l.maps[currentActive]
	standbyMap := l.maps[standbyIdx]

	// Step 1: Record old entry count.
	activeMap.mu.RLock()
	result.EntriesOld = len(activeMap.entries)
	activeMap.mu.RUnlock()

	// Step 2: Clear the standby map.
	standbyMap.mu.Lock()
	standbyMap.entries = make(map[[4]byte]uint8, len(entries))

	// Step 3: Populate standby with new entries.
	for k, v := range entries {
		standbyMap.entries[k] = v
	}
	standbyMap.version++
	standbyMap.updated = time.Now()
	standbyMap.dirty = false
	result.EntriesNew = len(standbyMap.entries)
	standbyMap.mu.Unlock()

	// Step 4: Atomic swap — the standby index becomes active.
	// In a real BPF implementation, this would update the prog_array
	// tail-call entry to point to a program reading the standby map:
	//
	//   err := l.progArray.Update(uint32(PROG_BLOCKLIST),
	//       uint32(l.blocklistProgs[standbyIdx].FD()),
	//       ebpf.UpdateAny)
	//
	// This is a single map update — atomic from the XDP program's perspective.
	// Any packet in-flight on the old program completes; the next packet
	// uses the new program. No locking needed in the data path.
	l.activeIdx.Store(int32(standbyIdx))

	result.ActiveMap = standbyIdx
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// UpdateBlocklist6 performs an atomic dual-map swap for IPv6 blocklist.
func (l *EBPFLoader) UpdateBlocklist6(entries map[[16]byte]uint8) error {
	currentActive := int(l.activeIdx.Load())
	standbyIdx := 1 - currentActive

	standbyMap := l.maps[standbyIdx]

	standbyMap.mu.Lock()
	standbyMap.entries6 = make(map[[16]byte]uint8, len(entries))
	for k, v := range entries {
		standbyMap.entries6[k] = v
	}
	standbyMap.mu.Unlock()

	// The IPv6 map is swapped together with IPv4 in the next UpdateBlocklist call,
	// or can be triggered independently via SwapNow().
	return nil
}

// SwapNow forces an immediate swap of active/standby maps without
// repopulating. Used for instant rollback.
func (l *EBPFLoader) SwapNow() SwapResult {
	start := time.Now()
	current := int(l.activeIdx.Load())
	next := 1 - current

	l.activeIdx.Store(int32(next))

	return SwapResult{
		Success:     true,
		PreviousMap: current,
		ActiveMap:   next,
		SwapTime:    start,
		Duration:    time.Since(start),
	}
}

// Rollback reverts to the previous blocklist by swapping maps back.
// This is instant because the old map's data is still intact.
func (l *EBPFLoader) Rollback() SwapResult {
	slog.Info("rolling back blocklist to previous version")
	result := l.SwapNow()
	if result.Success {
		activeMap := l.maps[result.ActiveMap]
		activeMap.mu.RLock()
		result.EntriesNew = len(activeMap.entries)
		activeMap.mu.RUnlock()
	}
	return result
}

// ReadStats reads per-CPU statistics from the BPF stats map.
// In a real implementation, this calls map.Lookup() and aggregates per-CPU values.
func (l *EBPFLoader) ReadStats(ifIndex int) (Stats, error) {
	// In a real cilium/ebpf implementation:
	//
	//   var key StatsKey
	//   var values []StatsValue  // per-CPU array
	//   key.Ifindex = uint32(ifIndex)
	//
	//   for _, action := range []uint32{XDP_DROP, XDP_PASS} {
	//       key.Action = action
	//       err := l.statsMap.Lookup(&key, &values)
	//       // Sum across CPUs:
	//       for _, v := range values {
	//           total.Packets += v.Packets
	//           total.Bytes += v.Bytes
	//       }
	//   }
	return Stats{}, nil
}

// Close releases all BPF resources.
func (l *EBPFLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return nil
	}

	// Detach all programs.
	for ifName := range l.programs {
		slog.Info("detaching XDP on close", "interface", ifName)
	}
	l.programs = make(map[string]*AttachedProgram)

	close(l.stopCh)
	l.loaded = false
	slog.Info("BPF resources released")
	return nil
}

// ActiveMapIndex returns which map (0 or 1) is currently active.
func (l *EBPFLoader) ActiveMapIndex() int {
	return int(l.activeIdx.Load())
}

// MapInfo returns metadata about both maps for diagnostics.
func (l *EBPFLoader) MapInfo() [2]MapDiag {
	var info [2]MapDiag
	activeIdx := int(l.activeIdx.Load())

	for i := 0; i < 2; i++ {
		m := l.maps[i]
		m.mu.RLock()
		info[i] = MapDiag{
			Index:      i,
			Active:     i == activeIdx,
			EntriesV4:  len(m.entries),
			EntriesV6:  len(m.entries6),
			Version:    m.version,
			LastUpdate: m.updated,
		}
		m.mu.RUnlock()
	}
	return info
}

// MapDiag is diagnostic info for one map in the dual-map pair.
type MapDiag struct {
	Index      int       `json:"index"`
	Active     bool      `json:"active"`
	EntriesV4  int       `json:"entries_v4"`
	EntriesV6  int       `json:"entries_v6"`
	Version    uint64    `json:"version"`
	LastUpdate time.Time `json:"last_update"`
}

// IsDegraded returns whether the loader is running in a fallback mode.
func (l *EBPFLoader) IsDegraded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.degraded
}

// RetryPreferredMode attempts to upgrade from degraded generic mode back
// to the preferred native mode. Called periodically by the service.
func (l *EBPFLoader) RetryPreferredMode() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.degraded {
		return nil // Already in preferred mode.
	}

	// Rate limit retries.
	if time.Since(l.lastRetry) < l.retryBackoff {
		return nil
	}
	l.lastRetry = time.Now()

	// Try to re-attach each interface in preferred mode.
	for ifName, prog := range l.programs {
		if prog.Mode == l.preferred {
			continue // Already in preferred mode.
		}

		err := l.tryAttach(ifName, prog.IfIndex, l.preferred)
		if err != nil {
			// Increase backoff (capped at 5 minutes).
			l.retryBackoff = l.retryBackoff * 2
			if l.retryBackoff > 5*time.Minute {
				l.retryBackoff = 5 * time.Minute
			}
			return fmt.Errorf("failback attempt failed for %s: %w", ifName, err)
		}

		// Success — upgrade this interface.
		prog.Mode = l.preferred
		prog.Since = time.Now()
		slog.Info("XDP failback successful — upgraded to preferred mode",
			"interface", ifName,
			"mode", l.preferred.String(),
		)
	}

	l.degraded = false
	l.actual = l.preferred
	l.retryBackoff = 30 * time.Second // Reset backoff.
	return nil
}
