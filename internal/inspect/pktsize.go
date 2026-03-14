package inspect

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// PacketSizeProfile tracks packet size distribution per source IP.
type PacketSizeProfile struct {
	SrcIP string
	DstIP string
	Sizes []int // Observed packet sizes (IP total length)
}

// PacketSizeFingerprint captures the packet size distribution of a host.
// Different OS/application stacks produce different MTU, typical payload sizes,
// and fragmentation behavior.
type PacketSizeFingerprint struct {
	Hash         string    `json:"hash"`           // Truncated SHA256 of size distribution
	AvgSize      float64   `json:"avg_size"`       // Average packet size
	StdDevSize   float64   `json:"stddev_size"`    // Std deviation of sizes
	MinSize      int       `json:"min_size"`       // Minimum observed size
	MaxSize      int       `json:"max_size"`       // Maximum observed (likely MTU)
	MedianSize   int       `json:"median_size"`    // Median packet size
	P95Size      int       `json:"p95_size"`       // 95th percentile
	Fragmented   bool      `json:"fragmented"`     // Any fragmented packets seen
	MTUEstimate  int       `json:"mtu_estimate"`   // Estimated MTU from max sizes
	SampleCount  int       `json:"sample_count"`   // Number of packets sampled
	Distribution []int     `json:"distribution"`   // Histogram buckets (0-100, 100-500, 500-1000, 1000-1500, 1500+)
	Alerts       []string  `json:"alerts"`         // Unusual patterns
	SrcIP        string    `json:"src_ip"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Count        int64     `json:"count"`
}

// PacketSizeTracker accumulates packet size observations per IP.
type PacketSizeTracker struct {
	mu       sync.Mutex
	profiles map[string]*sizeAccumulator // keyed by srcIP
	maxAge   time.Duration
}

type sizeAccumulator struct {
	srcIP      string
	sizes      []int
	fragmented bool
	lastSeen   time.Time
}

// NewPacketSizeTracker creates a new packet size tracker.
func NewPacketSizeTracker(maxAge time.Duration) *PacketSizeTracker {
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	return &PacketSizeTracker{
		profiles: make(map[string]*sizeAccumulator),
		maxAge:   maxAge,
	}
}

// RecordSize records a packet size observation.
// fragmented indicates if the IP fragmentation flag or offset is set.
func (t *PacketSizeTracker) RecordSize(srcIP string, size int, fragmented bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	acc, ok := t.profiles[srcIP]
	if !ok {
		acc = &sizeAccumulator{srcIP: srcIP}
		t.profiles[srcIP] = acc
	}

	if len(acc.sizes) < 10000 { // Cap stored samples.
		acc.sizes = append(acc.sizes, size)
	}
	if fragmented {
		acc.fragmented = true
	}
	acc.lastSeen = time.Now()
}

// Analyze generates a PacketSizeFingerprint for a given source IP.
func (t *PacketSizeTracker) Analyze(srcIP string) *PacketSizeFingerprint {
	t.mu.Lock()
	acc, ok := t.profiles[srcIP]
	if !ok || len(acc.sizes) < 5 {
		t.mu.Unlock()
		return nil
	}
	// Copy data under lock.
	sizes := make([]int, len(acc.sizes))
	copy(sizes, acc.sizes)
	fragmented := acc.fragmented
	t.mu.Unlock()

	sort.Ints(sizes)

	n := len(sizes)
	minSize := sizes[0]
	maxSize := sizes[n-1]
	medianSize := sizes[n/2]
	p95Size := sizes[int(float64(n)*0.95)]

	var sum float64
	for _, s := range sizes {
		sum += float64(s)
	}
	avg := sum / float64(n)

	var variance float64
	for _, s := range sizes {
		diff := float64(s) - avg
		variance += diff * diff
	}
	stddev := math.Sqrt(variance / float64(n))

	// Histogram: [0-100), [100-500), [500-1000), [1000-1500), [1500+)
	hist := make([]int, 5)
	for _, s := range sizes {
		switch {
		case s < 100:
			hist[0]++
		case s < 500:
			hist[1]++
		case s < 1000:
			hist[2]++
		case s < 1500:
			hist[3]++
		default:
			hist[4]++
		}
	}

	// MTU estimate: commonly 1500 (Ethernet), 1480 (tunnel), 1280 (IPv6 min), 576 (min IPv4).
	mtu := estimateMTU(maxSize)

	var alerts []string
	if fragmented {
		alerts = append(alerts, "IP fragmentation observed")
	}
	if maxSize > 1500 {
		alerts = append(alerts, fmt.Sprintf("jumbo frames detected: %d bytes", maxSize))
	}
	// All same size = likely generated traffic.
	if stddev < 1.0 && n > 10 {
		alerts = append(alerts, "constant packet size (likely generated traffic)")
	}
	// Very small packets only = possible covert channel.
	if maxSize < 100 && n > 20 {
		alerts = append(alerts, "all packets very small (possible covert channel)")
	}

	raw := fmt.Sprintf("%.0f:%.0f:%d:%d:%d", avg, stddev, minSize, maxSize, mtu)
	hash := truncHash(raw)

	now := time.Now()
	return &PacketSizeFingerprint{
		Hash:         hash,
		AvgSize:      avg,
		StdDevSize:   stddev,
		MinSize:      minSize,
		MaxSize:      maxSize,
		MedianSize:   medianSize,
		P95Size:      p95Size,
		Fragmented:   fragmented,
		MTUEstimate:  mtu,
		SampleCount:  n,
		Distribution: hist,
		Alerts:       alerts,
		SrcIP:        srcIP,
		FirstSeen:    now,
		LastSeen:     now,
		Count:        int64(n),
	}
}

// Prune removes profiles older than maxAge.
func (t *PacketSizeTracker) Prune() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-t.maxAge)
	for key, acc := range t.profiles {
		if acc.lastSeen.Before(cutoff) {
			delete(t.profiles, key)
		}
	}
}

// estimateMTU infers MTU from maximum packet size.
func estimateMTU(maxSize int) int {
	switch {
	case maxSize >= 9000:
		return 9000 // Jumbo frames
	case maxSize >= 1500:
		return 1500 // Standard Ethernet
	case maxSize >= 1480:
		return 1480 // Tunnel/VPN overhead
	case maxSize >= 1280:
		return 1280 // IPv6 minimum
	default:
		return 576 // IPv4 minimum
	}
}
