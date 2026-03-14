package inspect

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// TimingProfile tracks inter-packet timing characteristics per source IP.
// Timing analysis reveals proxies, VPNs, Tor exits, and automated tools.
type TimingProfile struct {
	SrcIP string
	DstIP string

	// Connection-level timing.
	SYNToSYNACK time.Duration // SYN → SYN-ACK latency (RTT estimate)
	TLSHandshake time.Duration // ClientHello → ServerHello latency

	// Inter-packet timing for fingerprinting.
	InterPacketTimes []time.Duration // Time between consecutive packets
}

// TimingFingerprint is a per-IP timing behavior fingerprint.
type TimingFingerprint struct {
	Hash        string    `json:"hash"`          // Truncated SHA256 of timing profile
	AvgIPT      float64   `json:"avg_ipt_ms"`    // Average inter-packet time (ms)
	StdDevIPT   float64   `json:"stddev_ipt_ms"` // Std deviation of inter-packet time
	MinIPT      float64   `json:"min_ipt_ms"`    // Minimum inter-packet time
	MaxIPT      float64   `json:"max_ipt_ms"`    // Maximum inter-packet time
	RTTEstimate float64   `json:"rtt_ms"`        // Estimated RTT (ms)
	Jitter      float64   `json:"jitter_ms"`     // Timing jitter (ms)
	Profile     string    `json:"profile"`       // "human", "automated", "proxy"
	Alerts      []string  `json:"alerts"`        // Suspicious timing patterns
	SrcIP       string    `json:"src_ip"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int64     `json:"count"`
}

// TimingTracker accumulates timing observations per IP for analysis.
type TimingTracker struct {
	mu       sync.Mutex
	sessions map[string]*timingSession // keyed by "srcIP:dstIP"
	maxAge   time.Duration             // Sessions older than this are pruned
}

type timingSession struct {
	srcIP     string
	dstIP     string
	lastSeen  time.Time
	synTime   time.Time     // When SYN was observed
	synAckTime time.Time    // When SYN-ACK was observed
	helloTime  time.Time    // When ClientHello was observed
	shelloTime time.Time    // When ServerHello was observed
	lastPkt   time.Time     // Last packet timestamp
	ipts      []time.Duration // Inter-packet times (capped)
}

// NewTimingTracker creates a new timing tracker.
func NewTimingTracker(maxAge time.Duration) *TimingTracker {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	return &TimingTracker{
		sessions: make(map[string]*timingSession),
		maxAge:   maxAge,
	}
}

// RecordPacket records a packet timestamp for timing analysis.
func (t *TimingTracker) RecordPacket(srcIP, dstIP string, ts time.Time) {
	key := srcIP + ":" + dstIP
	t.mu.Lock()
	defer t.mu.Unlock()

	sess, ok := t.sessions[key]
	if !ok {
		sess = &timingSession{
			srcIP:    srcIP,
			dstIP:    dstIP,
			lastSeen: ts,
			lastPkt:  ts,
		}
		t.sessions[key] = sess
		return
	}

	// Record inter-packet time.
	if !sess.lastPkt.IsZero() {
		ipt := ts.Sub(sess.lastPkt)
		if ipt > 0 && ipt < 30*time.Second { // Ignore huge gaps.
			if len(sess.ipts) < 1000 { // Cap stored samples.
				sess.ipts = append(sess.ipts, ipt)
			}
		}
	}

	sess.lastPkt = ts
	sess.lastSeen = ts
}

// RecordSYN records a TCP SYN timestamp.
func (t *TimingTracker) RecordSYN(srcIP, dstIP string, ts time.Time) {
	key := srcIP + ":" + dstIP
	t.mu.Lock()
	defer t.mu.Unlock()

	sess, ok := t.sessions[key]
	if !ok {
		sess = &timingSession{srcIP: srcIP, dstIP: dstIP, lastSeen: ts}
		t.sessions[key] = sess
	}
	sess.synTime = ts
	sess.lastSeen = ts
}

// RecordSYNACK records a TCP SYN-ACK timestamp.
func (t *TimingTracker) RecordSYNACK(srcIP, dstIP string, ts time.Time) {
	// SYN-ACK comes from dstIP back to srcIP, so key is reversed.
	key := dstIP + ":" + srcIP
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, ok := t.sessions[key]; ok {
		sess.synAckTime = ts
		sess.lastSeen = ts
	}
}

// RecordClientHello records a TLS ClientHello timestamp.
func (t *TimingTracker) RecordClientHello(srcIP, dstIP string, ts time.Time) {
	key := srcIP + ":" + dstIP
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, ok := t.sessions[key]; ok {
		sess.helloTime = ts
		sess.lastSeen = ts
	}
}

// RecordServerHello records a TLS ServerHello timestamp.
func (t *TimingTracker) RecordServerHello(srcIP, dstIP string, ts time.Time) {
	key := dstIP + ":" + srcIP
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, ok := t.sessions[key]; ok {
		sess.shelloTime = ts
		sess.lastSeen = ts
	}
}

// Analyze generates a TimingFingerprint for a given source IP.
// Aggregates timing data across all sessions from that IP.
func (t *TimingTracker) Analyze(srcIP string) *TimingFingerprint {
	t.mu.Lock()
	defer t.mu.Unlock()

	var allIPTs []time.Duration
	var rttSamples []time.Duration
	var tlsSamples []time.Duration

	for _, sess := range t.sessions {
		if sess.srcIP != srcIP {
			continue
		}
		allIPTs = append(allIPTs, sess.ipts...)
		if !sess.synTime.IsZero() && !sess.synAckTime.IsZero() {
			rtt := sess.synAckTime.Sub(sess.synTime)
			if rtt > 0 && rtt < 10*time.Second {
				rttSamples = append(rttSamples, rtt)
			}
		}
		if !sess.helloTime.IsZero() && !sess.shelloTime.IsZero() {
			hs := sess.shelloTime.Sub(sess.helloTime)
			if hs > 0 && hs < 10*time.Second {
				tlsSamples = append(tlsSamples, hs)
			}
		}
	}

	if len(allIPTs) < 2 {
		return nil // Not enough data.
	}

	// Compute statistics.
	avg, stddev, minIPT, maxIPT := computeStats(allIPTs)

	var rttEstimate float64
	if len(rttSamples) > 0 {
		for _, r := range rttSamples {
			rttEstimate += float64(r.Microseconds())
		}
		rttEstimate = rttEstimate / float64(len(rttSamples)) / 1000.0
	}

	_ = tlsSamples // Reserved for future TLS timing analysis.

	// Classify the timing profile.
	profile, alerts := classifyTiming(avg, stddev, minIPT, maxIPT, rttEstimate)

	raw := fmt.Sprintf("%.2f:%.2f:%.2f:%.2f", avg, stddev, minIPT, maxIPT)
	hash := truncHash(raw)

	now := time.Now()
	return &TimingFingerprint{
		Hash:        hash,
		AvgIPT:      avg,
		StdDevIPT:   stddev,
		MinIPT:      minIPT,
		MaxIPT:      maxIPT,
		RTTEstimate: rttEstimate,
		Jitter:      stddev,
		Profile:     profile,
		Alerts:      alerts,
		SrcIP:       srcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       int64(len(allIPTs)),
	}
}

// Prune removes sessions older than maxAge.
func (t *TimingTracker) Prune() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-t.maxAge)
	for key, sess := range t.sessions {
		if sess.lastSeen.Before(cutoff) {
			delete(t.sessions, key)
		}
	}
}

// computeStats returns average, stddev, min, and max of durations in milliseconds.
func computeStats(durations []time.Duration) (avg, stddev, min, max float64) {
	if len(durations) == 0 {
		return
	}

	min = math.MaxFloat64
	var sum float64
	for _, d := range durations {
		ms := float64(d.Microseconds()) / 1000.0
		sum += ms
		if ms < min {
			min = ms
		}
		if ms > max {
			max = ms
		}
	}
	avg = sum / float64(len(durations))

	var variance float64
	for _, d := range durations {
		ms := float64(d.Microseconds()) / 1000.0
		diff := ms - avg
		variance += diff * diff
	}
	stddev = math.Sqrt(variance / float64(len(durations)))

	return
}

// classifyTiming categorizes traffic based on timing characteristics.
func classifyTiming(avg, stddev, minIPT, maxIPT, rtt float64) (string, []string) {
	var alerts []string
	profile := "normal"

	// Very consistent timing = likely automated.
	if stddev < 1.0 && avg < 50.0 {
		profile = "automated"
		alerts = append(alerts, "extremely consistent timing (likely bot/script)")
	}

	// High jitter with long RTT = likely proxy/VPN/Tor.
	if rtt > 200.0 && stddev > 50.0 {
		profile = "proxy"
		alerts = append(alerts, fmt.Sprintf("high RTT (%.0fms) with jitter — possible proxy/VPN", rtt))
	}

	// Very fast bursts = scanner or attack tool.
	if minIPT < 0.1 && avg < 1.0 {
		profile = "scanner"
		alerts = append(alerts, "sub-millisecond inter-packet times (scanner/flooding)")
	}

	// Normal human browsing has high variance.
	if stddev > avg*0.5 && avg > 100.0 {
		profile = "human"
	}

	return profile, alerts
}
