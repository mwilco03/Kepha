package inspect

import (
	"testing"
	"time"
)

func TestTimingTracker_Basic(t *testing.T) {
	tracker := NewTimingTracker(5 * time.Minute)

	now := time.Now()
	for i := 0; i < 20; i++ {
		tracker.RecordPacket("10.0.0.1", "10.0.0.2", now.Add(time.Duration(i)*100*time.Millisecond))
	}

	fp := tracker.Analyze("10.0.0.1")
	if fp == nil {
		t.Fatal("expected fingerprint, got nil")
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.AvgIPT <= 0 {
		t.Errorf("avg_ipt = %.2f, want > 0", fp.AvgIPT)
	}
	if fp.Count == 0 {
		t.Error("count should be > 0")
	}
}

func TestTimingTracker_RTT(t *testing.T) {
	tracker := NewTimingTracker(5 * time.Minute)

	now := time.Now()
	tracker.RecordSYN("10.0.0.1", "10.0.0.2", now)
	// SYN-ACK comes from the server (10.0.0.2) back to the client (10.0.0.1).
	tracker.RecordSYNACK("10.0.0.2", "10.0.0.1", now.Add(50*time.Millisecond))

	// Need some inter-packet times too.
	for i := 0; i < 10; i++ {
		tracker.RecordPacket("10.0.0.1", "10.0.0.2", now.Add(time.Duration(i)*10*time.Millisecond))
	}

	fp := tracker.Analyze("10.0.0.1")
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	if fp.RTTEstimate < 40 || fp.RTTEstimate > 60 {
		t.Errorf("rtt = %.2f, want ~50ms", fp.RTTEstimate)
	}
}

func TestTimingTracker_NotEnoughData(t *testing.T) {
	tracker := NewTimingTracker(5 * time.Minute)

	// Only 1 packet = not enough.
	tracker.RecordPacket("10.0.0.1", "10.0.0.2", time.Now())

	fp := tracker.Analyze("10.0.0.1")
	if fp != nil {
		t.Error("expected nil for insufficient data")
	}
}

func TestTimingTracker_UnknownIP(t *testing.T) {
	tracker := NewTimingTracker(5 * time.Minute)

	fp := tracker.Analyze("10.0.0.99")
	if fp != nil {
		t.Error("expected nil for unknown IP")
	}
}

func TestTimingTracker_Prune(t *testing.T) {
	tracker := NewTimingTracker(1 * time.Millisecond)

	tracker.RecordPacket("10.0.0.1", "10.0.0.2", time.Now().Add(-time.Second))
	time.Sleep(2 * time.Millisecond)

	tracker.Prune()

	tracker.mu.Lock()
	count := len(tracker.sessions)
	tracker.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 sessions after prune, got %d", count)
	}
}

func TestClassifyTiming_Automated(t *testing.T) {
	profile, alerts := classifyTiming(10.0, 0.5, 9.5, 10.5, 0)
	if profile != "automated" {
		t.Errorf("profile = %q, want automated", profile)
	}
	if len(alerts) == 0 {
		t.Error("expected alert for automated timing")
	}
}

func TestClassifyTiming_Scanner(t *testing.T) {
	profile, _ := classifyTiming(0.05, 0.01, 0.01, 0.1, 0)
	if profile != "scanner" {
		t.Errorf("profile = %q, want scanner", profile)
	}
}

func TestComputeStats(t *testing.T) {
	durations := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}

	avg, _, min, max := computeStats(durations)
	if avg != 30.0 {
		t.Errorf("avg = %.2f, want 30.0", avg)
	}
	if min != 10.0 {
		t.Errorf("min = %.2f, want 10.0", min)
	}
	if max != 50.0 {
		t.Errorf("max = %.2f, want 50.0", max)
	}
}
