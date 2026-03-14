package inspect

import (
	"testing"
	"time"
)

func TestPacketSizeTracker_Basic(t *testing.T) {
	tracker := NewPacketSizeTracker(5 * time.Minute)

	// Simulate a mix of packet sizes.
	sizes := []int{54, 54, 1500, 1500, 1500, 800, 400, 54, 1200, 900}
	for _, s := range sizes {
		tracker.RecordSize("10.0.0.1", s, false)
	}

	fp := tracker.Analyze("10.0.0.1")
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.MinSize != 54 {
		t.Errorf("min = %d, want 54", fp.MinSize)
	}
	if fp.MaxSize != 1500 {
		t.Errorf("max = %d, want 1500", fp.MaxSize)
	}
	if fp.SampleCount != 10 {
		t.Errorf("samples = %d, want 10", fp.SampleCount)
	}
	if fp.MTUEstimate != 1500 {
		t.Errorf("mtu = %d, want 1500", fp.MTUEstimate)
	}
}

func TestPacketSizeTracker_Fragmentation(t *testing.T) {
	tracker := NewPacketSizeTracker(5 * time.Minute)

	for i := 0; i < 10; i++ {
		tracker.RecordSize("10.0.0.2", 500, i == 5)
	}

	fp := tracker.Analyze("10.0.0.2")
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	if !fp.Fragmented {
		t.Error("should detect fragmentation")
	}
	found := false
	for _, a := range fp.Alerts {
		if a == "IP fragmentation observed" {
			found = true
		}
	}
	if !found {
		t.Error("expected fragmentation alert")
	}
}

func TestPacketSizeTracker_JumboFrames(t *testing.T) {
	tracker := NewPacketSizeTracker(5 * time.Minute)

	for i := 0; i < 10; i++ {
		tracker.RecordSize("10.0.0.3", 9000, false)
	}

	fp := tracker.Analyze("10.0.0.3")
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	if fp.MTUEstimate != 9000 {
		t.Errorf("mtu = %d, want 9000", fp.MTUEstimate)
	}
}

func TestPacketSizeTracker_ConstantSize(t *testing.T) {
	tracker := NewPacketSizeTracker(5 * time.Minute)

	for i := 0; i < 20; i++ {
		tracker.RecordSize("10.0.0.4", 100, false)
	}

	fp := tracker.Analyze("10.0.0.4")
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	found := false
	for _, a := range fp.Alerts {
		if a == "constant packet size (likely generated traffic)" {
			found = true
		}
	}
	if !found {
		t.Error("expected constant size alert")
	}
}

func TestPacketSizeTracker_NotEnoughData(t *testing.T) {
	tracker := NewPacketSizeTracker(5 * time.Minute)

	tracker.RecordSize("10.0.0.5", 100, false)

	fp := tracker.Analyze("10.0.0.5")
	if fp != nil {
		t.Error("expected nil for insufficient data")
	}
}

func TestPacketSizeTracker_Prune(t *testing.T) {
	tracker := NewPacketSizeTracker(1 * time.Millisecond)

	tracker.RecordSize("10.0.0.1", 100, false)
	time.Sleep(2 * time.Millisecond)

	tracker.Prune()

	tracker.mu.Lock()
	count := len(tracker.profiles)
	tracker.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 profiles after prune, got %d", count)
	}
}

func TestPacketSizeTracker_Distribution(t *testing.T) {
	tracker := NewPacketSizeTracker(5 * time.Minute)

	// 3 small, 2 medium, 2 large, 3 MTU-sized
	sizes := []int{54, 60, 80, 200, 400, 600, 800, 1200, 1400, 1500}
	for _, s := range sizes {
		tracker.RecordSize("10.0.0.6", s, false)
	}

	fp := tracker.Analyze("10.0.0.6")
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	if len(fp.Distribution) != 5 {
		t.Errorf("distribution buckets = %d, want 5", len(fp.Distribution))
	}
	// [0-100): 3 packets (54, 60, 80)
	if fp.Distribution[0] != 3 {
		t.Errorf("bucket[0-100] = %d, want 3", fp.Distribution[0])
	}
}

func TestEstimateMTU(t *testing.T) {
	tests := []struct {
		maxSize int
		want    int
	}{
		{9000, 9000},
		{1500, 1500},
		{1480, 1480},
		{1280, 1280},
		{500, 576},
	}
	for _, tt := range tests {
		got := estimateMTU(tt.maxSize)
		if got != tt.want {
			t.Errorf("estimateMTU(%d) = %d, want %d", tt.maxSize, got, tt.want)
		}
	}
}
