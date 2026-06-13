package fsm

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func TestBackoff_Next(t *testing.T) {
	b := collector.NewBackoff(100*time.Millisecond, 10*time.Second, 2.0)

	d1 := b.Next()
	if d1 < 50*time.Millisecond || d1 > 150*time.Millisecond {
		t.Errorf("first backoff should be ~100ms, got %v", d1)
	}

	d2 := b.Next()
	if d2 < 100*time.Millisecond {
		t.Errorf("second backoff should be >= 100ms, got %v", d2)
	}

	b.Reset()
	if b.Attempt() != 0 {
		t.Errorf("attempt should be 0 after reset, got %d", b.Attempt())
	}
}

func TestBackoff_MaxCap(t *testing.T) {
	b := collector.NewBackoff(100*time.Millisecond, 500*time.Millisecond, 3.0)

	for i := 0; i < 20; i++ {
		d := b.Next()
		if d > 600*time.Millisecond {
			t.Errorf("backoff exceeded max: %v", d)
		}
	}
}

func TestBackoff_Reset(t *testing.T) {
	b := collector.NewBackoff(time.Second, time.Minute, 2.0)
	b.Next()
	b.Next()
	b.Next()
	if b.Attempt() != 3 {
		t.Fatalf("expected attempt 3, got %d", b.Attempt())
	}

	b.Reset()
	if b.Attempt() != 0 {
		t.Fatalf("expected attempt 0 after reset, got %d", b.Attempt())
	}
}
