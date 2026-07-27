package exporter_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/buffer"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// failingSink fails the first N calls then succeeds.
type failingSink struct {
	failCount int32
	calls     atomic.Int32
	exported  atomic.Int32
}

func (s *failingSink) Export(_ context.Context, _ []collector.Metric, _ map[string]string) error {
	calls := s.calls.Add(1)
	if calls <= s.failCount {
		return errors.New("simulated transient failure")
	}
	s.exported.Add(1)
	return nil
}

func newTestBuffer(t *testing.T) *buffer.Buffer {
	t.Helper()
	cfg := buffer.Config{
		Enabled:       true,
		Path:          t.TempDir(),
		MaxSizeMB:     10,
		MaxAge:        time.Hour,
		FlushInterval: 50 * time.Millisecond,
	}
	b, err := buffer.New(cfg)
	if err != nil {
		t.Fatalf("buffer.New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestBufferRetrySink_DisabledIsPassthrough(t *testing.T) {
	inner := &failingSink{failCount: 1}
	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{Enabled: false, Logger: zap.NewNop()})
	err := sink.Export(context.Background(), []collector.Metric{{Name: "m"}}, nil)
	if err == nil {
		t.Error("disabled sink should propagate error from inner")
	}
}

func TestBufferRetrySink_EnabledAbsorbsError(t *testing.T) {
	inner := &failingSink{failCount: 1}
	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled: true,
		Buffer:  newTestBuffer(t),
		Logger:  zap.NewNop(),
	})
	err := sink.Export(context.Background(), []collector.Metric{{Name: "m"}}, nil)
	if err != nil {
		t.Errorf("enabled sink should absorb error, got %v", err)
	}
}

func TestBufferRetrySink_RetryLoopEventuallyExports(t *testing.T) {
	inner := &failingSink{failCount: 2}
	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled:       true,
		Buffer:        newTestBuffer(t),
		RetryInterval: 50 * time.Millisecond,
		Logger:        zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink.StartRetryLoop(ctx)

	// First call fails but is absorbed.
	_ = sink.Export(ctx, []collector.Metric{{Name: "m"}}, nil)

	// Wait for retries to succeed.
	deadline := time.After(2 * time.Second)
	for {
		if inner.exported.Load() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("retry loop did not succeed; calls=%d exported=%d",
				inner.calls.Load(), inner.exported.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestBufferRetrySink_InMemoryFallback(t *testing.T) {
	inner := &failingSink{failCount: 1}
	// Buffer == nil forces the in-memory fallback path.
	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled:       true,
		Buffer:        nil,
		RetryInterval: 50 * time.Millisecond,
		Logger:        zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink.StartRetryLoop(ctx)

	_ = sink.Export(ctx, []collector.Metric{{Name: "m"}}, nil)

	deadline := time.After(2 * time.Second)
	for {
		if inner.exported.Load() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("in-memory retry did not succeed")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestBufferRetrySink_MaxRetriesDrops(t *testing.T) {
	// Always-failing sink with MaxRetries=1 → entry dropped after 1 retry.
	inner := &failingSink{failCount: 1_000_000}

	// Manual buffer lifecycle (not t.Cleanup) to avoid a race between the
	// retry goroutine's buf.Push/Pop and buf.Close.
	cfg := buffer.Config{
		Enabled:       true,
		Path:          t.TempDir(),
		MaxSizeMB:     10,
		MaxAge:        time.Hour,
		FlushInterval: 50 * time.Millisecond,
	}
	buf, err := buffer.New(cfg)
	if err != nil {
		t.Fatalf("buffer.New: %v", err)
	}

	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled:       true,
		Buffer:        buf,
		RetryInterval: 30 * time.Millisecond,
		MaxRetries:    1,
		Logger:        zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	sink.StartRetryLoop(ctx)

	_ = sink.Export(ctx, []collector.Metric{{Name: "m"}}, nil)

	// Give it plenty of retries — they should all fail and the entry should
	// eventually be dropped (no goroutine leak, no infinite loop).
	time.Sleep(300 * time.Millisecond)
	if sink.Stats().InMemoryQueueDepth > 0 {
		t.Errorf("expected empty queue after max retries, got %d",
			sink.Stats().InMemoryQueueDepth)
	}

	// Stop the retry goroutine FIRST, then close the buffer.
	cancel()
	time.Sleep(100 * time.Millisecond) // let the goroutine observe ctx.Done
	_ = buf.Close()
}
