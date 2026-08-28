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

// TestBufferRetrySink_NoBusyLoopWhenBackendDown is a regression test for
// RCA-20260828-001: while the backend was failing, drainDisk re-persisted
// entries and immediately re-popped them in a tight `for { Pop(50) }` loop,
// pinning CPU at its limit. The fixed code makes at most ONE export attempt
// per retry tick while the backend is down — for both the disk and the
// in-memory paths.
func TestBufferRetrySink_NoBusyLoopWhenBackendDown(t *testing.T) {
	const (
		retryInterval = 50 * time.Millisecond
		window        = 400 * time.Millisecond
		// ~8 ticks → at most ~9 attempts (initial export + 1 per tick).
		// The 1.3.1 busy loop performed hundreds of attempts in this window.
		maxAttempts = 30
	)

	run := func(t *testing.T, withDisk bool) {
		t.Helper()
		inner := &failingSink{failCount: 1_000_000}

		var buf *buffer.Buffer
		if withDisk {
			b, err := buffer.New(buffer.Config{
				Enabled:       true,
				Path:          t.TempDir(),
				MaxSizeMB:     10,
				MaxAge:        time.Hour,
				FlushInterval: 50 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("buffer.New: %v", err)
			}
			buf = b
		}

		sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
			Enabled:       true,
			Buffer:        buf,
			RetryInterval: retryInterval,
			Logger:        zap.NewNop(),
		})
		ctx, cancel := context.WithCancel(context.Background())
		sink.StartRetryLoop(ctx)

		_ = sink.Export(ctx, []collector.Metric{{Name: "m"}}, nil)

		time.Sleep(window)
		cancel()
		time.Sleep(100 * time.Millisecond) // let the goroutine observe ctx.Done
		if buf != nil {
			_ = buf.Close()
		}

		if got := inner.calls.Load(); got > maxAttempts {
			t.Errorf("retry loop made %d export attempts in %v — busy-loop regression (max %d)",
				got, window, maxAttempts)
		}
	}

	t.Run("disk path", func(t *testing.T) { run(t, true) })
	t.Run("in-memory path", func(t *testing.T) { run(t, false) })
}

// TestBufferRetrySink_MaxRetriesDropsDiskEntries is a regression test for
// RCA-20260828-001: drainDisk incremented Retries but never enforced
// MaxRetries, so entries were retried forever while the backend was down.
func TestBufferRetrySink_MaxRetriesDropsDiskEntries(t *testing.T) {
	inner := &failingSink{failCount: 1_000_000}

	buf, err := buffer.New(buffer.Config{
		Enabled:       true,
		Path:          t.TempDir(),
		MaxSizeMB:     10,
		MaxAge:        time.Hour,
		FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("buffer.New: %v", err)
	}

	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled:       true,
		Buffer:        buf,
		RetryInterval: 30 * time.Millisecond,
		MaxRetries:    2,
		Logger:        zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	sink.StartRetryLoop(ctx)

	_ = sink.Export(ctx, []collector.Metric{{Name: "m"}}, nil)

	time.Sleep(300 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)
	_ = buf.Close()

	if got := buf.Len(); got != 0 {
		t.Errorf("expected drained disk buffer after MaxRetries, got %d entries", got)
	}
}

// TestBufferRetrySink_InMemoryQueueMetricsBudget is a regression test for
// RCA-20260828-001: the in-memory fallback queue was bounded only by entry
// count (100 entries × ~5k metrics ≈ 250 MiB). It is now also bounded by
// total buffered metrics.
func TestBufferRetrySink_InMemoryQueueMetricsBudget(t *testing.T) {
	inner := &failingSink{failCount: 1_000_000}
	// No retry loop — this test exercises only the enqueue budget.
	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled: true,
		Buffer:  nil,
		Logger:  zap.NewNop(),
	})

	batch := make([]collector.Metric, 1000)
	for i := range batch {
		batch[i] = collector.Metric{Name: "m"}
	}
	for i := 0; i < 30; i++ { // 30k metrics total > 25k budget
		_ = sink.Export(context.Background(), batch, nil)
	}

	st := sink.Stats()
	if st.InMemoryQueueDepth > 100 {
		t.Errorf("entry budget exceeded: %d entries", st.InMemoryQueueDepth)
	}
	// One-entry overshoot is allowed (the queue always keeps ≥1 entry).
	if st.InMemoryQueueMetrics > 25_000+1000 {
		t.Errorf("metrics budget exceeded: %d metrics", st.InMemoryQueueMetrics)
	}
}
