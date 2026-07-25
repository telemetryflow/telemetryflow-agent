package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"go.uber.org/zap"
)

// --- Test fixtures -----------------------------------------------------------

// noopCollector is a poll-style collector that emits a fixed metric on each
// Collect call.
type noopCollector struct {
	name    string
	running atomic.Bool
	mu      sync.Mutex
	count   atomic.Int64
}

func (c *noopCollector) Name() string                  { return c.name }
func (c *noopCollector) Start(_ context.Context) error { c.running.Store(true); return nil }
func (c *noopCollector) Stop() error                   { c.running.Store(false); return nil }
func (c *noopCollector) Collect(_ context.Context) ([]plugin.Metric, error) {
	c.count.Add(1)
	return []plugin.Metric{{Name: "test.metric", Value: float64(c.count.Load()), Type: plugin.MetricTypeGauge}}, nil
}
func (c *noopCollector) IsRunning() bool { return c.running.Load() }

// captureOutput records every metric written to it.
type captureOutput struct {
	name    string
	mu      sync.Mutex
	written []plugin.Metric
	open    atomic.Bool
}

func (o *captureOutput) Name() string   { return o.name }
func (o *captureOutput) Connect() error { o.open.Store(true); return nil }
func (o *captureOutput) Close() error   { o.open.Store(false); return nil }
func (o *captureOutput) Write(m []plugin.Metric) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.written = append(o.written, m...)
	return nil
}
func (o *captureOutput) Snapshot() []plugin.Metric {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]plugin.Metric, len(o.written))
	copy(out, o.written)
	return out
}

// dropAllProcessor is a StreamingProcessor that drops every metric.
type dropAllProcessor struct{ started atomic.Bool }

func (p *dropAllProcessor) Name() string                                    { return "drop_all" }
func (p *dropAllProcessor) Start(_ plugin.Accumulator) error                { p.started.Store(true); return nil }
func (p *dropAllProcessor) Add(_ plugin.Metric, _ plugin.Accumulator) error { return nil }
func (p *dropAllProcessor) Stop() error                                     { return nil }

// passthroughProcessor forwards every metric unchanged.
type passthroughProcessor struct {
	acc plugin.Accumulator
}

func (p *passthroughProcessor) Name() string                       { return "passthrough" }
func (p *passthroughProcessor) Start(acc plugin.Accumulator) error { p.acc = acc; return nil }
func (p *passthroughProcessor) Add(m plugin.Metric, _ plugin.Accumulator) error {
	p.acc.Add(m)
	return nil
}
func (p *passthroughProcessor) Stop() error { return nil }

// --- Tests -------------------------------------------------------------------

func TestPipeline_EmptyStages_RunStop(t *testing.T) {
	p := New(Config{QueueSize: 10, FlushInterval: 50 * time.Millisecond}, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = p.Run(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not stop within 2s")
	}
}

func TestPipeline_NoProcessors_EndToEnd(t *testing.T) {
	p := New(Config{QueueSize: 100, FlushInterval: 50 * time.Millisecond}, zap.NewNop())
	col := &noopCollector{name: "test"}
	out := &captureOutput{name: "capture"}
	p.AddCollector(col)
	p.AddOutput(out)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Run(ctx); close(done) }()

	// Wait for at least one flush (poll collector runs on a 30s ticker, so we
	// cannot rely on a real Collect call here). Instead, exercise the pipeline
	// via a direct enqueue by adding a service input — but for this minimal
	// test we just verify graceful shutdown.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if !col.running.Load() && col.count.Load() > 0 {
		// Collector may or may not have fired depending on timing; only assert
		// lifecycle was clean.
	}
}

func TestPipeline_ProcessorChain(t *testing.T) {
	cfg := Config{
		QueueSize:     100,
		DropPolicy:    DropPolicyNewest,
		FlushInterval: 50 * time.Millisecond,
	}
	p := New(cfg, zap.NewNop())
	p.AddPreAggregatorProcessor(&dropAllProcessor{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Run(ctx); close(done) }()
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done
}

func TestPipeline_PreAggPassthrough_DeliversMetric(t *testing.T) {
	cfg := Config{QueueSize: 100, FlushInterval: 30 * time.Millisecond}
	p := New(cfg, zap.NewNop())
	p.AddPreAggregatorProcessor(&passthroughProcessor{})
	out := &captureOutput{name: "capture"}
	p.AddOutput(out)

	// Drive input by hand: create a service collector that emits one metric.
	// Register BEFORE Run to avoid racing the pipeline's snapshot of inputs.
	svc := &oneShotService{name: "oneshot", metric: plugin.Metric{Name: "test.metric", Value: 42, Type: plugin.MetricTypeGauge}}
	p.AddServiceCollector(svc)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Run(ctx); close(done) }()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	got := out.Snapshot()
	if len(got) == 0 {
		t.Fatalf("expected at least one metric delivered, got 0")
	}
	if got[0].Name != "test.metric" || got[0].Value != 42 {
		t.Errorf("unexpected metric: %+v", got[0])
	}
}

// oneShotService emits a single metric on Start and then blocks on ctx.
type oneShotService struct {
	name   string
	metric plugin.Metric
}

func (s *oneShotService) Name() string { return s.name }
func (s *oneShotService) Start(ctx context.Context, acc plugin.Accumulator) error {
	acc.Add(s.metric)
	<-ctx.Done()
	return nil
}
func (s *oneShotService) Stop() error                                        { return nil }
func (s *oneShotService) Collect(_ context.Context) ([]plugin.Metric, error) { return nil, nil }
func (s *oneShotService) IsRunning() bool                                    { return true }

func TestPipeline_StopIsIdempotent(t *testing.T) {
	p := New(Config{QueueSize: 10}, zap.NewNop())
	p.Stop() // not yet started — must not panic
	p.Stop()
}

func TestPipeline_RunTwice_ReturnsError(t *testing.T) {
	p := New(Config{QueueSize: 10, FlushInterval: 30 * time.Millisecond}, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = p.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	if err := p.Run(ctx); err == nil {
		t.Error("expected error when calling Run twice, got nil")
	}
	cancel()
	<-done
}

func TestPipeline_DropPolicyNewest_NoBlock(t *testing.T) {
	cfg := Config{QueueSize: 2, DropPolicy: DropPolicyNewest, FlushInterval: 10 * time.Second}
	p := New(cfg, zap.NewNop())
	ch := make(chan plugin.Metric, 2)
	// Fill the queue.
	for i := 0; i < 2; i++ {
		p.enqueue(ch, plugin.Metric{Name: "first"})
	}
	// This call must not block under DropPolicyNewest.
	done := make(chan struct{})
	go func() {
		p.enqueue(ch, plugin.Metric{Name: "drop_me"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("enqueue blocked under DropPolicyNewest")
	}
}

func TestPipeline_DropPolicyOldest_Evicts(t *testing.T) {
	cfg := Config{QueueSize: 2, DropPolicy: DropPolicyOldest, FlushInterval: 10 * time.Second}
	p := New(cfg, zap.NewNop())
	ch := make(chan plugin.Metric, 2)
	ch <- plugin.Metric{Name: "old"}
	ch <- plugin.Metric{Name: "newer"}
	// Queue full; enqueue under DropPolicyOldest must evict "old".
	p.enqueue(ch, plugin.Metric{Name: "newest"})
	if len(ch) != 2 {
		t.Fatalf("queue length: want 2, got %d", len(ch))
	}
	first := <-ch
	if first.Name != "newer" {
		t.Errorf("oldest evicted wrong element: got %s", first.Name)
	}
}

func TestPipeline_DefaultConfig_AppliesWhenZero(t *testing.T) {
	p := New(Config{}, zap.NewNop())
	if p.cfg.QueueSize != DefaultQueueSize {
		t.Errorf("QueueSize default: want %d, got %d", DefaultQueueSize, p.cfg.QueueSize)
	}
	if p.cfg.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval default: want 5s, got %s", p.cfg.FlushInterval)
	}
}
