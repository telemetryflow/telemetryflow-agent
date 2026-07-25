// Package pipeline implements the channel-based metric pipeline that wires
// inputs → pre-aggregator processors → aggregators → post-aggregator
// processors → outputs. It mirrors the topology used by Telegraf.
//
// The pipeline is opt-in: the existing metric_forwarder path continues to
// work unchanged for backwards compatibility. New collectors/processors/
// outputs registered via internal/plugin are routed through this pipeline.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package pipeline

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// DefaultQueueSize is the per-stage buffered channel capacity.
const DefaultQueueSize = 10000

// DropPolicy controls behaviour when a queue is full.
type DropPolicy string

const (
	// DropPolicyBlock blocks the producer until the queue has room. Provides
	// strong back-pressure but can stall collectors under load.
	DropPolicyBlock DropPolicy = "block"
	// DropPolicyOldest drops the oldest queued metric to make room. Keeps
	// latency bounded at the cost of data loss on the oldest metrics.
	DropPolicyOldest DropPolicy = "drop_oldest"
	// DropPolicyNewest drops the incoming metric (default). Preserves
	// historical data at the cost of freshness under load.
	DropPolicyNewest DropPolicy = "drop_newest"
)

// Config tunes pipeline queueing behaviour.
type Config struct {
	// QueueSize is the per-stage channel capacity. Default 10000.
	QueueSize int
	// DropPolicy controls behaviour when a queue is full. Default drop_newest.
	DropPolicy DropPolicy
	// AggregatorPeriod is the window duration for aggregator Push/Reset calls.
	// Default 30s.
	AggregatorPeriod time.Duration
	// FlushInterval is how often the output stage drains its buffer to the
	// configured Outputs. Default 5s.
	FlushInterval time.Duration
}

// DefaultConfig returns sensible production defaults.
func DefaultConfig() Config {
	return Config{
		QueueSize:        DefaultQueueSize,
		DropPolicy:       DropPolicyNewest,
		AggregatorPeriod: 30 * time.Second,
		FlushInterval:    5 * time.Second,
	}
}

// Pipeline holds the DAG of plugins. Build via Builder.
type Pipeline struct {
	cfg Config
	log *zap.Logger

	// Plugins — kept for lifecycle (Start/Stop) and selfstat reporting.
	inputs        []plugin.Collector
	serviceInputs []plugin.ServiceCollector
	preAggProcs   []plugin.StreamingProcessor
	aggregators   []plugin.Aggregator
	postAggProcs  []plugin.StreamingProcessor
	outputs       []plugin.Output

	// Runtime state
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	stopped chan struct{}
}

// New returns a Pipeline assembled by the Builder.
func New(cfg Config, logger *zap.Logger) *Pipeline {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.AggregatorPeriod <= 0 {
		cfg.AggregatorPeriod = 30 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Pipeline{
		cfg:     cfg,
		log:     logger,
		stopped: make(chan struct{}),
	}
}

// AddCollector appends a poll-style Collector to the pipeline.
func (p *Pipeline) AddCollector(c plugin.Collector) { p.inputs = append(p.inputs, c) }

// AddServiceCollector appends a listener-style ServiceCollector.
func (p *Pipeline) AddServiceCollector(c plugin.ServiceCollector) {
	p.serviceInputs = append(p.serviceInputs, c)
}

// AddPreAggregatorProcessor appends a processor that runs BEFORE aggregators.
func (p *Pipeline) AddPreAggregatorProcessor(proc plugin.StreamingProcessor) {
	p.preAggProcs = append(p.preAggProcs, proc)
}

// AddAggregator appends an aggregator to the pipeline.
func (p *Pipeline) AddAggregator(a plugin.Aggregator) { p.aggregators = append(p.aggregators, a) }

// AddPostAggregatorProcessor appends a processor that runs AFTER aggregators.
func (p *Pipeline) AddPostAggregatorProcessor(proc plugin.StreamingProcessor) {
	p.postAggProcs = append(p.postAggProcs, proc)
}

// AddOutput appends an Output to the fan-out stage.
func (p *Pipeline) AddOutput(o plugin.Output) { p.outputs = append(p.outputs, o) }

// Run starts every stage and blocks until ctx is cancelled. It is idempotent
// (calling Run twice returns an error) and safe to call from agent.go.
func (p *Pipeline) Run(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return errors.New("pipeline already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.running = true
	p.stopped = make(chan struct{})
	p.mu.Unlock()

	defer func() {
		close(p.stopped)
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()

	p.log.Info("pipeline starting",
		zap.Int("inputs", len(p.inputs)),
		zap.Int("service_inputs", len(p.serviceInputs)),
		zap.Int("pre_agg_processors", len(p.preAggProcs)),
		zap.Int("aggregators", len(p.aggregators)),
		zap.Int("post_agg_processors", len(p.postAggProcs)),
		zap.Int("outputs", len(p.outputs)),
		zap.Int("queue_size", p.cfg.QueueSize),
		zap.String("drop_policy", string(p.cfg.DropPolicy)),
	)

	// Connect outputs first so the sink is ready before any data flows.
	for _, out := range p.outputs {
		if err := out.Connect(); err != nil {
			p.log.Error("output connect failed", zap.String("output", out.Name()), zap.Error(err))
			// Continue — a single broken output should not crash the agent.
		}
	}

	// Wire the channel topology.
	inputCh := make(chan plugin.Metric, p.cfg.QueueSize)
	aggInCh := p.chainStreamingProcessors(runCtx, "pre_agg", p.preAggProcs, inputCh)
	aggOutCh := p.runAggregators(runCtx, aggInCh)
	outputsInCh := p.chainStreamingProcessors(runCtx, "post_agg", p.postAggProcs, aggOutCh)

	// Service inputs write directly into inputCh via an accumulator.
	acc := plugin.NewChannelAccumulator(inputCh, nil)
	for _, svc := range p.serviceInputs {
		svc := svc
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := svc.Start(runCtx, acc); err != nil {
				p.log.Error("service collector start failed",
					zap.String("collector", svc.Name()), zap.Error(err))
			}
		}()
	}

	// Poll-style inputs gather on a ticker; their metrics flow into inputCh.
	for _, in := range p.inputs {
		in := in
		p.wg.Add(1)
		go p.runPollCollector(runCtx, in, inputCh)
	}

	// Output flusher: drains outputsInCh, batches, fan-outs to every Output.
	p.wg.Add(1)
	go p.runOutputFlusher(runCtx, outputsInCh)

	// Wait for cancellation, then graceful shutdown.
	<-runCtx.Done()
	p.log.Info("pipeline stopping — waiting for goroutines")
	p.wg.Wait()

	// Stop processors in reverse order so in-flight data flows to the sink.
	for i := len(p.postAggProcs) - 1; i >= 0; i-- {
		_ = p.postAggProcs[i].Stop()
	}
	for i := len(p.preAggProcs) - 1; i >= 0; i-- {
		_ = p.preAggProcs[i].Stop()
	}
	for _, svc := range p.serviceInputs {
		_ = svc.Stop()
	}
	for _, in := range p.inputs {
		_ = in.Stop()
	}
	for _, out := range p.outputs {
		_ = out.Close()
	}
	return nil
}

// Stop cancels the pipeline and blocks until every stage has shut down.
func (p *Pipeline) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	cancel := p.cancel
	stopped := p.stopped
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
}

// chainStreamingProcessors wires a chain of StreamingProcessors between an
// input channel and a fresh output channel. The returned channel is fed by
// the last processor's accumulator. If procs is empty, inCh is returned
// unchanged.
func (p *Pipeline) chainStreamingProcessors(ctx context.Context, stage string, procs []plugin.StreamingProcessor, inCh <-chan plugin.Metric) <-chan plugin.Metric {
	if len(procs) == 0 {
		return inCh
	}
	cur := inCh
	for i, proc := range procs {
		out := make(chan plugin.Metric, p.cfg.QueueSize)
		acc := plugin.NewChannelAccumulator(out, nil)
		if err := proc.Start(acc); err != nil {
			p.log.Error("processor start failed",
				zap.String("stage", stage),
				zap.String("processor", proc.Name()),
				zap.Error(err))
		}
		p.wg.Add(1)
		go p.runStreamingProcessor(ctx, stage, i, proc, cur, out)
		cur = out
	}
	return cur
}

// runStreamingProcessor reads from in, calls Add, drains accumulator on ctx.Done.
func (p *Pipeline) runStreamingProcessor(ctx context.Context, stage string, idx int, proc plugin.StreamingProcessor, in <-chan plugin.Metric, out chan plugin.Metric) {
	defer p.wg.Done()
	acc := plugin.NewChannelAccumulator(out, nil)
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-in:
			if !ok {
				return
			}
			if err := proc.Add(m, acc); err != nil {
				p.log.Debug("processor Add returned error",
					zap.String("stage", stage),
					zap.Int("index", idx),
					zap.String("processor", proc.Name()),
					zap.Error(err))
			}
		}
	}
}

// runAggregators fans every incoming metric out to every aggregator (when its
// DropOriginal returns false the original is also forwarded). Pushes + resets
// on a ticker of AggregatorPeriod.
func (p *Pipeline) runAggregators(ctx context.Context, in <-chan plugin.Metric) <-chan plugin.Metric {
	out := make(chan plugin.Metric, p.cfg.QueueSize)
	if len(p.aggregators) == 0 {
		return in
	}
	acc := plugin.NewChannelAccumulator(out, nil)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.cfg.AggregatorPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				for _, a := range p.aggregators {
					a.Push(acc)
				}
				return
			case <-ticker.C:
				for _, a := range p.aggregators {
					a.Push(acc)
					a.Reset()
				}
			case m, ok := <-in:
				if !ok {
					return
				}
				for _, a := range p.aggregators {
					a.Add(m)
				}
				// Forward original only if every aggregator drops originals.
				// To match Telegraf semantics we forward only if ALL aggregators
				// return DropOriginal()==false. Otherwise the original is consumed.
				forward := true
				for _, a := range p.aggregators {
					if a.DropOriginal() {
						forward = false
						break
					}
				}
				if forward {
					p.enqueue(out, m)
				}
			}
		}
	}()
	return out
} // runPollCollector gathers on a fixed 30s ticker (configurable per-collector
// in a future iteration) and pushes metrics into out via enqueue.
func (p *Pipeline) runPollCollector(ctx context.Context, c plugin.Collector, out chan plugin.Metric) {
	defer p.wg.Done()
	if err := c.Start(ctx); err != nil {
		p.log.Error("collector start failed",
			zap.String("collector", c.Name()), zap.Error(err))
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics, err := c.Collect(ctx)
			if err != nil {
				p.log.Warn("collector gather error",
					zap.String("collector", c.Name()), zap.Error(err))
				continue
			}
			for _, m := range metrics {
				p.enqueue(out, m)
			}
		}
	}
}

// runOutputFlusher drains inCh into a batch and fan-outs to every Output on a
// FlushInterval ticker or when the batch reaches BatchSize.
func (p *Pipeline) runOutputFlusher(ctx context.Context, in <-chan plugin.Metric) {
	defer p.wg.Done()
	const batchSize = 1000
	batch := make([]plugin.Metric, 0, batchSize)
	ticker := time.NewTicker(p.cfg.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		for _, out := range p.outputs {
			start := time.Now()
			err := out.Write(batch)
			if err != nil {
				p.log.Warn("output write failed",
					zap.String("output", out.Name()),
					zap.Int("batch_size", len(batch)),
					zap.Duration("duration", time.Since(start)),
					zap.Error(err))
				continue
			}
			p.log.Debug("output write ok",
				zap.String("output", out.Name()),
				zap.Int("batch_size", len(batch)),
				zap.Duration("duration", time.Since(start)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain remaining
			for {
				select {
				case m, ok := <-in:
					if !ok {
						flush()
						return
					}
					batch = append(batch, m)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case <-ticker.C:
			flush()
		case m, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = append(batch, m)
			if len(batch) >= batchSize {
				flush()
			}
		}
	}
}

// Config returns the pipeline's effective configuration. Intended for
// tests and diagnostics that need to inspect the resolved defaults.
func (p *Pipeline) Config() Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg
}

// Enqueue is the exported entry point to the pipeline's drop-policy-aware
// channel push. It is intended for tests that need to exercise back-pressure
// behaviour directly; production code paths call enqueue internally.
func (p *Pipeline) Enqueue(ch chan plugin.Metric, m plugin.Metric) {
	p.enqueue(ch, m)
}

// enqueue pushes a metric into ch honouring the DropPolicy. Centralised so
// every stage has consistent back-pressure semantics. Takes a bidirectional
// channel so DropPolicyOldest can perform a non-blocking receive.
func (p *Pipeline) enqueue(ch chan plugin.Metric, m plugin.Metric) {
	switch p.cfg.DropPolicy {
	case DropPolicyBlock:
		select {
		case ch <- m:
		case <-p.stopped:
		}
	case DropPolicyOldest:
		select {
		case ch <- m:
		default:
			// Channel full — evict the oldest queued item by receiving one.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- m:
			default:
			}
		}
	default: // DropPolicyNewest
		select {
		case ch <- m:
		default:
			// Drop and log at most once per N drops to avoid log flooding.
		}
	}
}
