// Adapter: wraps the legacy internal/collector.Collector interface so existing
// collectors can be loaded via the new plugin registry without code changes.
// This is the bridge that lets us roll out the new plugin system incrementally
// (M1.10 migration) without rewriting all 26 collectors at once.

package plugin

import (
	"context"

	legacycol "github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// LegacyCollector is the existing internal/collector.Collector interface,
// re-exported here so adapter consumers do not need to import that package
// directly. The re-export is a type alias, not a redefinition.
type LegacyCollector = legacycol.Collector

// LegacyMetric is the existing internal/collector.Metric type alias.
type LegacyMetric = legacycol.Metric

// FromLegacyMetric converts a legacy collector.Metric into the new plugin.Metric.
// Field types map 1:1; the conversion is allocation-free for scalar metrics.
func FromLegacyMetric(m LegacyMetric) Metric {
	return Metric{
		Name:        m.Name,
		Description: m.Description,
		Type:        MetricType(m.Type),
		Value:       m.Value,
		Timestamp:   m.Timestamp,
		Labels:      m.Labels,
		Unit:        m.Unit,
		Signal:      SignalMetric,
	}
}

// FromLegacyMetrics converts a slice of legacy metrics.
func FromLegacyMetrics(in []LegacyMetric) []Metric {
	out := make([]Metric, len(in))
	for i := range in {
		out[i] = FromLegacyMetric(in[i])
	}
	return out
}

// ToLegacyMetric converts a plugin.Metric back into a legacy collector.Metric.
// Used by adapters that bridge new processors/outputs into the existing
// metric_forwarder path during the M1 transitional period.
func ToLegacyMetric(m Metric) LegacyMetric {
	return LegacyMetric{
		Name:        m.Name,
		Description: m.Description,
		Type:        legacycol.MetricType(m.Type),
		Value:       m.Value,
		Timestamp:   m.Timestamp,
		Labels:      m.Labels,
		Unit:        m.Unit,
	}
}

// ToLegacyMetrics converts a slice of new metrics to legacy form.
func ToLegacyMetrics(in []Metric) []LegacyMetric {
	out := make([]LegacyMetric, len(in))
	for i := range in {
		out[i] = ToLegacyMetric(in[i])
	}
	return out
}

// CollectorAdapter wraps a legacy collector.Collector so it satisfies the new
// plugin.Collector interface.
type CollectorAdapter struct {
	name string
	impl LegacyCollector
}

// NewCollectorAdapter returns a plugin.Collector that delegates to a legacy
// collector. The name is taken from the legacy impl if non-empty, otherwise
// from the argument.
func NewCollectorAdapter(name string, impl LegacyCollector) *CollectorAdapter {
	if name == "" {
		name = impl.Name()
	}
	return &CollectorAdapter{name: name, impl: impl}
}

// Name returns the collector name.
func (a *CollectorAdapter) Name() string { return a.name }

// Start starts the underlying legacy collector.
func (a *CollectorAdapter) Start(ctx context.Context) error { return a.impl.Start(ctx) }

// Stop stops the underlying legacy collector.
func (a *CollectorAdapter) Stop() error { return a.impl.Stop() }

// Collect runs a single collection cycle and converts metrics to the new type.
func (a *CollectorAdapter) Collect(ctx context.Context) ([]Metric, error) {
	legacy, err := a.impl.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return FromLegacyMetrics(legacy), nil
}

// IsRunning reports whether the underlying collector is running.
func (a *CollectorAdapter) IsRunning() bool { return a.impl.IsRunning() }

// Impl returns the wrapped legacy collector, allowing type assertions for
// optional mixins (Initializer, StatefulPlugin, ProbePlugin) on the original.
func (a *CollectorAdapter) Impl() LegacyCollector { return a.impl }

// AsLegacyCollector unwraps an adapter back to the underlying legacy collector.
// If the supplied Collector is not an adapter, returns ok=false.
func AsLegacyCollector(c Collector) (LegacyCollector, bool) {
	if a, ok := c.(*CollectorAdapter); ok {
		return a.Impl(), true
	}
	return nil, false
}

// SyncProcessorAdapter upgrades a legacy SyncProcessor to a StreamingProcessor.
// It batches incoming metrics into a window and applies the synchronous Apply
// function when the batch reaches a configurable size or a flush is requested.
type SyncProcessorAdapter struct {
	name   string
	impl   SyncProcessor
	buf    []Metric
	maxBuf int
	acc    Accumulator
}

// NewSyncProcessorAdapter wraps a SyncProcessor with a default batch size of
// 1000 metrics.
func NewSyncProcessorAdapter(name string, impl SyncProcessor) *SyncProcessorAdapter {
	return &SyncProcessorAdapter{name: name, impl: impl, maxBuf: 1000}
}

// Name returns the processor name.
func (a *SyncProcessorAdapter) Name() string { return a.name }

// Start stores the downstream accumulator reference.
func (a *SyncProcessorAdapter) Start(acc Accumulator) error {
	a.acc = acc
	return nil
}

// Add buffers a metric; flushes when buffer is full.
func (a *SyncProcessorAdapter) Add(m Metric, _ Accumulator) error {
	a.buf = append(a.buf, m)
	if len(a.buf) >= a.maxBuf {
		a.flush()
	}
	return nil
}

// Stop flushes any buffered metrics.
func (a *SyncProcessorAdapter) Stop() error {
	a.flush()
	return nil
}

func (a *SyncProcessorAdapter) flush() {
	if len(a.buf) == 0 || a.acc == nil {
		return
	}
	out := a.impl.Apply(a.buf)
	for _, m := range out {
		a.acc.Add(m)
	}
	a.buf = a.buf[:0]
}
