// Accumulator implementations: channel-based accumulator for pipeline use,
// and a discard accumulator for testing/single-shot tooling.

package plugin

import (
	"errors"
	"sync"
	"time"
)

// ChannelAccumulator is an Accumulator whose Add* methods push metrics into a
// channel. Used by ServiceCollectors, StreamingProcessors, and Aggregators to
// emit metrics into the pipeline.
type ChannelAccumulator struct {
	ch     chan<- Metric
	errCh  chan<- error
	mu     sync.Mutex
	errors []error
}

// NewChannelAccumulator wires the accumulator to the supplied metric and error
// channels. The caller owns the channels.
func NewChannelAccumulator(ch chan<- Metric, errCh chan<- error) *ChannelAccumulator {
	return &ChannelAccumulator{ch: ch, errCh: errCh}
}

// Add enqueues a metric. Non-blocking: if the channel is full the metric is
// dropped and an error is recorded. Use a buffered channel sized to peak load.
func (a *ChannelAccumulator) Add(m Metric) {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	select {
	case a.ch <- m:
	default:
		a.AddError(ErrAccumulatorFull)
	}
}

// AddFields is a convenience helper for untyped metrics.
func (a *ChannelAccumulator) AddFields(name string, value float64, labels map[string]string, t time.Time) {
	a.Add(Metric{Name: name, Type: MetricTypeCounter, Value: value, Labels: labels, Timestamp: t})
}

// AddGauge enqueues a gauge metric.
func (a *ChannelAccumulator) AddGauge(name string, value float64, labels map[string]string, t time.Time) {
	a.Add(Metric{Name: name, Type: MetricTypeGauge, Value: value, Labels: labels, Timestamp: t})
}

// AddCounter enqueues a counter metric.
func (a *ChannelAccumulator) AddCounter(name string, value float64, labels map[string]string, t time.Time) {
	a.Add(Metric{Name: name, Type: MetricTypeCounter, Value: value, Labels: labels, Timestamp: t})
}

// AddError forwards the error to the error channel (if any) and records it
// locally so callers can inspect accumulated errors via Errors().
func (a *ChannelAccumulator) AddError(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	a.errors = append(a.errors, err)
	a.mu.Unlock()
	if a.errCh != nil {
		select {
		case a.errCh <- err:
		default:
		}
	}
}

// Errors returns a copy of the accumulated errors.
func (a *ChannelAccumulator) Errors() []error {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]error, len(a.errors))
	copy(out, a.errors)
	return out
}

// ErrAccumulatorFull is reported when Add() cannot enqueue because the
// downstream channel is full.
var ErrAccumulatorFull = errors.New("accumulator channel full")

// DiscardAccumulator is a no-op accumulator for testing and single-shot paths
// where the caller does not care about emitted metrics.
type DiscardAccumulator struct {
	mu     sync.Mutex
	errors []error
}

// NewDiscardAccumulator returns a fresh DiscardAccumulator.
func NewDiscardAccumulator() *DiscardAccumulator { return &DiscardAccumulator{} }

// Add drops the metric silently.
func (a *DiscardAccumulator) Add(_ Metric) {}

// AddFields drops the metric silently.
func (a *DiscardAccumulator) AddFields(_ string, _ float64, _ map[string]string, _ time.Time) {}

// AddGauge drops the metric silently.
func (a *DiscardAccumulator) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time) {}

// AddCounter drops the metric silently.
func (a *DiscardAccumulator) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}

// AddError records the error for inspection via Errors().
func (a *DiscardAccumulator) AddError(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errors = append(a.errors, err)
}

// Errors returns a copy of the accumulated errors.
func (a *DiscardAccumulator) Errors() []error {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]error, len(a.errors))
	copy(out, a.errors)
	return out
}
