// Package plugin defines the typed plugin contracts (Collector, Output,
// Processor, Aggregator, Parser, Serializer, SecretStore) and the capability
// mixins (Initializer, StatefulPlugin, ProbePlugin, PluginWithID) used across
// the TelemetryFlow Agent.
//
// This package is the foundation for M1 of the roadmap. It coexists with the
// existing internal/collector.Collector interface (legacy collectors continue
// to work via an adapter) and the pkg/plugin package (legacy generic plugin
// registry kept for backwards compatibility).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package plugin

import (
	"context"
	"time"
)

// Type represents the category of a plugin.
type Type string

const (
	TypeCollector   Type = "collector"
	TypeOutput      Type = "output"
	TypeProcessor   Type = "processor"
	TypeAggregator  Type = "aggregator"
	TypeParser      Type = "parser"
	TypeSerializer  Type = "serializer"
	TypeSecretStore Type = "secretstore"
)

// Signal represents the kind of telemetry data (used for routing & parser
// selection). It mirrors the OpenTelemetry signal taxonomy.
type Signal string

const (
	SignalMetric Signal = "metric"
	SignalLog    Signal = "log"
	SignalTrace  Signal = "trace"
)

// Metric is the universal in-memory representation of a single metric data
// point flowing through the pipeline. It is intentionally compatible with the
// existing internal/collector.Metric struct so adapters can convert cheaply.
type Metric struct {
	// Name is the metric name (e.g. "system.cpu.usage").
	Name string

	// Description is a human-readable description.
	Description string

	// Type is the metric type.
	Type MetricType

	// Value is the scalar value for gauge/counter metrics.
	Value float64

	// HistogramBuckets / HistogramCounts are populated only when Type ==
	// MetricTypeHistogram. Buckets are upper bounds (le=...); Counts are
	// cumulative counts per bucket, same length as Buckets.
	HistogramBuckets []float64
	HistogramCounts  []uint64
	HistogramSum     float64
	HistogramCount   uint64

	// SummaryQuantiles / SummaryCount are populated only when Type ==
	// MetricTypeSummary.
	SummaryQuantiles []float64 // quantile boundaries (e.g. 0.5, 0.9, 0.99)
	SummaryValues    []float64 // value at each quantile
	SummaryCount     uint64
	SummarySum       float64

	// Timestamp is when the metric was observed.
	Timestamp time.Time

	// Labels are key-value dimensions. Never nil for safe mutation.
	Labels map[string]string

	// Unit is the unit hint (bytes, percent, seconds, ...).
	Unit string

	// Signal indicates which telemetry signal this metric belongs to. Most
	// metrics use SignalMetric. Log-derived gauges may use SignalLog.
	Signal Signal
}

// MetricType enumerates the supported metric value types.
type MetricType string

const (
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeCounter   MetricType = "counter"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// Copy returns a deep copy of the metric. Fan-out processors and multi-output
// dispatch rely on this to avoid shared mutable state.
func (m Metric) Copy() Metric {
	out := m
	if m.Labels != nil {
		out.Labels = make(map[string]string, len(m.Labels))
		for k, v := range m.Labels {
			out.Labels[k] = v
		}
	}
	if m.HistogramBuckets != nil {
		out.HistogramBuckets = append([]float64(nil), m.HistogramBuckets...)
		out.HistogramCounts = append([]uint64(nil), m.HistogramCounts...)
	}
	if m.SummaryQuantiles != nil {
		out.SummaryQuantiles = append([]float64(nil), m.SummaryQuantiles...)
		out.SummaryValues = append([]float64(nil), m.SummaryValues...)
	}
	return out
}

// AddLabel sets a single label, initialising the label map if needed.
func (m *Metric) AddLabel(k, v string) {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	m.Labels[k] = v
}

// AddField is a convenience alias kept for symmetry with Telegraf's API; the
// tfo-agent Metric type is scalar-only for now (multi-field metrics are
// expressed as multiple Metric values sharing the same Name prefix). It is a
// no-op placeholder that simply ensures Labels is non-nil.
func (m *Metric) AddField(_ string, _ interface{}) {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
}

// Info is the metadata every plugin must return via PluginDescriber.
type Info struct {
	Name         string
	Type         Type
	Description  string
	SampleConfig string
}

// PluginDescriber is the only mandatory interface: every plugin must describe
// itself. The typed plugin interfaces below compose it implicitly (they do
// not embed it, but every implementer is expected to expose a constructor
// that returns both the typed interface and an Info).
type PluginDescriber interface {
	Info() Info
}

// Initializer is an optional mixin for one-time setup that needs to run after
// configuration is unmarshaled but before Start/Collect/Write. Implementations
// should perform validation, connection probing, and resource allocation.
type Initializer interface {
	Init() error
}

// PluginWithID lets a plugin override its deterministic identifier. Used for
// persister keying when one configuration may instantiate the same plugin
// multiple times (e.g. multiple MySQL instances).
type PluginWithID interface {
	ID() string
}

// StatefulPlugin opts the plugin into persister-backed state save/restore.
// GetState must return a JSON-marshalable value. SetState is called once at
// startup (before Init) with the previously persisted state, or nil.
type StatefulPlugin interface {
	GetState() interface{}
	SetState(state interface{})
}

// ProbePlugin opts the plugin into startup health probing. When
// startup_error_behavior == "probe", Probe is called at startup; on error the
// plugin is silently dropped (vs crashing the agent).
type ProbePlugin interface {
	Probe() error
}

// Collector is the poll-style input plugin interface. It is satisfied by the
// existing internal/collector.Collector (via an adapter) and by all new
// poll-style plugins.
type Collector interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
	Collect(ctx context.Context) ([]Metric, error)
	IsRunning() bool
}

// ServiceCollector is a streaming/listener input (e.g. SNMP trap listener,
// NetFlow collector, syslog receiver). Start launches the listener; metrics
// are emitted via the supplied Accumulator rather than returned from Collect.
type ServiceCollector interface {
	Name() string
	Start(ctx context.Context, acc Accumulator) error
	Stop() error
	Collect(ctx context.Context) ([]Metric, error) // returns nil for pure listeners
	IsRunning() bool
}

// StreamingProcessor is the modern, async-capable processor interface. Start
// is called once; Add is invoked for every metric flowing through; Stop gives
// the processor a chance to flush in-flight work.
type StreamingProcessor interface {
	Name() string
	Start(acc Accumulator) error
	Add(metric Metric, acc Accumulator) error
	Stop() error
}

// SyncProcessor is the legacy synchronous processor interface. It is auto-
// upgraded to StreamingProcessor via NewSyncProcessorAdapter.
type SyncProcessor interface {
	Name() string
	Apply(metrics []Metric) []Metric
}

// Aggregator computes windowed rollups. Add accumulates a metric, Push emits
// the computed aggregates via the accumulator, Reset clears state for the next
// window. DropOriginal returns true (default) if the original metric should
// not also be forwarded downstream.
type Aggregator interface {
	Name() string
	Add(metric Metric)
	Push(acc Accumulator)
	Reset()
	DropOriginal() bool
}

// Output is the synchronous output plugin interface. Connect is called once
// at startup; Write receives a batch; Close releases resources at shutdown.
type Output interface {
	Name() string
	Connect() error
	Close() error
	Write(metrics []Metric) error
}

// Parser decodes arbitrary byte payloads into Metrics. Implementations are
// injectable into Collectors/Outputs that support ParserPlugin.
type Parser interface {
	Parse(buf []byte) ([]Metric, error)
	ParseLine(line string) (Metric, error)
	SetDefaultTags(tags map[string]string)
}

// Serializer encodes Metrics into bytes. Implementations are injectable into
// Outputs that support SerializerPlugin.
type Serializer interface {
	Serialize(metric Metric) ([]byte, error)
	SerializeBatch(metrics []Metric) ([]byte, error)
}

// SecretStore resolves @{store:key} references encountered in configuration.
type SecretStore interface {
	Name() string
	Init(config map[string]interface{}) error
	Get(key string) (string, error)
	List() ([]string, error)
	// GetResolver returns a function that returns the (possibly rotating)
	// value for a key. The bool return is true when the secret may change
	// over time (TOTP, OAuth2 refresh) and should be re-resolved.
	GetResolver(key string) (ResolveFunc, error)
}

// ResolveFunc is the resolver returned by SecretStore.GetResolver.
type ResolveFunc func() (value string, dynamic bool, err error)

// ParserPlugin is an optional mixin for Collectors/Outputs that can have a
// parser injected (e.g. http scrape, syslog listener).
type ParserPlugin interface {
	SetParser(p Parser)
}

// SerializerPlugin is an optional mixin for Outputs that can have a serializer
// injected.
type SerializerPlugin interface {
	SetSerializer(s Serializer)
}

// Accumulator is the in-process metric ingestion API passed to service
// collectors, processors, and aggregators.
type Accumulator interface {
	Add(metric Metric)
	AddFields(name string, value float64, labels map[string]string, t time.Time)
	AddGauge(name string, value float64, labels map[string]string, t time.Time)
	AddCounter(name string, value float64, labels map[string]string, t time.Time)
	AddError(err error)
}

// FatalError signals a non-recoverable startup failure. Causes the agent to exit.
type FatalError struct{ Err error }

func (e *FatalError) Error() string { return "fatal: " + e.Err.Error() }
func (e *FatalError) Unwrap() error { return e.Err }

// StartupError signals a potentially recoverable startup failure.
// Retry=true means retry per startup_error_behavior=retry.
// Partial=true means drop only this plugin (ignore mode) rather than crash.
type StartupError struct {
	Err     error
	Retry   bool
	Partial bool
}

func (e *StartupError) Error() string {
	msg := "startup error"
	if e.Partial {
		msg = "startup error (partial)"
	}
	if e.Retry {
		msg = "startup error (retry)"
	}
	return msg + ": " + e.Err.Error()
}
func (e *StartupError) Unwrap() error { return e.Err }

// PartialWriteError is returned by Output.Write to signal that a write
// partially succeeded. The pipeline retries only the rejected metrics.
type PartialWriteError struct {
	Err             error
	MetricsAccepted []Metric
	MetricsRejected []Metric
}

func (e *PartialWriteError) Error() string {
	return "partial write: " + e.Err.Error()
}
func (e *PartialWriteError) Unwrap() error { return e.Err }

// StartupBehavior is the per-plugin startup_error_behavior setting.
type StartupBehavior string

const (
	// StartupBehaviorError (default) hard-fails the entire agent on init error.
	StartupBehaviorError StartupBehavior = "error"
	// StartupBehaviorRetry keeps retrying the plugin until success.
	StartupBehaviorRetry StartupBehavior = "retry"
	// StartupBehaviorIgnore drops the plugin silently on init error.
	StartupBehaviorIgnore StartupBehavior = "ignore"
	// StartupBehaviorProbe calls ProbePlugin.Probe(); on failure, behaves like ignore.
	StartupBehaviorProbe StartupBehavior = "probe"
)
