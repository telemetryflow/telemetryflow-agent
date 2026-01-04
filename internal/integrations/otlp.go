// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"time"
)

// OTLP JSON format structures for HTTP export
// These structures follow the OTLP/JSON specification

// OTLPMetrics represents OTLP metrics in JSON format
type OTLPMetrics struct {
	ResourceMetrics []ResourceMetrics `json:"resourceMetrics"`
}

// ResourceMetrics represents a resource with its metrics
type ResourceMetrics struct {
	Resource     Resource       `json:"resource"`
	ScopeMetrics []ScopeMetrics `json:"scopeMetrics"`
}

// ScopeMetrics represents metrics within an instrumentation scope
type ScopeMetrics struct {
	Scope   InstrumentationScope `json:"scope"`
	Metrics []OTLPMetric         `json:"metrics"`
}

// OTLPMetric represents a single OTLP metric
type OTLPMetric struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Unit        string       `json:"unit,omitempty"`
	Gauge       *Gauge       `json:"gauge,omitempty"`
	Sum         *Sum         `json:"sum,omitempty"`
	Histogram   *Histogram   `json:"histogram,omitempty"`
	Summary     *OTLPSummary `json:"summary,omitempty"`
}

// Gauge represents a gauge metric
type Gauge struct {
	DataPoints []NumberDataPoint `json:"dataPoints"`
}

// Sum represents a sum (counter) metric
type Sum struct {
	AggregationTemporality string            `json:"aggregationTemporality"`
	IsMonotonic            bool              `json:"isMonotonic"`
	DataPoints             []NumberDataPoint `json:"dataPoints"`
}

// Histogram represents a histogram metric
type Histogram struct {
	AggregationTemporality string               `json:"aggregationTemporality"`
	DataPoints             []HistogramDataPoint `json:"dataPoints"`
}

// OTLPSummary represents a summary metric
type OTLPSummary struct {
	DataPoints []SummaryDataPoint `json:"dataPoints"`
}

// NumberDataPoint represents a numeric data point
type NumberDataPoint struct {
	Attributes        []KeyValue `json:"attributes,omitempty"`
	TimeUnixNano      string     `json:"timeUnixNano"`
	StartTimeUnixNano string     `json:"startTimeUnixNano,omitempty"`
	AsDouble          float64    `json:"asDouble"`
}

// HistogramDataPoint represents a histogram data point
type HistogramDataPoint struct {
	Attributes        []KeyValue `json:"attributes,omitempty"`
	TimeUnixNano      string     `json:"timeUnixNano"`
	StartTimeUnixNano string     `json:"startTimeUnixNano,omitempty"`
	Count             uint64     `json:"count"`
	Sum               float64    `json:"sum,omitempty"`
	BucketCounts      []uint64   `json:"bucketCounts,omitempty"`
	ExplicitBounds    []float64  `json:"explicitBounds,omitempty"`
}

// SummaryDataPoint represents a summary data point
type SummaryDataPoint struct {
	Attributes        []KeyValue      `json:"attributes,omitempty"`
	TimeUnixNano      string          `json:"timeUnixNano"`
	StartTimeUnixNano string          `json:"startTimeUnixNano,omitempty"`
	Count             uint64          `json:"count"`
	Sum               float64         `json:"sum"`
	QuantileValues    []QuantileValue `json:"quantileValues,omitempty"`
}

// QuantileValue represents a quantile value in a summary
type QuantileValue struct {
	Quantile float64 `json:"quantile"`
	Value    float64 `json:"value"`
}

// OTLPTraces represents OTLP traces in JSON format
type OTLPTraces struct {
	ResourceSpans []ResourceSpans `json:"resourceSpans"`
}

// ResourceSpans represents a resource with its spans
type ResourceSpans struct {
	Resource   Resource     `json:"resource"`
	ScopeSpans []ScopeSpans `json:"scopeSpans"`
}

// ScopeSpans represents spans within an instrumentation scope
type ScopeSpans struct {
	Scope InstrumentationScope `json:"scope"`
	Spans []OTLPSpan           `json:"spans"`
}

// OTLPSpan represents a single OTLP span
type OTLPSpan struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	ParentSpanID      string      `json:"parentSpanId,omitempty"`
	Name              string      `json:"name"`
	Kind              int         `json:"kind"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	EndTimeUnixNano   string      `json:"endTimeUnixNano"`
	Attributes        []KeyValue  `json:"attributes,omitempty"`
	Status            SpanStatus  `json:"status"`
	Events            []SpanEvent `json:"events,omitempty"`
}

// SpanStatus represents the status of a span
type SpanStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// SpanEvent represents an event within a span
type SpanEvent struct {
	TimeUnixNano string     `json:"timeUnixNano"`
	Name         string     `json:"name"`
	Attributes   []KeyValue `json:"attributes,omitempty"`
}

// OTLPLogs represents OTLP logs in JSON format
type OTLPLogs struct {
	ResourceLogs []ResourceLogs `json:"resourceLogs"`
}

// ResourceLogs represents a resource with its logs
type ResourceLogs struct {
	Resource  Resource    `json:"resource"`
	ScopeLogs []ScopeLogs `json:"scopeLogs"`
}

// ScopeLogs represents logs within an instrumentation scope
type ScopeLogs struct {
	Scope      InstrumentationScope `json:"scope"`
	LogRecords []LogRecord          `json:"logRecords"`
}

// LogRecord represents a single OTLP log record
type LogRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 AnyValue   `json:"body"`
	Attributes           []KeyValue `json:"attributes,omitempty"`
	TraceID              string     `json:"traceId,omitempty"`
	SpanID               string     `json:"spanId,omitempty"`
}

// Resource represents an OTLP resource
type Resource struct {
	Attributes []KeyValue `json:"attributes"`
}

// InstrumentationScope represents an instrumentation scope
type InstrumentationScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// KeyValue represents a key-value attribute
type KeyValue struct {
	Key   string   `json:"key"`
	Value AnyValue `json:"value"`
}

// AnyValue represents an OTLP AnyValue
type AnyValue struct {
	StringValue string  `json:"stringValue,omitempty"`
	IntValue    int64   `json:"intValue,omitempty"`
	DoubleValue float64 `json:"doubleValue,omitempty"`
	BoolValue   bool    `json:"boolValue,omitempty"`
}

// convertToOTLPMetrics converts internal metrics to OTLP format
func convertToOTLPMetrics(metrics []Metric, serviceName string, tags map[string]string) *OTLPMetrics {
	// Build resource attributes
	resourceAttrs := []KeyValue{
		{Key: "service.name", Value: AnyValue{StringValue: serviceName}},
	}
	for k, v := range tags {
		resourceAttrs = append(resourceAttrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
	}

	// Convert metrics
	otlpMetrics := make([]OTLPMetric, 0, len(metrics))
	for _, m := range metrics {
		// Convert metric attributes
		attrs := make([]KeyValue, 0, len(m.Tags))
		for k, v := range m.Tags {
			attrs = append(attrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
		}

		timeNano := formatTimeNano(m.Timestamp)
		dataPoint := NumberDataPoint{
			Attributes:   attrs,
			TimeUnixNano: timeNano,
			AsDouble:     m.Value,
		}

		otlpMetric := OTLPMetric{
			Name: m.Name,
			Unit: m.Unit,
		}

		switch m.Type {
		case MetricTypeCounter:
			otlpMetric.Sum = &Sum{
				AggregationTemporality: "AGGREGATION_TEMPORALITY_CUMULATIVE",
				IsMonotonic:            true,
				DataPoints:             []NumberDataPoint{dataPoint},
			}
		case MetricTypeHistogram:
			otlpMetric.Histogram = &Histogram{
				AggregationTemporality: "AGGREGATION_TEMPORALITY_CUMULATIVE",
				DataPoints: []HistogramDataPoint{
					{
						Attributes:   attrs,
						TimeUnixNano: timeNano,
						Sum:          m.Value,
						Count:        1,
					},
				},
			}
		case MetricTypeSummary:
			otlpMetric.Summary = &OTLPSummary{
				DataPoints: []SummaryDataPoint{
					{
						Attributes:   attrs,
						TimeUnixNano: timeNano,
						Sum:          m.Value,
						Count:        1,
					},
				},
			}
		default: // Gauge
			otlpMetric.Gauge = &Gauge{
				DataPoints: []NumberDataPoint{dataPoint},
			}
		}

		otlpMetrics = append(otlpMetrics, otlpMetric)
	}

	return &OTLPMetrics{
		ResourceMetrics: []ResourceMetrics{
			{
				Resource: Resource{Attributes: resourceAttrs},
				ScopeMetrics: []ScopeMetrics{
					{
						Scope:   InstrumentationScope{Name: "tfo-agent", Version: "1.1.2"},
						Metrics: otlpMetrics,
					},
				},
			},
		},
	}
}

// convertToOTLPTraces converts internal traces to OTLP format
func convertToOTLPTraces(traces []Trace, serviceName string, tags map[string]string) *OTLPTraces {
	// Build resource attributes
	resourceAttrs := []KeyValue{
		{Key: "service.name", Value: AnyValue{StringValue: serviceName}},
	}
	for k, v := range tags {
		resourceAttrs = append(resourceAttrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
	}

	// Convert traces to spans
	spans := make([]OTLPSpan, 0, len(traces))
	for _, t := range traces {
		// Convert trace attributes
		attrs := make([]KeyValue, 0, len(t.Tags))
		for k, v := range t.Tags {
			attrs = append(attrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
		}

		// Convert span logs to events
		events := make([]SpanEvent, 0, len(t.Logs))
		for _, log := range t.Logs {
			eventAttrs := make([]KeyValue, 0, len(log.Fields)+1)
			eventAttrs = append(eventAttrs, KeyValue{Key: "message", Value: AnyValue{StringValue: log.Message}})
			for k, v := range log.Fields {
				eventAttrs = append(eventAttrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
			}
			events = append(events, SpanEvent{
				TimeUnixNano: formatTimeNano(log.Timestamp),
				Name:         "log",
				Attributes:   eventAttrs,
			})
		}

		// Determine status code
		statusCode := 1 // OK
		if t.Status == TraceStatusError {
			statusCode = 2 // Error
		}

		span := OTLPSpan{
			TraceID:           t.TraceID,
			SpanID:            t.SpanID,
			ParentSpanID:      t.ParentSpanID,
			Name:              t.OperationName,
			Kind:              1, // SPAN_KIND_INTERNAL
			StartTimeUnixNano: formatTimeNano(t.StartTime),
			EndTimeUnixNano:   formatTimeNano(t.StartTime.Add(t.Duration)),
			Attributes:        attrs,
			Status:            SpanStatus{Code: statusCode},
			Events:            events,
		}
		spans = append(spans, span)
	}

	return &OTLPTraces{
		ResourceSpans: []ResourceSpans{
			{
				Resource: Resource{Attributes: resourceAttrs},
				ScopeSpans: []ScopeSpans{
					{
						Scope: InstrumentationScope{Name: "tfo-agent", Version: "1.1.2"},
						Spans: spans,
					},
				},
			},
		},
	}
}

// convertToOTLPLogs converts internal logs to OTLP format
func convertToOTLPLogs(logs []LogEntry, serviceName string, tags map[string]string) *OTLPLogs {
	// Build resource attributes
	resourceAttrs := []KeyValue{
		{Key: "service.name", Value: AnyValue{StringValue: serviceName}},
	}
	for k, v := range tags {
		resourceAttrs = append(resourceAttrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
	}

	// Convert logs
	logRecords := make([]LogRecord, 0, len(logs))
	for _, l := range logs {
		// Convert log attributes
		attrs := make([]KeyValue, 0, len(l.Attributes)+1)
		if l.Source != "" {
			attrs = append(attrs, KeyValue{Key: "source", Value: AnyValue{StringValue: l.Source}})
		}
		for k, v := range l.Attributes {
			attrs = append(attrs, KeyValue{Key: k, Value: AnyValue{StringValue: v}})
		}

		timeNano := formatTimeNano(l.Timestamp)
		record := LogRecord{
			TimeUnixNano:         timeNano,
			ObservedTimeUnixNano: timeNano,
			SeverityNumber:       logLevelToSeverityNumber(l.Level),
			SeverityText:         string(l.Level),
			Body:                 AnyValue{StringValue: l.Message},
			Attributes:           attrs,
			TraceID:              l.TraceID,
			SpanID:               l.SpanID,
		}
		logRecords = append(logRecords, record)
	}

	return &OTLPLogs{
		ResourceLogs: []ResourceLogs{
			{
				Resource: Resource{Attributes: resourceAttrs},
				ScopeLogs: []ScopeLogs{
					{
						Scope:      InstrumentationScope{Name: "tfo-agent", Version: "1.1.2"},
						LogRecords: logRecords,
					},
				},
			},
		},
	}
}

// formatTimeNano formats a time.Time as nanoseconds string for OTLP JSON
func formatTimeNano(t time.Time) string {
	return formatUnixNano(t.UnixNano())
}

// formatUnixNano formats nanoseconds as string
func formatUnixNano(nanos int64) string {
	return time.Unix(0, nanos).UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// logLevelToSeverityNumber converts log level to OTLP severity number
func logLevelToSeverityNumber(level LogLevel) int {
	switch level {
	case LogLevelDebug:
		return 5 // DEBUG
	case LogLevelInfo:
		return 9 // INFO
	case LogLevelWarn:
		return 13 // WARN
	case LogLevelError:
		return 17 // ERROR
	case LogLevelFatal:
		return 21 // FATAL
	default:
		return 9 // INFO as default
	}
}
