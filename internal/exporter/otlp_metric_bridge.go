// Package exporter converts collector.Metric slices to OTLP and exports them via an OTLP HTTP endpoint.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

package exporter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// OTLPMetricBridge converts collector.Metric slices to OTLP and exports them
// via an OTLP HTTP endpoint. Each call to Export sends a batch immediately.
//
// Resource attributes are set per-instance (e.g. db.system=postgresql,
// db.instance.id, net.host.name) so the backend can route and identify the
// metric source correctly.
type OTLPMetricBridge struct {
	exporter sdkmetric.Exporter
	logger   *zap.Logger

	mu sync.Mutex
}

// OTLPMetricBridgeConfig holds configuration for creating an OTLPMetricBridge.
type OTLPMetricBridgeConfig struct {
	Endpoint      string
	Path          string // OTLP HTTP path, e.g. "/v1/metrics"
	TLSEnabled    bool
	TLSSkipVerify bool
	Headers       map[string]string
	Logger        *zap.Logger
}

// NewOTLPMetricBridge creates and initialises the OTLP HTTP metric exporter.
func NewOTLPMetricBridge(ctx context.Context, cfg OTLPMetricBridgeConfig) (*OTLPMetricBridge, error) {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Path != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(cfg.Path))
	}
	if cfg.TLSEnabled {
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(newTLSConfig(cfg.TLSSkipVerify)))
	} else {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}

	exp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp metric bridge: create exporter: %w", err)
	}

	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &OTLPMetricBridge{
		exporter: exp,
		logger:   logger,
	}, nil
}

// Export converts a batch of collector.Metric into OTLP ResourceMetrics and
// sends them to the configured OTLP endpoint. The resourceAttrs parameter
// is merged with a base set that includes service.name and service.version.
func (b *OTLPMetricBridge) Export(ctx context.Context, metrics []collector.Metric, resourceAttrs map[string]string) error {
	if len(metrics) == 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Build OTel resource from the provided attributes.
	attrs := baseResourceAttrs()
	for k, v := range resourceAttrs {
		attrs = append(attrs, attribute.String(k, v))
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		return fmt.Errorf("otlp metric bridge: build resource: %w", err)
	}

	// Group metrics by name so we can create one Metrics entry per unique name.
	grouped := groupMetricsByName(metrics)

	var scopeMetrics []metricdata.Metrics
	for name, points := range grouped {
		md := buildAggregation(points)
		scopeMetrics = append(scopeMetrics, metricdata.Metrics{
			Name:        name,
			Description: points[0].m.Description,
			Unit:        points[0].m.Unit,
			Data:        md,
		})
	}

	rm := &metricdata.ResourceMetrics{
		Resource: res,
		ScopeMetrics: []metricdata.ScopeMetrics{
			{
				Scope:   instrumentationScope(),
				Metrics: scopeMetrics,
			},
		},
	}

	if err := b.exporter.Export(ctx, rm); err != nil {
		return fmt.Errorf("otlp metric bridge: export: %w", err)
	}

	b.logger.Debug("OTLP metric bridge exported",
		zap.Int("metrics", len(metrics)),
	)
	return nil
}

// Shutdown flushes pending exports and closes the exporter.
func (b *OTLPMetricBridge) Shutdown(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exporter != nil {
		return b.exporter.Shutdown(ctx)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type metricPoint struct {
	m     collector.Metric
	attrs attribute.Set
}

func baseResourceAttrs() []attribute.KeyValue {
	return []attribute.KeyValue{
		semconv.ServiceName("telemetryflow-agent"),
		semconv.ServiceVersion("1.0.0"),
	}
}

func instrumentationScope() instrumentation.Scope {
	return instrumentation.Scope{
		Name:    "github.com/telemetryflow/telemetryflow-agent",
		Version: "1.0.0",
	}
}

// groupMetricsByName groups metric points by metric name for efficient OTLP
// serialisation (one Metrics entry per unique name with multiple data points).
func groupMetricsByName(metrics []collector.Metric) map[string][]metricPoint {
	groups := make(map[string][]metricPoint, len(metrics))
	for i := range metrics {
		m := &metrics[i]
		attrs := labelsToAttributeSet(m.Labels)
		groups[m.Name] = append(groups[m.Name], metricPoint{m: *m, attrs: attrs})
	}
	return groups
}

// buildAggregation creates the appropriate Aggregation (Gauge or Sum) based on
// the metric type of the first point. All points in a group share the same type.
func buildAggregation(points []metricPoint) metricdata.Aggregation {
	if len(points) == 0 {
		return metricdata.Gauge[float64]{}
	}

	switch points[0].m.Type {
	case collector.MetricTypeCounter:
		dataPoints := make([]metricdata.DataPoint[float64], len(points))
		for i, p := range points {
			dataPoints[i] = metricdata.DataPoint[float64]{
				Attributes: p.attrs,
				StartTime:  points[0].m.Timestamp.Add(-time.Second),
				Time:       p.m.Timestamp,
				Value:      p.m.Value,
			}
		}
		return metricdata.Sum[float64]{
			DataPoints:  dataPoints,
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
		}
	default: // gauge, histogram, summary all fall through to gauge
		dataPoints := make([]metricdata.DataPoint[float64], len(points))
		for i, p := range points {
			dataPoints[i] = metricdata.DataPoint[float64]{
				Attributes: p.attrs,
				Time:       p.m.Timestamp,
				Value:      p.m.Value,
			}
		}
		return metricdata.Gauge[float64]{DataPoints: dataPoints}
	}
}

// labelsToAttributeSet converts a map of string labels to an OTel attribute.Set.
func labelsToAttributeSet(labels map[string]string) attribute.Set {
	if len(labels) == 0 {
		return *attribute.EmptySet()
	}
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attribute.NewSet(attrs...)
}
