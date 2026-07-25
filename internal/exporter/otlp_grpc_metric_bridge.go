// Package exporter: OTLPMetricGRPCBridge converts collector.Metric slices to
// OTLP and exports them via an OTLP gRPC endpoint. Mirrors OTLPMetricBridge
// (HTTP) but uses otlpmetricgrpc so deployments that prefer gRPC (e.g. the
// standard OTLP collector on :4317) can use the same MetricSink contract.
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

package exporter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// OTLPMetricGRPCBridge converts collector.Metric slices to OTLP and exports
// them via an OTLP gRPC endpoint. It is the gRPC twin of OTLPMetricBridge and
// satisfies the MetricSink interface so it can be wired into the metric
// forwarder and the disk-backed retry buffer unchanged.
type OTLPMetricGRPCBridge struct {
	exporter sdkmetric.Exporter
	logger   *zap.Logger

	mu sync.Mutex
}

// OTLPMetricGRPCBridgeConfig holds configuration for creating an
// OTLPMetricGRPCBridge.
type OTLPMetricGRPCBridgeConfig struct {
	// Endpoint is the gRPC host:port (e.g. "api.telemetryflow.id:4317").
	Endpoint string

	// TLSEnabled enables TLS transport credentials.
	TLSEnabled bool

	// TLSSkipVerify disables certificate verification (insecure; dev/test only).
	TLSSkipVerify bool

	// Headers are gRPC metadata headers (e.g. auth headers).
	Headers map[string]string

	// Logger is the structured logger; defaults to a production logger when nil.
	Logger *zap.Logger

	// Timeout is the per-RPC timeout. Zero leaves the exporter default.
	Timeout time.Duration

	// Compression selects the gRPC compressor; only "gzip" is honoured.
	Compression string
}

// NewOTLPMetricGRPCBridge creates and initialises the OTLP gRPC metric
// exporter. The returned bridge satisfies exporter.MetricSink.
func NewOTLPMetricGRPCBridge(ctx context.Context, cfg OTLPMetricGRPCBridgeConfig) (*OTLPMetricGRPCBridge, error) {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Timeout > 0 {
		opts = append(opts, otlpmetricgrpc.WithTimeout(cfg.Timeout))
	}
	if cfg.TLSEnabled {
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(newTLSConfig(cfg.TLSSkipVerify))))
	} else {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
	}
	if cfg.Compression == "gzip" {
		opts = append(opts, otlpmetricgrpc.WithCompressor("gzip"))
	}

	exp, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp grpc metric bridge: create exporter: %w", err)
	}

	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &OTLPMetricGRPCBridge{
		exporter: exp,
		logger:   logger,
	}, nil
}

// Export converts a batch of collector.Metric into OTLP ResourceMetrics and
// sends them to the configured OTLP gRPC endpoint. resourceAttrs is merged
// with the base service.name/service.version attributes.
func (b *OTLPMetricGRPCBridge) Export(ctx context.Context, metrics []collector.Metric, resourceAttrs map[string]string) error {
	if len(metrics) == 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	attrs := baseResourceAttrs()
	for k, v := range resourceAttrs {
		attrs = append(attrs, attribute.String(k, v))
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		return fmt.Errorf("otlp grpc metric bridge: build resource: %w", err)
	}

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
		return fmt.Errorf("otlp grpc metric bridge: export: %w", err)
	}

	b.logger.Debug("otlp grpc metric bridge exported",
		zap.Int("metrics", len(metrics)),
	)
	return nil
}

// Shutdown flushes pending exports and closes the underlying gRPC exporter.
func (b *OTLPMetricGRPCBridge) Shutdown(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exporter != nil {
		return b.exporter.Shutdown(ctx)
	}
	return nil
}

// Compile-time interface guards.
var (
	_ MetricSink = (*OTLPMetricGRPCBridge)(nil)
)
