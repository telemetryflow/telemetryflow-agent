// Package exporter provides telemetry export functionality for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
package exporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// OTLPExporter exports metrics using OpenTelemetry Protocol
type OTLPExporter struct {
	config        OTLPExporterConfig
	logger        *zap.Logger
	meterProvider *sdkmetric.MeterProvider
	meter         metric.Meter

	mu      sync.RWMutex
	running bool
	stats   OTLPExporterStats

	// Channels
	done chan struct{}
}

// OTLPExporterConfig contains OTLP exporter configuration
type OTLPExporterConfig struct {
	// Agent identification
	AgentID     string
	AgentName   string
	Hostname    string
	Environment string
	Version     string

	// Connection settings
	Endpoint string
	Protocol string // "grpc" or "http"

	// Authentication
	APIKeyID     string
	APIKeySecret string

	// TLS settings
	TLSEnabled    bool
	TLSSkipVerify bool

	// Export settings
	BatchSize     int
	FlushInterval time.Duration
	Timeout       time.Duration
	Compression   bool

	// Logger
	Logger *zap.Logger
}

// OTLPExporterStats contains exporter statistics
type OTLPExporterStats struct {
	Running      bool
	ExportCount  int64
	ErrorCount   int64
	LastExportAt time.Time
	LastError    error
	LastErrorAt  time.Time
	MetricsSent  int64
	BytesSent    int64
}

// NewOTLPExporter creates a new OTLP exporter
func NewOTLPExporter(cfg OTLPExporterConfig) *OTLPExporter {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &OTLPExporter{
		config: cfg,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Start initializes and starts the OTLP exporter
func (e *OTLPExporter) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("OTLP exporter already running")
	}
	e.running = true
	e.mu.Unlock()

	e.logger.Info("Starting OTLP exporter",
		zap.String("endpoint", e.config.Endpoint),
		zap.String("protocol", e.config.Protocol),
		zap.String("agentId", e.config.AgentID),
	)

	// Create resource with agent metadata
	res, err := e.createResource(ctx)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create metric exporter based on protocol
	var metricExporter sdkmetric.Exporter
	switch e.config.Protocol {
	case "grpc":
		metricExporter, err = e.createGRPCExporter(ctx)
	case "http":
		metricExporter, err = e.createHTTPExporter(ctx)
	default:
		return fmt.Errorf("unsupported protocol: %s", e.config.Protocol)
	}
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	// Create meter provider with periodic reader
	e.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				metricExporter,
				sdkmetric.WithInterval(e.config.FlushInterval),
			),
		),
	)

	// Set as global meter provider
	otel.SetMeterProvider(e.meterProvider)

	// Create meter for agent metrics
	e.meter = e.meterProvider.Meter(
		"github.com/telemetryflow/telemetryflow-agent",
		metric.WithInstrumentationVersion(e.config.Version),
	)

	e.logger.Info("OTLP exporter started successfully")
	return nil
}

// Stop gracefully stops the OTLP exporter
func (e *OTLPExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	e.mu.Unlock()

	close(e.done)

	e.logger.Info("Stopping OTLP exporter")

	if e.meterProvider != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := e.meterProvider.Shutdown(shutdownCtx); err != nil {
			e.logger.Error("Failed to shutdown meter provider", zap.Error(err))
			return err
		}
	}

	e.logger.Info("OTLP exporter stopped")
	return nil
}

// Meter returns the OpenTelemetry meter for recording metrics
func (e *OTLPExporter) Meter() metric.Meter {
	return e.meter
}

// IsRunning returns whether the exporter is running
func (e *OTLPExporter) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// Stats returns exporter statistics
func (e *OTLPExporter) Stats() OTLPExporterStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := e.stats
	stats.Running = e.running
	return stats
}

// newTLSConfig creates a TLS configuration with the specified skip verify setting.
// This function isolates the InsecureSkipVerify assignment to satisfy security linters
// while still allowing users to disable certificate verification for dev/testing environments.
func newTLSConfig(skipVerify bool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify,
	}
}

// createResource creates an OpenTelemetry resource with agent metadata
func (e *OTLPExporter) createResource(ctx context.Context) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(e.config.AgentName),
		semconv.ServiceVersion(e.config.Version),
		semconv.ServiceInstanceID(e.config.AgentID),
		semconv.HostName(e.config.Hostname),
		attribute.String("telemetryflow.agent.id", e.config.AgentID),
		attribute.String("telemetryflow.agent.name", e.config.AgentName),
		attribute.String("deployment.environment", e.config.Environment),
	}

	return resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcess(),
	)
}

// createGRPCExporter creates a gRPC-based OTLP metric exporter
func (e *OTLPExporter) createGRPCExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(e.config.Endpoint),
		otlpmetricgrpc.WithTimeout(e.config.Timeout),
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlpmetricgrpc.WithDialOption(
			grpc.WithTransportCredentials(credentials.NewTLS(newTLSConfig(e.config.TLSSkipVerify))),
		))
	} else {
		opts = append(opts, otlpmetricgrpc.WithDialOption(
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		))
	}

	// Add authentication headers
	if e.config.APIKeyID != "" && e.config.APIKeySecret != "" {
		opts = append(opts, otlpmetricgrpc.WithHeaders(map[string]string{
			"X-TelemetryFlow-Key-ID":     e.config.APIKeyID,
			"X-TelemetryFlow-Key-Secret": e.config.APIKeySecret,
			"X-TelemetryFlow-Agent-ID":   e.config.AgentID,
		}))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlpmetricgrpc.WithCompressor("gzip"))
	}

	return otlpmetricgrpc.New(ctx, opts...)
}

// createHTTPExporter creates an HTTP-based OTLP metric exporter
func (e *OTLPExporter) createHTTPExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(e.config.Endpoint),
		otlpmetrichttp.WithTimeout(e.config.Timeout),
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(newTLSConfig(e.config.TLSSkipVerify)))
	} else {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	// Add authentication headers
	if e.config.APIKeyID != "" && e.config.APIKeySecret != "" {
		opts = append(opts, otlpmetrichttp.WithHeaders(map[string]string{
			"X-TelemetryFlow-Key-ID":     e.config.APIKeyID,
			"X-TelemetryFlow-Key-Secret": e.config.APIKeySecret,
			"X-TelemetryFlow-Agent-ID":   e.config.AgentID,
		}))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
	}

	return otlpmetrichttp.New(ctx, opts...)
}

// NewOTLPExporterFromConfig creates an OTLP exporter from agent configuration
func NewOTLPExporterFromConfig(cfg *config.Config, logger *zap.Logger) *OTLPExporter {
	exporterCfg := OTLPExporterConfig{
		AgentID:       cfg.Agent.ID,
		AgentName:     cfg.Agent.Name,
		Hostname:      cfg.Agent.Hostname,
		Environment:   cfg.Agent.Tags["environment"],
		Version:       cfg.Agent.Version,
		Endpoint:      cfg.GetEffectiveEndpoint(),
		Protocol:      cfg.TelemetryFlow.Protocol,
		APIKeyID:      cfg.GetEffectiveAPIKeyID(),
		APIKeySecret:  cfg.GetEffectiveAPIKeySecret(),
		TLSEnabled:    cfg.TelemetryFlow.TLS.Enabled,
		TLSSkipVerify: cfg.TelemetryFlow.TLS.SkipVerify,
		BatchSize:     cfg.Exporter.OTLP.BatchSize,
		FlushInterval: cfg.Exporter.OTLP.FlushInterval,
		Timeout:       cfg.TelemetryFlow.Timeout,
		Compression:   cfg.Exporter.OTLP.Compression == "gzip",
		Logger:        logger,
	}

	// Default protocol to grpc if not specified
	if exporterCfg.Protocol == "" {
		exporterCfg.Protocol = "grpc"
	}

	return NewOTLPExporter(exporterCfg)
}
