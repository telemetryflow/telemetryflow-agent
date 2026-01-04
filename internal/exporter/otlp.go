// Package exporter provides telemetry export functionality for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
//
// This exporter supports dual endpoint versions:
// - v1: OTEL community standard endpoints (/v1/metrics, /v1/traces, /v1/logs)
// - v2: TelemetryFlow Platform endpoints (/v2/metrics, /v2/traces, /v2/logs)
package exporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// OTLPExporter exports telemetry using OpenTelemetry Protocol
// Supports metrics, traces, and logs with dual endpoint versions (v1/v2)
type OTLPExporter struct {
	config OTLPExporterConfig
	logger *zap.Logger

	// Metrics
	meterProvider *sdkmetric.MeterProvider
	meter         metric.Meter

	// Traces
	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer

	// Logs
	loggerProvider *sdklog.LoggerProvider

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

	// Endpoint version (v1 for OTEL standard, v2 for TFO Platform)
	EndpointVersion string

	// Signal-specific endpoint paths (for HTTP protocol)
	MetricsEndpointPath string
	TracesEndpointPath  string
	LogsEndpointPath    string

	// Signal type enablement
	MetricsEnabled bool
	TracesEnabled  bool
	LogsEnabled    bool

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

	// Signal-specific stats
	MetricsSent    int64
	TracesSent     int64
	LogsSent       int64
	BytesSent      int64
	MetricsEnabled bool
	TracesEnabled  bool
	LogsEnabled    bool

	// Endpoint info
	EndpointVersion string
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
	e.stats.MetricsEnabled = e.config.MetricsEnabled
	e.stats.TracesEnabled = e.config.TracesEnabled
	e.stats.LogsEnabled = e.config.LogsEnabled
	e.stats.EndpointVersion = e.config.EndpointVersion
	e.mu.Unlock()

	e.logger.Info("Starting OTLP exporter",
		zap.String("endpoint", e.config.Endpoint),
		zap.String("protocol", e.config.Protocol),
		zap.String("endpointVersion", e.config.EndpointVersion),
		zap.String("agentId", e.config.AgentID),
		zap.Bool("metricsEnabled", e.config.MetricsEnabled),
		zap.Bool("tracesEnabled", e.config.TracesEnabled),
		zap.Bool("logsEnabled", e.config.LogsEnabled),
	)

	// Create resource with agent metadata
	res, err := e.createResource(ctx)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize Metrics Provider
	if e.config.MetricsEnabled {
		if err := e.initMetricsProvider(ctx, res); err != nil {
			return fmt.Errorf("failed to initialize metrics provider: %w", err)
		}
	}

	// Initialize Traces Provider
	if e.config.TracesEnabled {
		if err := e.initTracesProvider(ctx, res); err != nil {
			return fmt.Errorf("failed to initialize traces provider: %w", err)
		}
	}

	// Initialize Logs Provider
	if e.config.LogsEnabled {
		if err := e.initLogsProvider(ctx, res); err != nil {
			return fmt.Errorf("failed to initialize logs provider: %w", err)
		}
	}

	e.logger.Info("OTLP exporter started successfully",
		zap.String("endpointVersion", e.config.EndpointVersion),
	)
	return nil
}

// initMetricsProvider initializes the metrics provider
func (e *OTLPExporter) initMetricsProvider(ctx context.Context, res *resource.Resource) error {
	var metricExporter sdkmetric.Exporter
	var err error

	switch e.config.Protocol {
	case "grpc":
		metricExporter, err = e.createGRPCMetricExporter(ctx)
	case "http":
		metricExporter, err = e.createHTTPMetricExporter(ctx)
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

	e.logger.Info("Metrics provider initialized",
		zap.String("endpoint", e.config.Endpoint),
		zap.String("path", e.config.MetricsEndpointPath),
	)
	return nil
}

// initTracesProvider initializes the traces provider
func (e *OTLPExporter) initTracesProvider(ctx context.Context, res *resource.Resource) error {
	var traceExporter sdktrace.SpanExporter
	var err error

	switch e.config.Protocol {
	case "grpc":
		traceExporter, err = e.createGRPCTraceExporter(ctx)
	case "http":
		traceExporter, err = e.createHTTPTraceExporter(ctx)
	default:
		return fmt.Errorf("unsupported protocol: %s", e.config.Protocol)
	}
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create tracer provider with batch processor
	e.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithBatchTimeout(e.config.FlushInterval),
			sdktrace.WithMaxExportBatchSize(e.config.BatchSize),
		),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(e.tracerProvider)

	// Create tracer for agent traces
	e.tracer = e.tracerProvider.Tracer(
		"github.com/telemetryflow/telemetryflow-agent",
		trace.WithInstrumentationVersion(e.config.Version),
	)

	e.logger.Info("Traces provider initialized",
		zap.String("endpoint", e.config.Endpoint),
		zap.String("path", e.config.TracesEndpointPath),
	)
	return nil
}

// initLogsProvider initializes the logs provider
func (e *OTLPExporter) initLogsProvider(ctx context.Context, res *resource.Resource) error {
	var logExporter sdklog.Exporter
	var err error

	switch e.config.Protocol {
	case "grpc":
		logExporter, err = e.createGRPCLogExporter(ctx)
	case "http":
		logExporter, err = e.createHTTPLogExporter(ctx)
	default:
		return fmt.Errorf("unsupported protocol: %s", e.config.Protocol)
	}
	if err != nil {
		return fmt.Errorf("failed to create log exporter: %w", err)
	}

	// Create logger provider with batch processor
	e.loggerProvider = sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(
			sdklog.NewBatchProcessor(logExporter,
				sdklog.WithExportInterval(e.config.FlushInterval),
				sdklog.WithExportMaxBatchSize(e.config.BatchSize),
			),
		),
	)

	e.logger.Info("Logs provider initialized",
		zap.String("endpoint", e.config.Endpoint),
		zap.String("path", e.config.LogsEndpointPath),
	)
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

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var errs []error

	// Shutdown meter provider
	if e.meterProvider != nil {
		if err := e.meterProvider.Shutdown(shutdownCtx); err != nil {
			e.logger.Error("Failed to shutdown meter provider", zap.Error(err))
			errs = append(errs, err)
		}
	}

	// Shutdown tracer provider
	if e.tracerProvider != nil {
		if err := e.tracerProvider.Shutdown(shutdownCtx); err != nil {
			e.logger.Error("Failed to shutdown tracer provider", zap.Error(err))
			errs = append(errs, err)
		}
	}

	// Shutdown logger provider
	if e.loggerProvider != nil {
		if err := e.loggerProvider.Shutdown(shutdownCtx); err != nil {
			e.logger.Error("Failed to shutdown logger provider", zap.Error(err))
			errs = append(errs, err)
		}
	}

	e.logger.Info("OTLP exporter stopped")

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Meter returns the OpenTelemetry meter for recording metrics
func (e *OTLPExporter) Meter() metric.Meter {
	return e.meter
}

// Tracer returns the OpenTelemetry tracer for recording traces
func (e *OTLPExporter) Tracer() trace.Tracer {
	return e.tracer
}

// LoggerProvider returns the OpenTelemetry logger provider for recording logs
func (e *OTLPExporter) LoggerProvider() *sdklog.LoggerProvider {
	return e.loggerProvider
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

// getAuthHeaders returns the authentication headers for TelemetryFlow
func (e *OTLPExporter) getAuthHeaders() map[string]string {
	if e.config.APIKeyID == "" || e.config.APIKeySecret == "" {
		return nil
	}
	return map[string]string{
		"X-TelemetryFlow-Key-ID":     e.config.APIKeyID,
		"X-TelemetryFlow-Key-Secret": e.config.APIKeySecret,
		"X-TelemetryFlow-Agent-ID":   e.config.AgentID,
	}
}

// =============================================================================
// Metrics Exporters (gRPC and HTTP)
// =============================================================================

// createGRPCMetricExporter creates a gRPC-based OTLP metric exporter
func (e *OTLPExporter) createGRPCMetricExporter(ctx context.Context) (sdkmetric.Exporter, error) {
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
	if headers := e.getAuthHeaders(); headers != nil {
		opts = append(opts, otlpmetricgrpc.WithHeaders(headers))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlpmetricgrpc.WithCompressor("gzip"))
	}

	return otlpmetricgrpc.New(ctx, opts...)
}

// createHTTPMetricExporter creates an HTTP-based OTLP metric exporter
func (e *OTLPExporter) createHTTPMetricExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(e.config.Endpoint),
		otlpmetrichttp.WithTimeout(e.config.Timeout),
	}

	// Set URL path for dual endpoint support (v1/v2)
	if e.config.MetricsEndpointPath != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(e.config.MetricsEndpointPath))
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(newTLSConfig(e.config.TLSSkipVerify)))
	} else {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	// Add authentication headers
	if headers := e.getAuthHeaders(); headers != nil {
		opts = append(opts, otlpmetrichttp.WithHeaders(headers))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
	}

	return otlpmetrichttp.New(ctx, opts...)
}

// =============================================================================
// Trace Exporters (gRPC and HTTP)
// =============================================================================

// createGRPCTraceExporter creates a gRPC-based OTLP trace exporter
func (e *OTLPExporter) createGRPCTraceExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(e.config.Endpoint),
		otlptracegrpc.WithTimeout(e.config.Timeout),
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlptracegrpc.WithDialOption(
			grpc.WithTransportCredentials(credentials.NewTLS(newTLSConfig(e.config.TLSSkipVerify))),
		))
	} else {
		opts = append(opts, otlptracegrpc.WithDialOption(
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		))
	}

	// Add authentication headers
	if headers := e.getAuthHeaders(); headers != nil {
		opts = append(opts, otlptracegrpc.WithHeaders(headers))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlptracegrpc.WithCompressor("gzip"))
	}

	return otlptracegrpc.New(ctx, opts...)
}

// createHTTPTraceExporter creates an HTTP-based OTLP trace exporter
func (e *OTLPExporter) createHTTPTraceExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(e.config.Endpoint),
		otlptracehttp.WithTimeout(e.config.Timeout),
	}

	// Set URL path for dual endpoint support (v1/v2)
	if e.config.TracesEndpointPath != "" {
		opts = append(opts, otlptracehttp.WithURLPath(e.config.TracesEndpointPath))
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(newTLSConfig(e.config.TLSSkipVerify)))
	} else {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	// Add authentication headers
	if headers := e.getAuthHeaders(); headers != nil {
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
	}

	return otlptracehttp.New(ctx, opts...)
}

// =============================================================================
// Log Exporters (gRPC and HTTP)
// =============================================================================

// createGRPCLogExporter creates a gRPC-based OTLP log exporter
func (e *OTLPExporter) createGRPCLogExporter(ctx context.Context) (sdklog.Exporter, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(e.config.Endpoint),
		otlploggrpc.WithTimeout(e.config.Timeout),
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlploggrpc.WithDialOption(
			grpc.WithTransportCredentials(credentials.NewTLS(newTLSConfig(e.config.TLSSkipVerify))),
		))
	} else {
		opts = append(opts, otlploggrpc.WithDialOption(
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		))
	}

	// Add authentication headers
	if headers := e.getAuthHeaders(); headers != nil {
		opts = append(opts, otlploggrpc.WithHeaders(headers))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlploggrpc.WithCompressor("gzip"))
	}

	return otlploggrpc.New(ctx, opts...)
}

// createHTTPLogExporter creates an HTTP-based OTLP log exporter
func (e *OTLPExporter) createHTTPLogExporter(ctx context.Context) (sdklog.Exporter, error) {
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(e.config.Endpoint),
		otlploghttp.WithTimeout(e.config.Timeout),
	}

	// Set URL path for dual endpoint support (v1/v2)
	if e.config.LogsEndpointPath != "" {
		opts = append(opts, otlploghttp.WithURLPath(e.config.LogsEndpointPath))
	}

	// Configure TLS
	if e.config.TLSEnabled {
		opts = append(opts, otlploghttp.WithTLSClientConfig(newTLSConfig(e.config.TLSSkipVerify)))
	} else {
		opts = append(opts, otlploghttp.WithInsecure())
	}

	// Add authentication headers
	if headers := e.getAuthHeaders(); headers != nil {
		opts = append(opts, otlploghttp.WithHeaders(headers))
	}

	// Enable compression
	if e.config.Compression {
		opts = append(opts, otlploghttp.WithCompression(otlploghttp.GzipCompression))
	}

	return otlploghttp.New(ctx, opts...)
}

// NewOTLPExporterFromConfig creates an OTLP exporter from agent configuration
func NewOTLPExporterFromConfig(cfg *config.Config, logger *zap.Logger) *OTLPExporter {
	exporterCfg := OTLPExporterConfig{
		// Agent identification
		AgentID:     cfg.Agent.ID,
		AgentName:   cfg.Agent.Name,
		Hostname:    cfg.Agent.Hostname,
		Environment: cfg.Agent.Tags["environment"],
		Version:     cfg.Agent.Version,

		// Connection settings
		Endpoint:     cfg.GetEffectiveEndpoint(),
		Protocol:     cfg.TelemetryFlow.Protocol,
		APIKeyID:     cfg.GetEffectiveAPIKeyID(),
		APIKeySecret: cfg.GetEffectiveAPIKeySecret(),

		// TLS settings
		TLSEnabled:    cfg.TelemetryFlow.TLS.Enabled,
		TLSSkipVerify: cfg.TelemetryFlow.TLS.SkipVerify,

		// Export settings
		BatchSize:     cfg.Exporter.OTLP.BatchSize,
		FlushInterval: cfg.Exporter.OTLP.FlushInterval,
		Timeout:       cfg.TelemetryFlow.Timeout,
		Compression:   cfg.Exporter.OTLP.Compression == "gzip",

		// Dual endpoint version support (v1/v2)
		EndpointVersion:     cfg.GetEndpointVersion(),
		MetricsEndpointPath: cfg.GetMetricsEndpointPath(),
		TracesEndpointPath:  cfg.GetTracesEndpointPath(),
		LogsEndpointPath:    cfg.GetLogsEndpointPath(),

		// Signal type enablement
		MetricsEnabled: cfg.IsMetricsEnabled(),
		TracesEnabled:  cfg.IsTracesEnabled(),
		LogsEnabled:    cfg.IsLogsEnabled(),

		// Logger
		Logger: logger,
	}

	// Default protocol to grpc if not specified
	if exporterCfg.Protocol == "" {
		exporterCfg.Protocol = "grpc"
	}

	// Default endpoint version to v2 (TFO Platform) if not specified
	if exporterCfg.EndpointVersion == "" {
		exporterCfg.EndpointVersion = "v2"
	}

	return NewOTLPExporter(exporterCfg)
}
