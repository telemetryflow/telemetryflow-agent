// Package integrations provides 3rd party integration exporters for TelemetryFlow Agent.
// Each integration implements the Exporter interface for consistent data export capabilities.
package integrations

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// DataType represents the type of telemetry data
type DataType string

const (
	DataTypeMetrics DataType = "metrics"
	DataTypeTraces  DataType = "traces"
	DataTypeLogs    DataType = "logs"
)

// ExportResult contains the result of an export operation
type ExportResult struct {
	Success       bool          `json:"success"`
	ItemsExported int           `json:"itemsExported"`
	BytesSent     int64         `json:"bytesSent"`
	Duration      time.Duration `json:"duration"`
	Error         error         `json:"error,omitempty"`
	RetryCount    int           `json:"retryCount,omitempty"`
}

// Exporter defines the interface for all 3rd party integrations
type Exporter interface {
	// Name returns the integration name (e.g., "prometheus", "datadog")
	Name() string

	// Type returns the integration type for categorization
	Type() string

	// Init initializes the exporter with configuration
	Init(ctx context.Context) error

	// Validate validates the exporter configuration
	Validate() error

	// Export exports telemetry data
	Export(ctx context.Context, data *TelemetryData) (*ExportResult, error)

	// ExportMetrics exports metrics data
	ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error)

	// ExportTraces exports trace data
	ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error)

	// ExportLogs exports log data
	ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error)

	// Health returns the health status of the integration
	Health(ctx context.Context) (*HealthStatus, error)

	// Close gracefully shuts down the exporter
	Close(ctx context.Context) error

	// IsEnabled returns whether the integration is enabled
	IsEnabled() bool

	// SupportedDataTypes returns the data types this exporter supports
	SupportedDataTypes() []DataType
}

// TelemetryData represents a batch of telemetry data for export
type TelemetryData struct {
	Metrics    []Metric              `json:"metrics,omitempty"`
	Traces     []Trace               `json:"traces,omitempty"`
	Logs       []LogEntry            `json:"logs,omitempty"`
	SystemInfo *collector.SystemInfo `json:"systemInfo,omitempty"`
	Timestamp  time.Time             `json:"timestamp"`
	AgentID    string                `json:"agentId"`
	Hostname   string                `json:"hostname"`
	Tags       map[string]string     `json:"tags,omitempty"`
}

// Metric represents a single metric data point
type Metric struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Type      MetricType        `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Tags      map[string]string `json:"tags,omitempty"`
	Unit      string            `json:"unit,omitempty"`
	Interval  time.Duration     `json:"interval,omitempty"`
}

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeCounter   MetricType = "counter"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// Trace represents a distributed trace
type Trace struct {
	TraceID       string            `json:"traceId"`
	SpanID        string            `json:"spanId"`
	ParentSpanID  string            `json:"parentSpanId,omitempty"`
	OperationName string            `json:"operationName"`
	ServiceName   string            `json:"serviceName"`
	StartTime     time.Time         `json:"startTime"`
	Duration      time.Duration     `json:"duration"`
	Status        TraceStatus       `json:"status"`
	Tags          map[string]string `json:"tags,omitempty"`
	Logs          []SpanLog         `json:"logs,omitempty"`
}

// TraceStatus represents the status of a trace span
type TraceStatus string

const (
	TraceStatusOK    TraceStatus = "ok"
	TraceStatusError TraceStatus = "error"
)

// SpanLog represents a log entry within a span
type SpanLog struct {
	Timestamp time.Time         `json:"timestamp"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp  time.Time         `json:"timestamp"`
	Level      LogLevel          `json:"level"`
	Message    string            `json:"message"`
	Source     string            `json:"source,omitempty"`
	TraceID    string            `json:"traceId,omitempty"`
	SpanID     string            `json:"spanId,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// LogLevel represents log severity
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// HealthStatus represents the health of an integration
type HealthStatus struct {
	Healthy     bool                   `json:"healthy"`
	Message     string                 `json:"message,omitempty"`
	LastCheck   time.Time              `json:"lastCheck"`
	LastSuccess time.Time              `json:"lastSuccess,omitempty"`
	LastError   error                  `json:"lastError,omitempty"`
	Latency     time.Duration          `json:"latency,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// BaseExporter provides common functionality for all exporters
type BaseExporter struct {
	name            string
	integrationType string
	enabled         bool
	logger          *zap.Logger
	supportedTypes  []DataType

	mu            sync.RWMutex
	initialized   bool
	lastError     error
	lastSuccess   time.Time
	exportCount   int64
	errorCount    int64
	bytesExported int64
}

// NewBaseExporter creates a new base exporter
func NewBaseExporter(name, integrationType string, enabled bool, logger *zap.Logger, supportedTypes []DataType) *BaseExporter {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &BaseExporter{
		name:            name,
		integrationType: integrationType,
		enabled:         enabled,
		logger:          logger,
		supportedTypes:  supportedTypes,
	}
}

// Name returns the exporter name
func (b *BaseExporter) Name() string {
	return b.name
}

// Type returns the integration type
func (b *BaseExporter) Type() string {
	return b.integrationType
}

// IsEnabled returns whether the exporter is enabled
func (b *BaseExporter) IsEnabled() bool {
	return b.enabled
}

// SupportedDataTypes returns the supported data types
func (b *BaseExporter) SupportedDataTypes() []DataType {
	return b.supportedTypes
}

// Logger returns the logger
func (b *BaseExporter) Logger() *zap.Logger {
	return b.logger
}

// SetInitialized marks the exporter as initialized
func (b *BaseExporter) SetInitialized(initialized bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initialized = initialized
}

// IsInitialized returns whether the exporter is initialized
func (b *BaseExporter) IsInitialized() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.initialized
}

// RecordSuccess records a successful export
func (b *BaseExporter) RecordSuccess(bytesExported int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastSuccess = time.Now()
	b.lastError = nil
	b.exportCount++
	b.bytesExported += bytesExported
}

// RecordError records a failed export
func (b *BaseExporter) RecordError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastError = err
	b.errorCount++
}

// Stats returns exporter statistics
func (b *BaseExporter) Stats() ExporterStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return ExporterStats{
		Name:          b.name,
		Type:          b.integrationType,
		Enabled:       b.enabled,
		Initialized:   b.initialized,
		ExportCount:   b.exportCount,
		ErrorCount:    b.errorCount,
		BytesExported: b.bytesExported,
		LastSuccess:   b.lastSuccess,
		LastError:     b.lastError,
	}
}

// ExporterStats contains exporter statistics
type ExporterStats struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Enabled       bool      `json:"enabled"`
	Initialized   bool      `json:"initialized"`
	ExportCount   int64     `json:"exportCount"`
	ErrorCount    int64     `json:"errorCount"`
	BytesExported int64     `json:"bytesExported"`
	LastSuccess   time.Time `json:"lastSuccess,omitempty"`
	LastError     error     `json:"lastError,omitempty"`
}

// Common validation errors
var (
	ErrNotEnabled       = errors.New("integration is not enabled")
	ErrNotInitialized   = errors.New("integration is not initialized")
	ErrMissingEndpoint  = errors.New("endpoint is required")
	ErrMissingAPIKey    = errors.New("api_key is required")
	ErrMissingToken     = errors.New("token is required")
	ErrInvalidEndpoint  = errors.New("invalid endpoint URL")
	ErrConnectionFailed = errors.New("connection failed")
	ErrExportFailed     = errors.New("export failed")
	ErrTimeout          = errors.New("operation timed out")
	ErrRateLimited      = errors.New("rate limited")
	ErrAuthFailed       = errors.New("authentication failed")
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Integration string
	Field       string
	Message     string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s - %s", e.Integration, e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(integration, field, message string) *ValidationError {
	return &ValidationError{
		Integration: integration,
		Field:       field,
		Message:     message,
	}
}
