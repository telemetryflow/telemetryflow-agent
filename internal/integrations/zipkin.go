// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ZipkinConfig contains Zipkin integration configuration
type ZipkinConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	Endpoint      string            `mapstructure:"endpoint"`
	LocalEndpoint string            `mapstructure:"local_endpoint"`
	ServiceName   string            `mapstructure:"service_name"`
	BatchSize     int               `mapstructure:"batch_size"`
	FlushInterval time.Duration     `mapstructure:"flush_interval"`
	Timeout       time.Duration     `mapstructure:"timeout"`
	Headers       map[string]string `mapstructure:"headers"`
}

// ZipkinExporter exports traces to Zipkin
type ZipkinExporter struct {
	*BaseExporter
	config     ZipkinConfig
	httpClient *http.Client
}

// Zipkin V2 JSON format structures
type zipkinSpan struct {
	TraceID        string             `json:"traceId"`
	ID             string             `json:"id"`
	ParentID       string             `json:"parentId,omitempty"`
	Name           string             `json:"name"`
	Kind           string             `json:"kind,omitempty"`
	Timestamp      int64              `json:"timestamp"`
	Duration       int64              `json:"duration"`
	LocalEndpoint  *zipkinEndpoint    `json:"localEndpoint,omitempty"`
	RemoteEndpoint *zipkinEndpoint    `json:"remoteEndpoint,omitempty"`
	Annotations    []zipkinAnnotation `json:"annotations,omitempty"`
	Tags           map[string]string  `json:"tags,omitempty"`
	Debug          bool               `json:"debug,omitempty"`
	Shared         bool               `json:"shared,omitempty"`
}

type zipkinEndpoint struct {
	ServiceName string `json:"serviceName,omitempty"`
	IPv4        string `json:"ipv4,omitempty"`
	IPv6        string `json:"ipv6,omitempty"`
	Port        int    `json:"port,omitempty"`
}

type zipkinAnnotation struct {
	Timestamp int64  `json:"timestamp"`
	Value     string `json:"value"`
}

// NewZipkinExporter creates a new Zipkin exporter
func NewZipkinExporter(config ZipkinConfig, logger *zap.Logger) *ZipkinExporter {
	return &ZipkinExporter{
		BaseExporter: NewBaseExporter(
			"zipkin",
			"tracing",
			config.Enabled,
			logger,
			[]DataType{DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the Zipkin exporter
func (z *ZipkinExporter) Init(ctx context.Context) error {
	if !z.config.Enabled {
		return nil
	}

	if err := z.Validate(); err != nil {
		return err
	}

	// Set defaults
	if z.config.ServiceName == "" {
		z.config.ServiceName = "telemetryflow-agent"
	}
	if z.config.BatchSize == 0 {
		z.config.BatchSize = 100
	}
	if z.config.FlushInterval == 0 {
		z.config.FlushInterval = time.Second
	}
	if z.config.Timeout == 0 {
		z.config.Timeout = 30 * time.Second
	}

	// Create HTTP client
	z.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: z.config.Timeout,
	}

	z.SetInitialized(true)
	z.Logger().Info("Zipkin exporter initialized",
		zap.String("endpoint", z.config.Endpoint),
		zap.String("serviceName", z.config.ServiceName),
	)

	return nil
}

// Validate validates the Zipkin configuration
func (z *ZipkinExporter) Validate() error {
	if !z.config.Enabled {
		return nil
	}

	if z.config.Endpoint == "" {
		return NewValidationError("zipkin", "endpoint", "endpoint is required")
	}

	return nil
}

// Export exports telemetry data to Zipkin
func (z *ZipkinExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !z.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Traces) > 0 {
		return z.ExportTraces(ctx, data.Traces)
	}

	return &ExportResult{Success: true}, nil
}

// ExportMetrics is not supported by Zipkin
func (z *ZipkinExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("zipkin does not support metrics export")
}

// ExportTraces exports traces to Zipkin
func (z *ZipkinExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !z.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !z.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Zipkin format
	spans := make([]zipkinSpan, 0, len(traces))
	for _, t := range traces {
		span := zipkinSpan{
			TraceID:   t.TraceID,
			ID:        t.SpanID,
			ParentID:  t.ParentSpanID,
			Name:      t.OperationName,
			Timestamp: t.StartTime.UnixMicro(),
			Duration:  t.Duration.Microseconds(),
			LocalEndpoint: &zipkinEndpoint{
				ServiceName: t.ServiceName,
			},
			Tags: make(map[string]string),
		}

		// Copy tags
		for k, v := range t.Tags {
			span.Tags[k] = v
		}

		// Add error tag if status is error
		if t.Status == TraceStatusError {
			span.Tags["error"] = "true"
		}

		// Convert span logs to annotations
		for _, log := range t.Logs {
			span.Annotations = append(span.Annotations, zipkinAnnotation{
				Timestamp: log.Timestamp.UnixMicro(),
				Value:     log.Message,
			})
		}

		spans = append(spans, span)
	}

	body, err := json.Marshal(spans)
	if err != nil {
		z.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := z.sendRequest(ctx, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		z.RecordError(err)
		return result, err
	}

	z.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs is not supported by Zipkin
func (z *ZipkinExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("zipkin does not support logs export")
}

// Health checks the health of Zipkin
func (z *ZipkinExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !z.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check Zipkin health endpoint
	healthURL := z.config.Endpoint
	if healthURL[len(healthURL)-1] != '/' {
		healthURL += "/"
	}
	healthURL += "health"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   fmt.Sprintf("connection failed: %v", err),
			LastCheck: time.Now(),
			LastError: err,
			Latency:   time.Since(startTime),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	return &HealthStatus{
		Healthy:   resp.StatusCode == http.StatusOK,
		Message:   fmt.Sprintf("status: %d", resp.StatusCode),
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
	}, nil
}

// Close closes the Zipkin exporter
func (z *ZipkinExporter) Close(ctx context.Context) error {
	if z.httpClient != nil {
		z.httpClient.CloseIdleConnections()
	}
	z.SetInitialized(false)
	z.Logger().Info("Zipkin exporter closed")
	return nil
}

// sendRequest sends spans to Zipkin
func (z *ZipkinExporter) sendRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	spansURL := z.config.Endpoint
	if spansURL[len(spansURL)-1] != '/' {
		spansURL += "/"
	}
	spansURL += "api/v2/spans"

	req, err := http.NewRequestWithContext(ctx, "POST", spansURL, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for k, v := range z.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("zipkin error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
