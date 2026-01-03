// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// CorootConfig contains Coroot integration configuration
type CorootConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Endpoint        string            `mapstructure:"endpoint"`
	APIKey          string            `mapstructure:"api_key"`
	ProjectID       string            `mapstructure:"project_id"`
	MetricsEndpoint string            `mapstructure:"metrics_endpoint"`
	TracesEndpoint  string            `mapstructure:"traces_endpoint"`
	LogsEndpoint    string            `mapstructure:"logs_endpoint"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	ServiceName     string            `mapstructure:"service_name"`
	Tags            map[string]string `mapstructure:"tags"`
	Headers         map[string]string `mapstructure:"headers"`
}

// CorootExporter exports telemetry data to Coroot
type CorootExporter struct {
	*BaseExporter
	config     CorootConfig
	httpClient *http.Client
}

// NewCorootExporter creates a new Coroot exporter
func NewCorootExporter(config CorootConfig, logger *zap.Logger) *CorootExporter {
	return &CorootExporter{
		BaseExporter: NewBaseExporter(
			"coroot",
			"observability",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Coroot exporter
func (c *CorootExporter) Init(ctx context.Context) error {
	if !c.config.Enabled {
		return nil
	}

	if err := c.Validate(); err != nil {
		return err
	}

	// Set defaults - Coroot uses OTLP endpoints
	if c.config.Endpoint == "" {
		c.config.Endpoint = "http://localhost:8080"
	}
	if c.config.MetricsEndpoint == "" {
		c.config.MetricsEndpoint = fmt.Sprintf("%s/v1/metrics", c.config.Endpoint)
	}
	if c.config.TracesEndpoint == "" {
		c.config.TracesEndpoint = fmt.Sprintf("%s/v1/traces", c.config.Endpoint)
	}
	if c.config.LogsEndpoint == "" {
		c.config.LogsEndpoint = fmt.Sprintf("%s/v1/logs", c.config.Endpoint)
	}
	if c.config.Timeout == 0 {
		c.config.Timeout = 30 * time.Second
	}
	if c.config.BatchSize == 0 {
		c.config.BatchSize = 1000
	}
	if c.config.FlushInterval == 0 {
		c.config.FlushInterval = 10 * time.Second
	}
	if c.config.ServiceName == "" {
		c.config.ServiceName = "tfo-agent"
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if c.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   c.config.Timeout,
	}

	c.SetInitialized(true)
	c.Logger().Info("Coroot exporter initialized",
		zap.String("endpoint", c.config.Endpoint),
		zap.String("projectId", c.config.ProjectID),
	)

	return nil
}

// Validate validates the Coroot configuration
func (c *CorootExporter) Validate() error {
	if !c.config.Enabled {
		return nil
	}
	// Coroot self-hosted may not require API key
	return nil
}

// Export exports telemetry data to Coroot
func (c *CorootExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	if len(data.Metrics) > 0 {
		result, err := c.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Traces) > 0 {
		result, err := c.ExportTraces(ctx, data.Traces)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Logs) > 0 {
		result, err := c.ExportLogs(ctx, data.Logs)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	return &totalResult, totalResult.Error
}

// ExportMetrics exports metrics to Coroot
func (c *CorootExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !c.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpMetrics := convertToOTLPMetrics(metrics, c.config.ServiceName, c.config.Tags)
	body, err := json.Marshal(otlpMetrics)
	if err != nil {
		c.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := c.sendRequest(ctx, "POST", c.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		c.RecordError(err)
		return result, err
	}

	c.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Coroot
func (c *CorootExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !c.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpTraces := convertToOTLPTraces(traces, c.config.ServiceName, c.config.Tags)
	body, err := json.Marshal(otlpTraces)
	if err != nil {
		c.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := c.sendRequest(ctx, "POST", c.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		c.RecordError(err)
		return result, err
	}

	c.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Coroot
func (c *CorootExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !c.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpLogs := convertToOTLPLogs(logs, c.config.ServiceName, c.config.Tags)
	body, err := json.Marshal(otlpLogs)
	if err != nil {
		c.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := c.sendRequest(ctx, "POST", c.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		c.RecordError(err)
		return result, err
	}

	c.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the Coroot integration
func (c *CorootExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !c.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	healthURL := fmt.Sprintf("%s/health", c.config.Endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}

	resp, err := c.httpClient.Do(req)
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("health check failed: status=%d body=%s", resp.StatusCode, string(body))
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
			Latency:   time.Since(startTime),
		}, nil
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   "Coroot API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint":  c.config.Endpoint,
			"projectId": c.config.ProjectID,
		},
	}, nil
}

// Close closes the Coroot exporter
func (c *CorootExporter) Close(ctx context.Context) error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	c.SetInitialized(false)
	c.Logger().Info("Coroot exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Coroot
func (c *CorootExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}
	if c.config.ProjectID != "" {
		req.Header.Set("X-Coroot-Project-ID", c.config.ProjectID)
	}

	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("coroot API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
