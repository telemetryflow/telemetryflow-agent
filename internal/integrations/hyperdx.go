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

// HyperDXConfig contains HyperDX/ClickStack integration configuration
type HyperDXConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	APIKey          string            `mapstructure:"api_key"`
	Endpoint        string            `mapstructure:"endpoint"`
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

// HyperDXExporter exports telemetry data to HyperDX/ClickStack
type HyperDXExporter struct {
	*BaseExporter
	config     HyperDXConfig
	httpClient *http.Client
}

// NewHyperDXExporter creates a new HyperDX exporter
func NewHyperDXExporter(config HyperDXConfig, logger *zap.Logger) *HyperDXExporter {
	return &HyperDXExporter{
		BaseExporter: NewBaseExporter(
			"hyperdx",
			"observability",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the HyperDX exporter
func (h *HyperDXExporter) Init(ctx context.Context) error {
	if !h.config.Enabled {
		return nil
	}

	if err := h.Validate(); err != nil {
		return err
	}

	// Set defaults - HyperDX uses OTLP endpoints
	if h.config.Endpoint == "" {
		h.config.Endpoint = "https://in-otel.hyperdx.io"
	}
	if h.config.MetricsEndpoint == "" {
		h.config.MetricsEndpoint = fmt.Sprintf("%s/v1/metrics", h.config.Endpoint)
	}
	if h.config.TracesEndpoint == "" {
		h.config.TracesEndpoint = fmt.Sprintf("%s/v1/traces", h.config.Endpoint)
	}
	if h.config.LogsEndpoint == "" {
		h.config.LogsEndpoint = fmt.Sprintf("%s/v1/logs", h.config.Endpoint)
	}
	if h.config.Timeout == 0 {
		h.config.Timeout = 30 * time.Second
	}
	if h.config.BatchSize == 0 {
		h.config.BatchSize = 1000
	}
	if h.config.FlushInterval == 0 {
		h.config.FlushInterval = 10 * time.Second
	}
	if h.config.ServiceName == "" {
		h.config.ServiceName = "tfo-agent"
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if h.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	h.httpClient = &http.Client{
		Transport: transport,
		Timeout:   h.config.Timeout,
	}

	h.SetInitialized(true)
	h.Logger().Info("HyperDX exporter initialized",
		zap.String("endpoint", h.config.Endpoint),
		zap.String("serviceName", h.config.ServiceName),
	)

	return nil
}

// Validate validates the HyperDX configuration
func (h *HyperDXExporter) Validate() error {
	if !h.config.Enabled {
		return nil
	}
	if h.config.APIKey == "" {
		return NewValidationError("hyperdx", "api_key", "api_key is required")
	}
	return nil
}

// Export exports telemetry data to HyperDX
func (h *HyperDXExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !h.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	if len(data.Metrics) > 0 {
		result, err := h.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Traces) > 0 {
		result, err := h.ExportTraces(ctx, data.Traces)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Logs) > 0 {
		result, err := h.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to HyperDX
func (h *HyperDXExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !h.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !h.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpMetrics := convertToOTLPMetrics(metrics, h.config.ServiceName, h.config.Tags)
	body, err := json.Marshal(otlpMetrics)
	if err != nil {
		h.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := h.sendRequest(ctx, "POST", h.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		h.RecordError(err)
		return result, err
	}

	h.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to HyperDX
func (h *HyperDXExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !h.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !h.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpTraces := convertToOTLPTraces(traces, h.config.ServiceName, h.config.Tags)
	body, err := json.Marshal(otlpTraces)
	if err != nil {
		h.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := h.sendRequest(ctx, "POST", h.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		h.RecordError(err)
		return result, err
	}

	h.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to HyperDX
func (h *HyperDXExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !h.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !h.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpLogs := convertToOTLPLogs(logs, h.config.ServiceName, h.config.Tags)
	body, err := json.Marshal(otlpLogs)
	if err != nil {
		h.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := h.sendRequest(ctx, "POST", h.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		h.RecordError(err)
		return result, err
	}

	h.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the HyperDX integration
func (h *HyperDXExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !h.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// HyperDX health check
	healthURL := fmt.Sprintf("%s/health", h.config.Endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	req.Header.Set("Authorization", h.config.APIKey)

	resp, err := h.httpClient.Do(req)
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

	// For HyperDX, we consider connection success as healthy
	return &HealthStatus{
		Healthy:   true,
		Message:   "HyperDX API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint": h.config.Endpoint,
		},
	}, nil
}

// Close closes the HyperDX exporter
func (h *HyperDXExporter) Close(ctx context.Context) error {
	if h.httpClient != nil {
		h.httpClient.CloseIdleConnections()
	}
	h.SetInitialized(false)
	h.Logger().Info("HyperDX exporter closed")
	return nil
}

// sendRequest sends an HTTP request to HyperDX
func (h *HyperDXExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", h.config.APIKey)

	for k, v := range h.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("HyperDX API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
