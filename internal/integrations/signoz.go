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

// SigNozConfig contains SigNoz integration configuration
type SigNozConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Endpoint        string            `mapstructure:"endpoint"`
	AccessToken     string            `mapstructure:"access_token"`
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

// SigNozExporter exports telemetry data to SigNoz
type SigNozExporter struct {
	*BaseExporter
	config     SigNozConfig
	httpClient *http.Client
}

// NewSigNozExporter creates a new SigNoz exporter
func NewSigNozExporter(config SigNozConfig, logger *zap.Logger) *SigNozExporter {
	return &SigNozExporter{
		BaseExporter: NewBaseExporter(
			"signoz",
			"observability",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the SigNoz exporter
func (s *SigNozExporter) Init(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}

	if err := s.Validate(); err != nil {
		return err
	}

	// Set defaults
	if s.config.Endpoint == "" {
		s.config.Endpoint = "http://localhost:4318"
	}
	if s.config.MetricsEndpoint == "" {
		s.config.MetricsEndpoint = fmt.Sprintf("%s/v1/metrics", s.config.Endpoint)
	}
	if s.config.TracesEndpoint == "" {
		s.config.TracesEndpoint = fmt.Sprintf("%s/v1/traces", s.config.Endpoint)
	}
	if s.config.LogsEndpoint == "" {
		s.config.LogsEndpoint = fmt.Sprintf("%s/v1/logs", s.config.Endpoint)
	}
	if s.config.Timeout == 0 {
		s.config.Timeout = 30 * time.Second
	}
	if s.config.BatchSize == 0 {
		s.config.BatchSize = 1000
	}
	if s.config.FlushInterval == 0 {
		s.config.FlushInterval = 10 * time.Second
	}
	if s.config.ServiceName == "" {
		s.config.ServiceName = "tfo-agent"
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if s.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	s.httpClient = &http.Client{
		Transport: transport,
		Timeout:   s.config.Timeout,
	}

	s.SetInitialized(true)
	s.Logger().Info("SigNoz exporter initialized",
		zap.String("endpoint", s.config.Endpoint),
		zap.String("serviceName", s.config.ServiceName),
	)

	return nil
}

// Validate validates the SigNoz configuration
func (s *SigNozExporter) Validate() error {
	if !s.config.Enabled {
		return nil
	}
	// SigNoz can work without access token for self-hosted
	return nil
}

// Export exports telemetry data to SigNoz
func (s *SigNozExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	if len(data.Metrics) > 0 {
		result, err := s.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Traces) > 0 {
		result, err := s.ExportTraces(ctx, data.Traces)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Logs) > 0 {
		result, err := s.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to SigNoz using OTLP HTTP
func (s *SigNozExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP format
	otlpMetrics := convertToOTLPMetrics(metrics, s.config.ServiceName, s.config.Tags)
	body, err := json.Marshal(otlpMetrics)
	if err != nil {
		s.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := s.sendRequest(ctx, "POST", s.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		s.RecordError(err)
		return result, err
	}

	s.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to SigNoz using OTLP HTTP
func (s *SigNozExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP format
	otlpTraces := convertToOTLPTraces(traces, s.config.ServiceName, s.config.Tags)
	body, err := json.Marshal(otlpTraces)
	if err != nil {
		s.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := s.sendRequest(ctx, "POST", s.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		s.RecordError(err)
		return result, err
	}

	s.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to SigNoz using OTLP HTTP
func (s *SigNozExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP format
	otlpLogs := convertToOTLPLogs(logs, s.config.ServiceName, s.config.Tags)
	body, err := json.Marshal(otlpLogs)
	if err != nil {
		s.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := s.sendRequest(ctx, "POST", s.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		s.RecordError(err)
		return result, err
	}

	s.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the SigNoz integration
func (s *SigNozExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !s.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// SigNoz health check
	healthURL := fmt.Sprintf("%s/api/v1/health", s.config.Endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	if s.config.AccessToken != "" {
		req.Header.Set("SIGNOZ-ACCESS-TOKEN", s.config.AccessToken)
	}

	resp, err := s.httpClient.Do(req)
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
		Message:   "SigNoz API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint": s.config.Endpoint,
		},
	}, nil
}

// Close closes the SigNoz exporter
func (s *SigNozExporter) Close(ctx context.Context) error {
	if s.httpClient != nil {
		s.httpClient.CloseIdleConnections()
	}
	s.SetInitialized(false)
	s.Logger().Info("SigNoz exporter closed")
	return nil
}

// sendRequest sends an HTTP request to SigNoz
func (s *SigNozExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.AccessToken != "" {
		req.Header.Set("SIGNOZ-ACCESS-TOKEN", s.config.AccessToken)
	}

	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("SigNoz API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
