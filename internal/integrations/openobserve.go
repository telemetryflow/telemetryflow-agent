// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// OpenObserveConfig contains OpenObserve integration configuration
type OpenObserveConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Endpoint        string            `mapstructure:"endpoint"`
	Username        string            `mapstructure:"username"`
	Password        string            `mapstructure:"password"`
	Organization    string            `mapstructure:"organization"`
	StreamName      string            `mapstructure:"stream_name"`
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

// OpenObserveExporter exports telemetry data to OpenObserve
type OpenObserveExporter struct {
	*BaseExporter
	config     OpenObserveConfig
	httpClient *http.Client
	authHeader string
}

// NewOpenObserveExporter creates a new OpenObserve exporter
func NewOpenObserveExporter(config OpenObserveConfig, logger *zap.Logger) *OpenObserveExporter {
	return &OpenObserveExporter{
		BaseExporter: NewBaseExporter(
			"openobserve",
			"observability",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the OpenObserve exporter
func (o *OpenObserveExporter) Init(ctx context.Context) error {
	if !o.config.Enabled {
		return nil
	}

	if err := o.Validate(); err != nil {
		return err
	}

	// Set defaults
	if o.config.Endpoint == "" {
		o.config.Endpoint = "http://localhost:5080"
	}
	if o.config.Organization == "" {
		o.config.Organization = "default"
	}
	if o.config.StreamName == "" {
		o.config.StreamName = "default"
	}
	if o.config.MetricsEndpoint == "" {
		o.config.MetricsEndpoint = fmt.Sprintf("%s/api/%s/v1/metrics", o.config.Endpoint, o.config.Organization)
	}
	if o.config.TracesEndpoint == "" {
		o.config.TracesEndpoint = fmt.Sprintf("%s/api/%s/v1/traces", o.config.Endpoint, o.config.Organization)
	}
	if o.config.LogsEndpoint == "" {
		o.config.LogsEndpoint = fmt.Sprintf("%s/api/%s/%s/_json", o.config.Endpoint, o.config.Organization, o.config.StreamName)
	}
	if o.config.Timeout == 0 {
		o.config.Timeout = 30 * time.Second
	}
	if o.config.BatchSize == 0 {
		o.config.BatchSize = 1000
	}
	if o.config.FlushInterval == 0 {
		o.config.FlushInterval = 10 * time.Second
	}
	if o.config.ServiceName == "" {
		o.config.ServiceName = "tfo-agent"
	}

	// Create basic auth header
	if o.config.Username != "" && o.config.Password != "" {
		auth := o.config.Username + ":" + o.config.Password
		o.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if o.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	o.httpClient = &http.Client{
		Transport: transport,
		Timeout:   o.config.Timeout,
	}

	o.SetInitialized(true)
	o.Logger().Info("OpenObserve exporter initialized",
		zap.String("endpoint", o.config.Endpoint),
		zap.String("organization", o.config.Organization),
	)

	return nil
}

// Validate validates the OpenObserve configuration
func (o *OpenObserveExporter) Validate() error {
	if !o.config.Enabled {
		return nil
	}
	if o.config.Username == "" {
		return NewValidationError("openobserve", "username", "username is required")
	}
	if o.config.Password == "" {
		return NewValidationError("openobserve", "password", "password is required")
	}
	return nil
}

// Export exports telemetry data to OpenObserve
func (o *OpenObserveExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !o.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	if len(data.Metrics) > 0 {
		result, err := o.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Traces) > 0 {
		result, err := o.ExportTraces(ctx, data.Traces)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	if len(data.Logs) > 0 {
		result, err := o.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to OpenObserve
func (o *OpenObserveExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !o.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !o.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// OpenObserve accepts OTLP format
	otlpMetrics := convertToOTLPMetrics(metrics, o.config.ServiceName, o.config.Tags)
	body, err := json.Marshal(otlpMetrics)
	if err != nil {
		o.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := o.sendRequest(ctx, "POST", o.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		o.RecordError(err)
		return result, err
	}

	o.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to OpenObserve
func (o *OpenObserveExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !o.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !o.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	otlpTraces := convertToOTLPTraces(traces, o.config.ServiceName, o.config.Tags)
	body, err := json.Marshal(otlpTraces)
	if err != nil {
		o.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := o.sendRequest(ctx, "POST", o.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		o.RecordError(err)
		return result, err
	}

	o.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to OpenObserve (JSON bulk API)
func (o *OpenObserveExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !o.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !o.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OpenObserve JSON format
	ooLogs := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		logEntry := map[string]interface{}{
			"_timestamp": l.Timestamp.UnixMicro(),
			"level":      string(l.Level),
			"message":    l.Message,
			"source":     l.Source,
			"service":    o.config.ServiceName,
		}
		for k, v := range l.Attributes {
			logEntry[k] = v
		}
		for k, v := range o.config.Tags {
			logEntry[k] = v
		}
		ooLogs = append(ooLogs, logEntry)
	}

	body, err := json.Marshal(ooLogs)
	if err != nil {
		o.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := o.sendRequest(ctx, "POST", o.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		o.RecordError(err)
		return result, err
	}

	o.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the OpenObserve integration
func (o *OpenObserveExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !o.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	healthURL := fmt.Sprintf("%s/healthz", o.config.Endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	if o.authHeader != "" {
		req.Header.Set("Authorization", o.authHeader)
	}

	resp, err := o.httpClient.Do(req)
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
		Message:   "OpenObserve API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint":     o.config.Endpoint,
			"organization": o.config.Organization,
		},
	}, nil
}

// Close closes the OpenObserve exporter
func (o *OpenObserveExporter) Close(ctx context.Context) error {
	if o.httpClient != nil {
		o.httpClient.CloseIdleConnections()
	}
	o.SetInitialized(false)
	o.Logger().Info("OpenObserve exporter closed")
	return nil
}

// sendRequest sends an HTTP request to OpenObserve
func (o *OpenObserveExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	if o.authHeader != "" {
		req.Header.Set("Authorization", o.authHeader)
	}

	for k, v := range o.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OpenObserve API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
