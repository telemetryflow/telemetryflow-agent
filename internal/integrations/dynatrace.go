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

// DynatraceConfig contains Dynatrace integration configuration
type DynatraceConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	APIToken        string            `mapstructure:"api_token"`
	EnvironmentID   string            `mapstructure:"environment_id"`
	EnvironmentURL  string            `mapstructure:"environment_url"`
	MetricsEndpoint string            `mapstructure:"metrics_endpoint"`
	LogsEndpoint    string            `mapstructure:"logs_endpoint"`
	TracesEndpoint  string            `mapstructure:"traces_endpoint"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	EntitySelector  string            `mapstructure:"entity_selector"`
	Tags            map[string]string `mapstructure:"tags"`
	Headers         map[string]string `mapstructure:"headers"`
}

// DynatraceExporter exports telemetry data to Dynatrace
type DynatraceExporter struct {
	*BaseExporter
	config     DynatraceConfig
	httpClient *http.Client
}

// Dynatrace API payload structures
type dynatraceLogEntry struct {
	Content     string            `json:"content"`
	Timestamp   string            `json:"timestamp,omitempty"`
	LogSource   string            `json:"log.source,omitempty"`
	LogLevel    string            `json:"loglevel,omitempty"`
	HostName    string            `json:"host.name,omitempty"`
	ServiceName string            `json:"service.name,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// NewDynatraceExporter creates a new Dynatrace exporter
func NewDynatraceExporter(config DynatraceConfig, logger *zap.Logger) *DynatraceExporter {
	return &DynatraceExporter{
		BaseExporter: NewBaseExporter(
			"dynatrace",
			"apm",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Dynatrace exporter
func (d *DynatraceExporter) Init(ctx context.Context) error {
	if !d.config.Enabled {
		return nil
	}

	if err := d.Validate(); err != nil {
		return err
	}

	// Set defaults
	if d.config.EnvironmentURL == "" && d.config.EnvironmentID != "" {
		d.config.EnvironmentURL = fmt.Sprintf("https://%s.live.dynatrace.com", d.config.EnvironmentID)
	}
	if d.config.MetricsEndpoint == "" {
		d.config.MetricsEndpoint = fmt.Sprintf("%s/api/v2/metrics/ingest", d.config.EnvironmentURL)
	}
	if d.config.LogsEndpoint == "" {
		d.config.LogsEndpoint = fmt.Sprintf("%s/api/v2/logs/ingest", d.config.EnvironmentURL)
	}
	if d.config.TracesEndpoint == "" {
		d.config.TracesEndpoint = fmt.Sprintf("%s/api/v2/otlp/v1/traces", d.config.EnvironmentURL)
	}
	if d.config.Timeout == 0 {
		d.config.Timeout = 30 * time.Second
	}
	if d.config.BatchSize == 0 {
		d.config.BatchSize = 1000
	}
	if d.config.FlushInterval == 0 {
		d.config.FlushInterval = 10 * time.Second
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if d.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in Dynatrace Managed deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	d.httpClient = &http.Client{
		Transport: transport,
		Timeout:   d.config.Timeout,
	}

	d.SetInitialized(true)
	d.Logger().Info("Dynatrace exporter initialized",
		zap.String("environmentUrl", d.config.EnvironmentURL),
		zap.String("environmentId", d.config.EnvironmentID),
	)

	return nil
}

// Validate validates the Dynatrace configuration
func (d *DynatraceExporter) Validate() error {
	if !d.config.Enabled {
		return nil
	}

	if d.config.APIToken == "" {
		return NewValidationError("dynatrace", "api_token", "api_token is required")
	}

	if d.config.EnvironmentURL == "" && d.config.EnvironmentID == "" {
		return NewValidationError("dynatrace", "environment", "environment_url or environment_id is required")
	}

	return nil
}

// Export exports telemetry data to Dynatrace
func (d *DynatraceExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := d.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	// Export traces
	if len(data.Traces) > 0 {
		result, err := d.ExportTraces(ctx, data.Traces)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	// Export logs
	if len(data.Logs) > 0 {
		result, err := d.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to Dynatrace using MINT protocol
func (d *DynatraceExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !d.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Dynatrace MINT format (line protocol)
	var buf bytes.Buffer
	for _, m := range metrics {
		// Format: metric.key,dimension=value gauge,123.45 timestamp
		buf.WriteString(m.Name)

		// Add dimensions from tags
		for k, v := range m.Tags {
			buf.WriteString(fmt.Sprintf(",%s=%s", k, v))
		}
		for k, v := range d.config.Tags {
			buf.WriteString(fmt.Sprintf(",%s=%s", k, v))
		}

		buf.WriteString(fmt.Sprintf(" gauge,%f %d\n", m.Value, m.Timestamp.UnixMilli()))
	}

	result, err := d.sendRequest(ctx, "POST", d.config.MetricsEndpoint, buf.Bytes(), "text/plain; charset=utf-8")
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		d.RecordError(err)
		return result, err
	}

	d.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Dynatrace
func (d *DynatraceExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !d.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP-compatible format for Dynatrace
	dtTraces := make([]map[string]interface{}, 0, len(traces))
	for _, t := range traces {
		dtTrace := map[string]interface{}{
			"traceId":           t.TraceID,
			"spanId":            t.SpanID,
			"parentSpanId":      t.ParentSpanID,
			"name":              t.OperationName,
			"serviceName":       t.ServiceName,
			"startTimeUnixNano": t.StartTime.UnixNano(),
			"endTimeUnixNano":   t.StartTime.Add(t.Duration).UnixNano(),
			"attributes":        t.Tags,
		}
		if t.Status == TraceStatusError {
			dtTrace["status"] = map[string]interface{}{"code": 2}
		}
		dtTraces = append(dtTraces, dtTrace)
	}

	body, err := json.Marshal(map[string]interface{}{
		"resourceSpans": []map[string]interface{}{
			{
				"scopeSpans": []map[string]interface{}{
					{"spans": dtTraces},
				},
			},
		},
	})
	if err != nil {
		d.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := d.sendRequest(ctx, "POST", d.config.TracesEndpoint, body, "application/json")
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		d.RecordError(err)
		return result, err
	}

	d.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Dynatrace
func (d *DynatraceExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !d.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Dynatrace log format
	dtLogs := make([]dynatraceLogEntry, 0, len(logs))
	for _, l := range logs {
		dtLog := dynatraceLogEntry{
			Content:    l.Message,
			Timestamp:  l.Timestamp.Format(time.RFC3339Nano),
			LogSource:  l.Source,
			LogLevel:   string(l.Level),
			Attributes: l.Attributes,
		}
		dtLogs = append(dtLogs, dtLog)
	}

	body, err := json.Marshal(dtLogs)
	if err != nil {
		d.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := d.sendRequest(ctx, "POST", d.config.LogsEndpoint, body, "application/json")
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		d.RecordError(err)
		return result, err
	}

	d.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the Dynatrace integration
func (d *DynatraceExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !d.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Validate API token by checking cluster version
	healthURL := fmt.Sprintf("%s/api/v1/config/clusterversion", d.config.EnvironmentURL)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	req.Header.Set("Authorization", "Api-Token "+d.config.APIToken)

	resp, err := d.httpClient.Do(req)
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
		Message:   "Dynatrace API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"environmentId": d.config.EnvironmentID,
		},
	}, nil
}

// Close closes the Dynatrace exporter
func (d *DynatraceExporter) Close(ctx context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	d.SetInitialized(false)
	d.Logger().Info("Dynatrace exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Dynatrace
func (d *DynatraceExporter) sendRequest(ctx context.Context, method, url string, body []byte, contentType string) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Api-Token "+d.config.APIToken)

	// Add custom headers
	for k, v := range d.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("dynatrace API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
