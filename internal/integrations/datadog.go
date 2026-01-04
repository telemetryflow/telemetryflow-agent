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

// DatadogConfig contains Datadog integration configuration
type DatadogConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	APIKey          string            `mapstructure:"api_key"`
	AppKey          string            `mapstructure:"app_key"`
	Site            string            `mapstructure:"site"`
	MetricsEndpoint string            `mapstructure:"metrics_endpoint"`
	LogsEndpoint    string            `mapstructure:"logs_endpoint"`
	TracesEndpoint  string            `mapstructure:"traces_endpoint"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	Compression     string            `mapstructure:"compression"`
	Tags            []string          `mapstructure:"tags"`
	ServiceName     string            `mapstructure:"service_name"`
	Environment     string            `mapstructure:"environment"`
	Version         string            `mapstructure:"version"`
	Headers         map[string]string `mapstructure:"headers"`
}

// DatadogExporter exports telemetry data to Datadog
type DatadogExporter struct {
	*BaseExporter
	config     DatadogConfig
	httpClient *http.Client
}

// Datadog API payload structures
type datadogMetricSeries struct {
	Series []datadogMetric `json:"series"`
}

type datadogMetric struct {
	Metric   string      `json:"metric"`
	Type     string      `json:"type"`
	Points   [][]float64 `json:"points"`
	Tags     []string    `json:"tags,omitempty"`
	Host     string      `json:"host,omitempty"`
	Interval int64       `json:"interval,omitempty"`
	Unit     string      `json:"unit,omitempty"`
}

type datadogLogEntry struct {
	Message    string            `json:"message"`
	Timestamp  int64             `json:"timestamp,omitempty"`
	Hostname   string            `json:"hostname,omitempty"`
	Service    string            `json:"service,omitempty"`
	Source     string            `json:"source,omitempty"`
	Status     string            `json:"status,omitempty"`
	Tags       string            `json:"ddtags,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewDatadogExporter creates a new Datadog exporter
func NewDatadogExporter(config DatadogConfig, logger *zap.Logger) *DatadogExporter {
	return &DatadogExporter{
		BaseExporter: NewBaseExporter(
			"datadog",
			"apm",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Datadog exporter
func (d *DatadogExporter) Init(ctx context.Context) error {
	if !d.config.Enabled {
		return nil
	}

	if err := d.Validate(); err != nil {
		return err
	}

	// Set defaults
	if d.config.Site == "" {
		d.config.Site = "datadoghq.com"
	}
	if d.config.MetricsEndpoint == "" {
		d.config.MetricsEndpoint = fmt.Sprintf("https://api.%s/api/v2/series", d.config.Site)
	}
	if d.config.LogsEndpoint == "" {
		d.config.LogsEndpoint = fmt.Sprintf("https://http-intake.logs.%s/api/v2/logs", d.config.Site)
	}
	if d.config.TracesEndpoint == "" {
		d.config.TracesEndpoint = fmt.Sprintf("https://trace.agent.%s/api/v0.2/traces", d.config.Site)
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
	if d.config.Compression == "" {
		d.config.Compression = "gzip"
	}

	// Create HTTP client
	d.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: d.config.Timeout,
	}

	d.SetInitialized(true)
	d.Logger().Info("Datadog exporter initialized",
		zap.String("site", d.config.Site),
		zap.String("service", d.config.ServiceName),
	)

	return nil
}

// Validate validates the Datadog configuration
func (d *DatadogExporter) Validate() error {
	if !d.config.Enabled {
		return nil
	}

	if d.config.APIKey == "" {
		return NewValidationError("datadog", "api_key", "api_key is required")
	}

	if len(d.config.APIKey) < 32 {
		return NewValidationError("datadog", "api_key", "api_key appears to be invalid (too short)")
	}

	return nil
}

// Export exports telemetry data to Datadog
func (d *DatadogExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
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

// ExportMetrics exports metrics to Datadog
func (d *DatadogExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !d.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Datadog format
	ddMetrics := make([]datadogMetric, 0, len(metrics))
	for _, m := range metrics {
		ddMetric := datadogMetric{
			Metric: m.Name,
			Type:   string(m.Type),
			Points: [][]float64{
				{float64(m.Timestamp.Unix()), m.Value},
			},
			Tags: d.buildTags(m.Tags),
			Unit: m.Unit,
		}
		if m.Interval > 0 {
			ddMetric.Interval = int64(m.Interval.Seconds())
		}
		ddMetrics = append(ddMetrics, ddMetric)
	}

	payload := datadogMetricSeries{Series: ddMetrics}
	body, err := json.Marshal(payload)
	if err != nil {
		d.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := d.sendRequest(ctx, "POST", d.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		d.RecordError(err)
		return result, err
	}

	d.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Datadog
func (d *DatadogExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !d.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Datadog APM trace format
	ddTraces := make([]map[string]interface{}, 0, len(traces))
	for _, t := range traces {
		ddTrace := map[string]interface{}{
			"trace_id":  t.TraceID,
			"span_id":   t.SpanID,
			"name":      t.OperationName,
			"service":   t.ServiceName,
			"resource":  t.OperationName,
			"start":     t.StartTime.UnixNano(),
			"duration":  t.Duration.Nanoseconds(),
			"meta":      t.Tags,
			"parent_id": t.ParentSpanID,
		}
		if t.Status == TraceStatusError {
			ddTrace["error"] = 1
		}
		ddTraces = append(ddTraces, ddTrace)
	}

	body, err := json.Marshal([][]map[string]interface{}{ddTraces})
	if err != nil {
		d.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := d.sendRequest(ctx, "PUT", d.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		d.RecordError(err)
		return result, err
	}

	d.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Datadog
func (d *DatadogExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !d.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !d.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Datadog log format
	ddLogs := make([]datadogLogEntry, 0, len(logs))
	for _, l := range logs {
		ddLog := datadogLogEntry{
			Message:    l.Message,
			Timestamp:  l.Timestamp.UnixMilli(),
			Service:    d.config.ServiceName,
			Source:     l.Source,
			Status:     string(l.Level),
			Attributes: l.Attributes,
		}
		ddLogs = append(ddLogs, ddLog)
	}

	body, err := json.Marshal(ddLogs)
	if err != nil {
		d.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := d.sendRequest(ctx, "POST", d.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		d.RecordError(err)
		return result, err
	}

	d.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the Datadog integration
func (d *DatadogExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !d.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Validate API key by making a test request
	validateURL := fmt.Sprintf("https://api.%s/api/v1/validate", d.config.Site)
	req, err := http.NewRequestWithContext(ctx, "GET", validateURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	req.Header.Set("DD-API-KEY", d.config.APIKey)
	if d.config.AppKey != "" {
		req.Header.Set("DD-APPLICATION-KEY", d.config.AppKey)
	}

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
		err := fmt.Errorf("validation failed: status=%d body=%s", resp.StatusCode, string(body))
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
		Message:   "API key validated",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"site": d.config.Site,
		},
	}, nil
}

// Close closes the Datadog exporter
func (d *DatadogExporter) Close(ctx context.Context) error {
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	d.SetInitialized(false)
	d.Logger().Info("Datadog exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Datadog
func (d *DatadogExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", d.config.APIKey)
	if d.config.AppKey != "" {
		req.Header.Set("DD-APPLICATION-KEY", d.config.AppKey)
	}

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
		err := fmt.Errorf("datadog API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// buildTags builds Datadog tags from a map
func (d *DatadogExporter) buildTags(tags map[string]string) []string {
	result := make([]string, 0, len(tags)+len(d.config.Tags)+3)

	// Add default tags
	if d.config.ServiceName != "" {
		result = append(result, fmt.Sprintf("service:%s", d.config.ServiceName))
	}
	if d.config.Environment != "" {
		result = append(result, fmt.Sprintf("env:%s", d.config.Environment))
	}
	if d.config.Version != "" {
		result = append(result, fmt.Sprintf("version:%s", d.config.Version))
	}

	// Add configured tags
	result = append(result, d.config.Tags...)

	// Add metric-specific tags
	for k, v := range tags {
		result = append(result, fmt.Sprintf("%s:%s", k, v))
	}

	return result
}
