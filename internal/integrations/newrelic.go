// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// NewRelicConfig contains New Relic integration configuration
type NewRelicConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	LicenseKey        string            `mapstructure:"license_key"`
	InsightsInsertKey string            `mapstructure:"insights_insert_key"`
	AccountID         string            `mapstructure:"account_id"`
	Region            string            `mapstructure:"region"`
	MetricsEndpoint   string            `mapstructure:"metrics_endpoint"`
	LogsEndpoint      string            `mapstructure:"logs_endpoint"`
	TracesEndpoint    string            `mapstructure:"traces_endpoint"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	BatchSize         int               `mapstructure:"batch_size"`
	FlushInterval     time.Duration     `mapstructure:"flush_interval"`
	Compression       bool              `mapstructure:"compression"`
	ServiceName       string            `mapstructure:"service_name"`
	Environment       string            `mapstructure:"environment"`
	Headers           map[string]string `mapstructure:"headers"`
}

// NewRelicExporter exports telemetry data to New Relic
type NewRelicExporter struct {
	*BaseExporter
	config     NewRelicConfig
	httpClient *http.Client
}

// New Relic API payload structures
type newRelicMetricPayload struct {
	Metrics []newRelicMetric `json:"metrics"`
}

type newRelicMetric struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Value      float64           `json:"value"`
	Timestamp  int64             `json:"timestamp"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type newRelicLogPayload struct {
	Logs []newRelicLog `json:"logs"`
}

type newRelicLog struct {
	Timestamp  int64             `json:"timestamp"`
	Message    string            `json:"message"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewNewRelicExporter creates a new New Relic exporter
func NewNewRelicExporter(config NewRelicConfig, logger *zap.Logger) *NewRelicExporter {
	return &NewRelicExporter{
		BaseExporter: NewBaseExporter(
			"newrelic",
			"apm",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the New Relic exporter
func (n *NewRelicExporter) Init(ctx context.Context) error {
	if !n.config.Enabled {
		return nil
	}

	if err := n.Validate(); err != nil {
		return err
	}

	// Set defaults based on region
	if n.config.Region == "" {
		n.config.Region = "US"
	}

	var baseDomain string
	if n.config.Region == "EU" {
		baseDomain = "eu01.nr-data.net"
	} else {
		baseDomain = "metric-api.newrelic.com"
	}

	if n.config.MetricsEndpoint == "" {
		n.config.MetricsEndpoint = fmt.Sprintf("https://%s/metric/v1", baseDomain)
	}
	if n.config.LogsEndpoint == "" {
		if n.config.Region == "EU" {
			n.config.LogsEndpoint = "https://log-api.eu.newrelic.com/log/v1"
		} else {
			n.config.LogsEndpoint = "https://log-api.newrelic.com/log/v1"
		}
	}
	if n.config.TracesEndpoint == "" {
		if n.config.Region == "EU" {
			n.config.TracesEndpoint = "https://trace-api.eu.newrelic.com/trace/v1"
		} else {
			n.config.TracesEndpoint = "https://trace-api.newrelic.com/trace/v1"
		}
	}

	if n.config.Timeout == 0 {
		n.config.Timeout = 30 * time.Second
	}
	if n.config.BatchSize == 0 {
		n.config.BatchSize = 1000
	}
	if n.config.FlushInterval == 0 {
		n.config.FlushInterval = 10 * time.Second
	}

	// Create HTTP client
	n.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: n.config.Timeout,
	}

	n.SetInitialized(true)
	n.Logger().Info("New Relic exporter initialized",
		zap.String("region", n.config.Region),
		zap.String("service", n.config.ServiceName),
	)

	return nil
}

// Validate validates the New Relic configuration
func (n *NewRelicExporter) Validate() error {
	if !n.config.Enabled {
		return nil
	}

	if n.config.LicenseKey == "" && n.config.InsightsInsertKey == "" {
		return NewValidationError("newrelic", "license_key", "license_key or insights_insert_key is required")
	}

	if n.config.LicenseKey != "" && len(n.config.LicenseKey) < 40 {
		return NewValidationError("newrelic", "license_key", "license_key appears to be invalid (too short)")
	}

	return nil
}

// Export exports telemetry data to New Relic
func (n *NewRelicExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := n.ExportMetrics(ctx, data.Metrics)
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
		result, err := n.ExportTraces(ctx, data.Traces)
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
		result, err := n.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to New Relic
func (n *NewRelicExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !n.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to New Relic format
	nrMetrics := make([]newRelicMetric, 0, len(metrics))
	for _, m := range metrics {
		attrs := make(map[string]string)
		for k, v := range m.Tags {
			attrs[k] = v
		}
		if n.config.ServiceName != "" {
			attrs["service.name"] = n.config.ServiceName
		}
		if n.config.Environment != "" {
			attrs["environment"] = n.config.Environment
		}

		nrMetric := newRelicMetric{
			Name:       m.Name,
			Type:       string(m.Type),
			Value:      m.Value,
			Timestamp:  m.Timestamp.UnixMilli(),
			Attributes: attrs,
		}
		nrMetrics = append(nrMetrics, nrMetric)
	}

	payload := []newRelicMetricPayload{{Metrics: nrMetrics}}
	body, err := json.Marshal(payload)
	if err != nil {
		n.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := n.sendRequest(ctx, n.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		n.RecordError(err)
		return result, err
	}

	n.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to New Relic
func (n *NewRelicExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !n.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to New Relic distributed tracing format
	nrSpans := make([]map[string]interface{}, 0, len(traces))
	for _, t := range traces {
		span := map[string]interface{}{
			"trace.id":    t.TraceID,
			"id":          t.SpanID,
			"name":        t.OperationName,
			"timestamp":   t.StartTime.UnixMilli(),
			"duration.ms": t.Duration.Milliseconds(),
			"attributes": map[string]interface{}{
				"service.name": t.ServiceName,
			},
		}
		if t.ParentSpanID != "" {
			span["parent.id"] = t.ParentSpanID
		}
		if t.Status == TraceStatusError {
			span["error"] = true
		}
		nrSpans = append(nrSpans, span)
	}

	payload := []map[string]interface{}{
		{"spans": nrSpans},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		n.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := n.sendRequest(ctx, n.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		n.RecordError(err)
		return result, err
	}

	n.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to New Relic
func (n *NewRelicExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !n.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to New Relic log format
	nrLogs := make([]newRelicLog, 0, len(logs))
	for _, l := range logs {
		attrs := make(map[string]string)
		for k, v := range l.Attributes {
			attrs[k] = v
		}
		attrs["level"] = string(l.Level)
		if l.Source != "" {
			attrs["source"] = l.Source
		}
		if n.config.ServiceName != "" {
			attrs["service.name"] = n.config.ServiceName
		}

		nrLog := newRelicLog{
			Timestamp:  l.Timestamp.UnixMilli(),
			Message:    l.Message,
			Attributes: attrs,
		}
		nrLogs = append(nrLogs, nrLog)
	}

	payload := []newRelicLogPayload{{Logs: nrLogs}}
	body, err := json.Marshal(payload)
	if err != nil {
		n.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := n.sendRequest(ctx, n.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		n.RecordError(err)
		return result, err
	}

	n.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the New Relic integration
func (n *NewRelicExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !n.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	// New Relic doesn't have a simple health check endpoint
	// We'll verify by checking if we can resolve the endpoint
	startTime := time.Now()

	req, err := http.NewRequestWithContext(ctx, "OPTIONS", n.config.MetricsEndpoint, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	n.setAuthHeaders(req)

	resp, err := n.httpClient.Do(req)
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
		Healthy:   true,
		Message:   "endpoint reachable",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"region": n.config.Region,
		},
	}, nil
}

// Close closes the New Relic exporter
func (n *NewRelicExporter) Close(ctx context.Context) error {
	if n.httpClient != nil {
		n.httpClient.CloseIdleConnections()
	}
	n.SetInitialized(false)
	n.Logger().Info("New Relic exporter closed")
	return nil
}

// sendRequest sends an HTTP request to New Relic
func (n *NewRelicExporter) sendRequest(ctx context.Context, url string, body []byte) (*ExportResult, error) {
	var reqBody io.Reader

	// Optionally compress the payload
	if n.config.Compression {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(body); err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		if err := gz.Close(); err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		reqBody = &buf
	} else {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	if n.config.Compression {
		req.Header.Set("Content-Encoding", "gzip")
	}

	n.setAuthHeaders(req)

	// Add custom headers
	for k, v := range n.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("new relic API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets the appropriate authentication headers
func (n *NewRelicExporter) setAuthHeaders(req *http.Request) {
	if n.config.LicenseKey != "" {
		req.Header.Set("Api-Key", n.config.LicenseKey)
	} else if n.config.InsightsInsertKey != "" {
		req.Header.Set("X-Insert-Key", n.config.InsightsInsertKey)
	}
}
