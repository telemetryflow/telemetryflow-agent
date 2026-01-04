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

// AlloyConfig contains Grafana Alloy integration configuration
type AlloyConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Endpoint        string            `mapstructure:"endpoint"`
	MetricsEndpoint string            `mapstructure:"metrics_endpoint"`
	LogsEndpoint    string            `mapstructure:"logs_endpoint"`
	TracesEndpoint  string            `mapstructure:"traces_endpoint"`
	TenantID        string            `mapstructure:"tenant_id"`
	Username        string            `mapstructure:"username"`
	Password        string            `mapstructure:"password"`
	BearerToken     string            `mapstructure:"bearer_token"`
	TLSEnabled      bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	Labels          map[string]string `mapstructure:"labels"`
	Headers         map[string]string `mapstructure:"headers"`
	ExternalLabels  map[string]string `mapstructure:"external_labels"`
}

// AlloyExporter exports telemetry data to Grafana Alloy
type AlloyExporter struct {
	*BaseExporter
	config     AlloyConfig
	httpClient *http.Client
}

// NewAlloyExporter creates a new Grafana Alloy exporter
func NewAlloyExporter(config AlloyConfig, logger *zap.Logger) *AlloyExporter {
	return &AlloyExporter{
		BaseExporter: NewBaseExporter(
			"alloy",
			"collector",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Alloy exporter
func (a *AlloyExporter) Init(ctx context.Context) error {
	if !a.config.Enabled {
		return nil
	}

	if err := a.Validate(); err != nil {
		return err
	}

	// Set defaults
	if a.config.Timeout == 0 {
		a.config.Timeout = 30 * time.Second
	}
	if a.config.BatchSize == 0 {
		a.config.BatchSize = 1000
	}
	if a.config.FlushInterval == 0 {
		a.config.FlushInterval = 10 * time.Second
	}

	// Set endpoint defaults (Alloy uses OTLP by default)
	baseEndpoint := a.config.Endpoint
	if a.config.MetricsEndpoint == "" {
		a.config.MetricsEndpoint = baseEndpoint + "/v1/metrics"
	}
	if a.config.LogsEndpoint == "" {
		a.config.LogsEndpoint = baseEndpoint + "/v1/logs"
	}
	if a.config.TracesEndpoint == "" {
		a.config.TracesEndpoint = baseEndpoint + "/v1/traces"
	}

	// Create HTTP client
	a.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: a.config.Timeout,
	}

	a.SetInitialized(true)
	a.Logger().Info("Grafana Alloy exporter initialized",
		zap.String("endpoint", a.config.Endpoint),
		zap.String("tenantId", a.config.TenantID),
	)

	return nil
}

// Validate validates the Alloy configuration
func (a *AlloyExporter) Validate() error {
	if !a.config.Enabled {
		return nil
	}

	if a.config.Endpoint == "" {
		return NewValidationError("alloy", "endpoint", "endpoint is required")
	}

	return nil
}

// Export exports telemetry data to Alloy
func (a *AlloyExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := a.ExportMetrics(ctx, data.Metrics)
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
		result, err := a.ExportTraces(ctx, data.Traces)
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
		result, err := a.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to Alloy (OTLP format)
func (a *AlloyExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP-like JSON format
	otlpMetrics := a.metricsToOTLP(metrics)
	body, err := json.Marshal(otlpMetrics)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := a.sendRequest(ctx, a.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Alloy (OTLP format)
func (a *AlloyExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP-like JSON format
	otlpTraces := a.tracesToOTLP(traces)
	body, err := json.Marshal(otlpTraces)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := a.sendRequest(ctx, a.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Alloy (OTLP format)
func (a *AlloyExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to OTLP-like JSON format
	otlpLogs := a.logsToOTLP(logs)
	body, err := json.Marshal(otlpLogs)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := a.sendRequest(ctx, a.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of Alloy
func (a *AlloyExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !a.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check Alloy health endpoint
	healthURL := a.config.Endpoint + "/-/healthy"
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	a.setAuthHeaders(req)

	resp, err := a.httpClient.Do(req)
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
		Details: map[string]interface{}{
			"tenant_id": a.config.TenantID,
		},
	}, nil
}

// Close closes the Alloy exporter
func (a *AlloyExporter) Close(ctx context.Context) error {
	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}
	a.SetInitialized(false)
	a.Logger().Info("Grafana Alloy exporter closed")
	return nil
}

// sendRequest sends a request to Alloy
func (a *AlloyExporter) sendRequest(ctx context.Context, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	a.setAuthHeaders(req)

	// Add custom headers
	for k, v := range a.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("alloy error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets authentication headers
func (a *AlloyExporter) setAuthHeaders(req *http.Request) {
	if a.config.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", a.config.TenantID)
	}
	if a.config.Username != "" && a.config.Password != "" {
		req.SetBasicAuth(a.config.Username, a.config.Password)
	} else if a.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.config.BearerToken)
	}
}

// metricsToOTLP converts metrics to OTLP JSON format
func (a *AlloyExporter) metricsToOTLP(metrics []Metric) map[string]interface{} {
	dataPoints := make([]map[string]interface{}, 0, len(metrics))

	for _, m := range metrics {
		attrs := make([]map[string]interface{}, 0)
		for k, v := range m.Tags {
			attrs = append(attrs, map[string]interface{}{
				"key":   k,
				"value": map[string]string{"stringValue": v},
			})
		}
		// Add external labels
		for k, v := range a.config.ExternalLabels {
			attrs = append(attrs, map[string]interface{}{
				"key":   k,
				"value": map[string]string{"stringValue": v},
			})
		}

		dp := map[string]interface{}{
			"attributes":   attrs,
			"timeUnixNano": fmt.Sprintf("%d", m.Timestamp.UnixNano()),
			"asDouble":     m.Value,
		}
		dataPoints = append(dataPoints, dp)
	}

	return map[string]interface{}{
		"resourceMetrics": []map[string]interface{}{
			{
				"scopeMetrics": []map[string]interface{}{
					{
						"metrics": []map[string]interface{}{
							{
								"name": "telemetryflow.metrics",
								"gauge": map[string]interface{}{
									"dataPoints": dataPoints,
								},
							},
						},
					},
				},
			},
		},
	}
}

// tracesToOTLP converts traces to OTLP JSON format
func (a *AlloyExporter) tracesToOTLP(traces []Trace) map[string]interface{} {
	spans := make([]map[string]interface{}, 0, len(traces))

	for _, t := range traces {
		attrs := make([]map[string]interface{}, 0)
		for k, v := range t.Tags {
			attrs = append(attrs, map[string]interface{}{
				"key":   k,
				"value": map[string]string{"stringValue": v},
			})
		}

		span := map[string]interface{}{
			"traceId":           t.TraceID,
			"spanId":            t.SpanID,
			"parentSpanId":      t.ParentSpanID,
			"name":              t.OperationName,
			"startTimeUnixNano": fmt.Sprintf("%d", t.StartTime.UnixNano()),
			"endTimeUnixNano":   fmt.Sprintf("%d", t.StartTime.Add(t.Duration).UnixNano()),
			"attributes":        attrs,
		}

		if t.Status == TraceStatusError {
			span["status"] = map[string]interface{}{
				"code": 2, // ERROR
			}
		}

		spans = append(spans, span)
	}

	return map[string]interface{}{
		"resourceSpans": []map[string]interface{}{
			{
				"scopeSpans": []map[string]interface{}{
					{
						"spans": spans,
					},
				},
			},
		},
	}
}

// logsToOTLP converts logs to OTLP JSON format
func (a *AlloyExporter) logsToOTLP(logs []LogEntry) map[string]interface{} {
	logRecords := make([]map[string]interface{}, 0, len(logs))

	for _, l := range logs {
		attrs := make([]map[string]interface{}, 0)
		for k, v := range l.Attributes {
			attrs = append(attrs, map[string]interface{}{
				"key":   k,
				"value": map[string]string{"stringValue": v},
			})
		}
		// Add labels
		for k, v := range a.config.Labels {
			attrs = append(attrs, map[string]interface{}{
				"key":   k,
				"value": map[string]string{"stringValue": v},
			})
		}

		record := map[string]interface{}{
			"timeUnixNano": fmt.Sprintf("%d", l.Timestamp.UnixNano()),
			"severityText": string(l.Level),
			"body":         map[string]string{"stringValue": l.Message},
			"attributes":   attrs,
		}

		if l.TraceID != "" {
			record["traceId"] = l.TraceID
		}
		if l.SpanID != "" {
			record["spanId"] = l.SpanID
		}

		logRecords = append(logRecords, record)
	}

	return map[string]interface{}{
		"resourceLogs": []map[string]interface{}{
			{
				"scopeLogs": []map[string]interface{}{
					{
						"logRecords": logRecords,
					},
				},
			},
		},
	}
}
