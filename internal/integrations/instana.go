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

// InstanaConfig contains IBM Instana integration configuration
type InstanaConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	AgentKey        string            `mapstructure:"agent_key"`
	EndpointURL     string            `mapstructure:"endpoint_url"`
	Zone            string            `mapstructure:"zone"`
	MetricsEndpoint string            `mapstructure:"metrics_endpoint"`
	TracesEndpoint  string            `mapstructure:"traces_endpoint"`
	EventsEndpoint  string            `mapstructure:"events_endpoint"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	ServiceName     string            `mapstructure:"service_name"`
	HostID          string            `mapstructure:"host_id"`
	Tags            map[string]string `mapstructure:"tags"`
	Headers         map[string]string `mapstructure:"headers"`
}

// InstanaExporter exports telemetry data to IBM Instana
type InstanaExporter struct {
	*BaseExporter
	config     InstanaConfig
	httpClient *http.Client
}

// Instana API payload structures
type instanaMetric struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Timestamp int64             `json:"timestamp"`
	Host      string            `json:"host,omitempty"`
	Plugin    string            `json:"plugin,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

type instanaSpan struct {
	TraceID     string                 `json:"t"`
	SpanID      string                 `json:"s"`
	ParentID    string                 `json:"p,omitempty"`
	Name        string                 `json:"n"`
	Timestamp   int64                  `json:"ts"`
	Duration    int64                  `json:"d"`
	Kind        int                    `json:"k"` // 1=entry, 2=exit, 3=intermediate
	Error       bool                   `json:"error,omitempty"`
	EC          int                    `json:"ec,omitempty"` // error count
	Data        map[string]interface{} `json:"data,omitempty"`
	ServiceName string                 `json:"f,omitempty"`
}

type instanaEvent struct {
	Title     string            `json:"title"`
	Text      string            `json:"text"`
	Severity  int               `json:"severity"` // -1=change, 5=warning, 10=critical
	Timestamp int64             `json:"timestamp"`
	Duration  int64             `json:"duration,omitempty"`
	Host      string            `json:"host,omitempty"`
	Service   string            `json:"service,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// NewInstanaExporter creates a new IBM Instana exporter
func NewInstanaExporter(config InstanaConfig, logger *zap.Logger) *InstanaExporter {
	return &InstanaExporter{
		BaseExporter: NewBaseExporter(
			"instana",
			"apm",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Instana exporter
func (i *InstanaExporter) Init(ctx context.Context) error {
	if !i.config.Enabled {
		return nil
	}

	if err := i.Validate(); err != nil {
		return err
	}

	// Set defaults
	if i.config.EndpointURL == "" {
		i.config.EndpointURL = "https://serverless-us-west-2.instana.io"
	}
	if i.config.MetricsEndpoint == "" {
		i.config.MetricsEndpoint = fmt.Sprintf("%s/metrics", i.config.EndpointURL)
	}
	if i.config.TracesEndpoint == "" {
		i.config.TracesEndpoint = fmt.Sprintf("%s/traces", i.config.EndpointURL)
	}
	if i.config.EventsEndpoint == "" {
		i.config.EventsEndpoint = fmt.Sprintf("%s/events", i.config.EndpointURL)
	}
	if i.config.Timeout == 0 {
		i.config.Timeout = 30 * time.Second
	}
	if i.config.BatchSize == 0 {
		i.config.BatchSize = 1000
	}
	if i.config.FlushInterval == 0 {
		i.config.FlushInterval = 10 * time.Second
	}
	if i.config.ServiceName == "" {
		i.config.ServiceName = "telemetryflow-agent"
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if i.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in on-premise IBM Instana deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	i.httpClient = &http.Client{
		Transport: transport,
		Timeout:   i.config.Timeout,
	}

	i.SetInitialized(true)
	i.Logger().Info("IBM Instana exporter initialized",
		zap.String("endpointUrl", i.config.EndpointURL),
		zap.String("zone", i.config.Zone),
	)

	return nil
}

// Validate validates the Instana configuration
func (i *InstanaConfig) Validate() error {
	if i.AgentKey == "" {
		return NewValidationError("instana", "agent_key", "agent_key is required")
	}

	return nil
}

// Validate validates the Instana configuration (exporter method)
func (i *InstanaExporter) Validate() error {
	if !i.config.Enabled {
		return nil
	}

	return i.config.Validate()
}

// Export exports telemetry data to Instana
func (i *InstanaExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := i.ExportMetrics(ctx, data.Metrics)
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
		result, err := i.ExportTraces(ctx, data.Traces)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	// Export logs as events
	if len(data.Logs) > 0 {
		result, err := i.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to Instana
func (i *InstanaExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !i.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Instana format
	instanaMetrics := make([]instanaMetric, 0, len(metrics))
	for _, m := range metrics {
		tags := make(map[string]string)
		for k, v := range m.Tags {
			tags[k] = v
		}
		for k, v := range i.config.Tags {
			tags[k] = v
		}

		instanaMetrics = append(instanaMetrics, instanaMetric{
			Name:      m.Name,
			Value:     m.Value,
			Timestamp: m.Timestamp.UnixMilli(),
			Host:      i.config.HostID,
			Plugin:    "telemetryflow",
			Tags:      tags,
		})
	}

	body, err := json.Marshal(map[string]interface{}{
		"metrics": instanaMetrics,
	})
	if err != nil {
		i.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := i.sendRequest(ctx, "POST", i.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		i.RecordError(err)
		return result, err
	}

	i.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Instana
func (i *InstanaExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !i.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Instana span format
	spans := make([]instanaSpan, 0, len(traces))
	for _, t := range traces {
		span := instanaSpan{
			TraceID:     t.TraceID,
			SpanID:      t.SpanID,
			ParentID:    t.ParentSpanID,
			Name:        t.OperationName,
			Timestamp:   t.StartTime.UnixMilli(),
			Duration:    t.Duration.Milliseconds(),
			Kind:        1, // entry span
			ServiceName: t.ServiceName,
			Data: map[string]interface{}{
				"sdk": map[string]interface{}{
					"name": "telemetryflow",
					"type": "trace",
				},
			},
		}

		if t.Status == TraceStatusError {
			span.Error = true
			span.EC = 1
		}

		// Add tags to data
		for k, v := range t.Tags {
			span.Data[k] = v
		}

		spans = append(spans, span)
	}

	body, err := json.Marshal(map[string]interface{}{
		"spans": spans,
	})
	if err != nil {
		i.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := i.sendRequest(ctx, "POST", i.config.TracesEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		i.RecordError(err)
		return result, err
	}

	i.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Instana as events
func (i *InstanaExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !i.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert logs to Instana events
	events := make([]instanaEvent, 0, len(logs))
	for _, l := range logs {
		severity := -1 // change
		switch l.Level {
		case LogLevelError, LogLevelFatal:
			severity = 10 // critical
		case LogLevelWarn:
			severity = 5 // warning
		}

		event := instanaEvent{
			Title:     fmt.Sprintf("[%s] %s", l.Level, l.Source),
			Text:      l.Message,
			Severity:  severity,
			Timestamp: l.Timestamp.UnixMilli(),
			Host:      i.config.HostID,
			Service:   i.config.ServiceName,
			Tags:      l.Attributes,
		}
		events = append(events, event)
	}

	body, err := json.Marshal(map[string]interface{}{
		"events": events,
	})
	if err != nil {
		i.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := i.sendRequest(ctx, "POST", i.config.EventsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		i.RecordError(err)
		return result, err
	}

	i.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the Instana integration
func (i *InstanaExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !i.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check API availability
	healthURL := fmt.Sprintf("%s/api/instana/health", i.config.EndpointURL)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	req.Header.Set("X-INSTANA-KEY", i.config.AgentKey)

	resp, err := i.httpClient.Do(req)
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
		Message:   "IBM Instana API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"zone": i.config.Zone,
		},
	}, nil
}

// Close closes the Instana exporter
func (i *InstanaExporter) Close(ctx context.Context) error {
	if i.httpClient != nil {
		i.httpClient.CloseIdleConnections()
	}
	i.SetInitialized(false)
	i.Logger().Info("IBM Instana exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Instana
func (i *InstanaExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-INSTANA-KEY", i.config.AgentKey)
	if i.config.Zone != "" {
		req.Header.Set("X-INSTANA-ZONE", i.config.Zone)
	}

	// Add custom headers
	for k, v := range i.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := i.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("instana API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
