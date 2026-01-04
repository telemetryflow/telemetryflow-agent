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

// SplunkConfig contains Splunk HEC integration configuration
type SplunkConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	HECEndpoint   string            `mapstructure:"hec_endpoint"`
	HECToken      string            `mapstructure:"hec_token"`
	Index         string            `mapstructure:"index"`
	Source        string            `mapstructure:"source"`
	SourceType    string            `mapstructure:"source_type"`
	TLSEnabled    bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify bool              `mapstructure:"tls_skip_verify"`
	Timeout       time.Duration     `mapstructure:"timeout"`
	BatchSize     int               `mapstructure:"batch_size"`
	FlushInterval time.Duration     `mapstructure:"flush_interval"`
	Headers       map[string]string `mapstructure:"headers"`
}

// SplunkExporter exports telemetry data to Splunk HEC
type SplunkExporter struct {
	*BaseExporter
	config     SplunkConfig
	httpClient *http.Client
}

// Splunk HEC payload structure
type splunkEvent struct {
	Time       float64                `json:"time,omitempty"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	SourceType string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Event      interface{}            `json:"event"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

// NewSplunkExporter creates a new Splunk exporter
func NewSplunkExporter(config SplunkConfig, logger *zap.Logger) *SplunkExporter {
	return &SplunkExporter{
		BaseExporter: NewBaseExporter(
			"splunk",
			"siem",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Splunk exporter
func (s *SplunkExporter) Init(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}

	if err := s.Validate(); err != nil {
		return err
	}

	// Set defaults
	if s.config.Timeout == 0 {
		s.config.Timeout = 30 * time.Second
	}
	if s.config.BatchSize == 0 {
		s.config.BatchSize = 1000
	}
	if s.config.FlushInterval == 0 {
		s.config.FlushInterval = 10 * time.Second
	}
	if s.config.Source == "" {
		s.config.Source = "telemetryflow-agent"
	}
	if s.config.SourceType == "" {
		s.config.SourceType = "_json"
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if s.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in Splunk HEC deployments)
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
	s.Logger().Info("Splunk exporter initialized",
		zap.String("endpoint", s.config.HECEndpoint),
		zap.String("index", s.config.Index),
	)

	return nil
}

// Validate validates the Splunk configuration
func (s *SplunkExporter) Validate() error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.HECEndpoint == "" {
		return NewValidationError("splunk", "hec_endpoint", "hec_endpoint is required")
	}

	if s.config.HECToken == "" {
		return NewValidationError("splunk", "hec_token", "hec_token is required")
	}

	return nil
}

// Export exports telemetry data to Splunk
func (s *SplunkExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics as events
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

	// Export logs
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

// ExportMetrics exports metrics to Splunk HEC
func (s *SplunkExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert metrics to Splunk events
	var buf bytes.Buffer
	for _, m := range metrics {
		event := splunkEvent{
			Time:       float64(m.Timestamp.UnixNano()) / 1e9,
			Source:     s.config.Source,
			SourceType: "telemetryflow:metrics",
			Index:      s.config.Index,
			Event: map[string]interface{}{
				"metric_name": m.Name,
				"value":       m.Value,
				"type":        string(m.Type),
				"unit":        m.Unit,
			},
			Fields: make(map[string]interface{}),
		}
		for k, v := range m.Tags {
			event.Fields[k] = v
		}

		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	result, err := s.sendRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		s.RecordError(err)
		return result, err
	}

	s.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces is not fully supported by Splunk HEC (use Splunk APM)
func (s *SplunkExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	// Export traces as events for basic support
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	var buf bytes.Buffer
	for _, t := range traces {
		event := splunkEvent{
			Time:       float64(t.StartTime.UnixNano()) / 1e9,
			Source:     s.config.Source,
			SourceType: "telemetryflow:traces",
			Index:      s.config.Index,
			Event: map[string]interface{}{
				"trace_id":       t.TraceID,
				"span_id":        t.SpanID,
				"parent_span_id": t.ParentSpanID,
				"operation_name": t.OperationName,
				"service_name":   t.ServiceName,
				"duration_ms":    t.Duration.Milliseconds(),
				"status":         string(t.Status),
			},
			Fields: make(map[string]interface{}),
		}
		for k, v := range t.Tags {
			event.Fields[k] = v
		}

		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	result, err := s.sendRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		s.RecordError(err)
		return result, err
	}

	s.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Splunk HEC
func (s *SplunkExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	var buf bytes.Buffer
	for _, l := range logs {
		event := splunkEvent{
			Time:       float64(l.Timestamp.UnixNano()) / 1e9,
			Source:     s.config.Source,
			SourceType: s.config.SourceType,
			Index:      s.config.Index,
			Event: map[string]interface{}{
				"message": l.Message,
				"level":   string(l.Level),
				"source":  l.Source,
			},
			Fields: make(map[string]interface{}),
		}
		for k, v := range l.Attributes {
			event.Fields[k] = v
		}

		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	result, err := s.sendRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		s.RecordError(err)
		return result, err
	}

	s.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the Splunk integration
func (s *SplunkExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !s.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Send a health check event
	healthEvent := splunkEvent{
		Time:       float64(time.Now().UnixNano()) / 1e9,
		Source:     s.config.Source,
		SourceType: "telemetryflow:health",
		Event:      map[string]string{"type": "health_check"},
	}

	body, _ := json.Marshal(healthEvent)
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.HECEndpoint, bytes.NewReader(body))
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	req.Header.Set("Authorization", "Splunk "+s.config.HECToken)
	req.Header.Set("Content-Type", "application/json")

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
		Message:   "HEC endpoint healthy",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"index": s.config.Index,
		},
	}, nil
}

// Close closes the Splunk exporter
func (s *SplunkExporter) Close(ctx context.Context) error {
	if s.httpClient != nil {
		s.httpClient.CloseIdleConnections()
	}
	s.SetInitialized(false)
	s.Logger().Info("Splunk exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Splunk HEC
func (s *SplunkExporter) sendRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.HECEndpoint, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Authorization", "Splunk "+s.config.HECToken)
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
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
		err := fmt.Errorf("splunk HEC error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
