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

// ManageEngineConfig contains ManageEngine integration configuration
type ManageEngineConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	APIKey          string            `mapstructure:"api_key"`
	BaseURL         string            `mapstructure:"base_url"`
	AccountID       string            `mapstructure:"account_id"`
	Product         string            `mapstructure:"product"` // opmanager, applications_manager, site24x7
	MetricsEndpoint string            `mapstructure:"metrics_endpoint"`
	AlertsEndpoint  string            `mapstructure:"alerts_endpoint"`
	LogsEndpoint    string            `mapstructure:"logs_endpoint"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	MonitorGroup    string            `mapstructure:"monitor_group"`
	Tags            map[string]string `mapstructure:"tags"`
	Headers         map[string]string `mapstructure:"headers"`
}

// ManageEngineExporter exports telemetry data to ManageEngine products
type ManageEngineExporter struct {
	*BaseExporter
	config     ManageEngineConfig
	httpClient *http.Client
}

// ManageEngine API payload structures
type manageEngineMetric struct {
	MonitorName  string                 `json:"monitor_name"`
	DisplayName  string                 `json:"display_name"`
	Type         string                 `json:"type"`
	Value        float64                `json:"value"`
	Unit         string                 `json:"unit,omitempty"`
	Timestamp    int64                  `json:"timestamp"`
	MonitorGroup string                 `json:"monitor_group,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

type manageEngineAlert struct {
	Message     string            `json:"message"`
	Severity    string            `json:"severity"` // Critical, Major, Minor, Warning, Info
	Source      string            `json:"source"`
	Timestamp   int64             `json:"timestamp"`
	MonitorName string            `json:"monitor_name,omitempty"`
	Entity      string            `json:"entity,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type manageEngineLogEntry struct {
	Message    string            `json:"message"`
	LogLevel   string            `json:"log_level"`
	Source     string            `json:"source"`
	Timestamp  int64             `json:"timestamp"`
	Host       string            `json:"host,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewManageEngineExporter creates a new ManageEngine exporter
func NewManageEngineExporter(config ManageEngineConfig, logger *zap.Logger) *ManageEngineExporter {
	return &ManageEngineExporter{
		BaseExporter: NewBaseExporter(
			"manageengine",
			"monitoring",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the ManageEngine exporter
func (m *ManageEngineExporter) Init(ctx context.Context) error {
	if !m.config.Enabled {
		return nil
	}

	if err := m.Validate(); err != nil {
		return err
	}

	// Set defaults based on product
	if m.config.Product == "" {
		m.config.Product = "opmanager"
	}
	if m.config.BaseURL == "" {
		switch m.config.Product {
		case "site24x7":
			m.config.BaseURL = "https://www.site24x7.com"
		case "applications_manager":
			m.config.BaseURL = "https://localhost:9090"
		default:
			m.config.BaseURL = "https://localhost:8060"
		}
	}
	if m.config.MetricsEndpoint == "" {
		m.config.MetricsEndpoint = fmt.Sprintf("%s/api/v1/metrics", m.config.BaseURL)
	}
	if m.config.AlertsEndpoint == "" {
		m.config.AlertsEndpoint = fmt.Sprintf("%s/api/v1/alerts", m.config.BaseURL)
	}
	if m.config.LogsEndpoint == "" {
		m.config.LogsEndpoint = fmt.Sprintf("%s/api/v1/logs", m.config.BaseURL)
	}
	if m.config.Timeout == 0 {
		m.config.Timeout = 30 * time.Second
	}
	if m.config.BatchSize == 0 {
		m.config.BatchSize = 500
	}
	if m.config.FlushInterval == 0 {
		m.config.FlushInterval = 10 * time.Second
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if m.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in on-premise ManageEngine deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	m.httpClient = &http.Client{
		Transport: transport,
		Timeout:   m.config.Timeout,
	}

	m.SetInitialized(true)
	m.Logger().Info("ManageEngine exporter initialized",
		zap.String("baseUrl", m.config.BaseURL),
		zap.String("product", m.config.Product),
	)

	return nil
}

// Validate validates the ManageEngine configuration
func (m *ManageEngineExporter) Validate() error {
	if !m.config.Enabled {
		return nil
	}

	if m.config.APIKey == "" {
		return NewValidationError("manageengine", "api_key", "api_key is required")
	}

	validProducts := map[string]bool{
		"opmanager":            true,
		"applications_manager": true,
		"site24x7":             true,
	}
	if m.config.Product != "" && !validProducts[m.config.Product] {
		return NewValidationError("manageengine", "product", "product must be one of: opmanager, applications_manager, site24x7")
	}

	return nil
}

// Export exports telemetry data to ManageEngine
func (m *ManageEngineExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := m.ExportMetrics(ctx, data.Metrics)
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
		result, err := m.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to ManageEngine
func (m *ManageEngineExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !m.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to ManageEngine format
	meMetrics := make([]manageEngineMetric, 0, len(metrics))
	for _, metric := range metrics {
		meMetric := manageEngineMetric{
			MonitorName:  metric.Name,
			DisplayName:  metric.Name,
			Type:         string(metric.Type),
			Value:        metric.Value,
			Unit:         metric.Unit,
			Timestamp:    metric.Timestamp.UnixMilli(),
			MonitorGroup: m.config.MonitorGroup,
			Attributes:   make(map[string]interface{}),
		}
		for k, v := range metric.Tags {
			meMetric.Attributes[k] = v
		}
		for k, v := range m.config.Tags {
			meMetric.Attributes[k] = v
		}
		meMetrics = append(meMetrics, meMetric)
	}

	body, err := json.Marshal(map[string]interface{}{
		"metrics": meMetrics,
	})
	if err != nil {
		m.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := m.sendRequest(ctx, "POST", m.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		m.RecordError(err)
		return result, err
	}

	m.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to ManageEngine (converted to alerts for APM-like visibility)
func (m *ManageEngineExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !m.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert error traces to alerts
	alerts := make([]manageEngineAlert, 0)
	for _, t := range traces {
		if t.Status == TraceStatusError {
			alert := manageEngineAlert{
				Message:     fmt.Sprintf("Trace error in %s: %s", t.ServiceName, t.OperationName),
				Severity:    "Major",
				Source:      "telemetryflow-agent",
				Timestamp:   t.StartTime.UnixMilli(),
				MonitorName: t.ServiceName,
				Entity:      t.TraceID,
				Tags:        t.Tags,
			}
			alerts = append(alerts, alert)
		}
	}

	if len(alerts) == 0 {
		return &ExportResult{
			Success:       true,
			ItemsExported: 0,
			Duration:      time.Since(startTime),
		}, nil
	}

	body, err := json.Marshal(map[string]interface{}{
		"alerts": alerts,
	})
	if err != nil {
		m.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := m.sendRequest(ctx, "POST", m.config.AlertsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(alerts)

	if err != nil {
		m.RecordError(err)
		return result, err
	}

	m.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to ManageEngine
func (m *ManageEngineExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !m.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to ManageEngine log format
	meLogs := make([]manageEngineLogEntry, 0, len(logs))
	for _, l := range logs {
		meLog := manageEngineLogEntry{
			Message:    l.Message,
			LogLevel:   string(l.Level),
			Source:     l.Source,
			Timestamp:  l.Timestamp.UnixMilli(),
			Attributes: l.Attributes,
		}
		meLogs = append(meLogs, meLog)
	}

	body, err := json.Marshal(map[string]interface{}{
		"logs": meLogs,
	})
	if err != nil {
		m.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := m.sendRequest(ctx, "POST", m.config.LogsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		m.RecordError(err)
		return result, err
	}

	m.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the ManageEngine integration
func (m *ManageEngineExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !m.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check API availability
	healthURL := fmt.Sprintf("%s/api/v1/health", m.config.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	req.Header.Set("Authorization", "Apikey "+m.config.APIKey)
	if m.config.AccountID != "" {
		req.Header.Set("X-Account-ID", m.config.AccountID)
	}

	resp, err := m.httpClient.Do(req)
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
		Message:   "ManageEngine API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"product": m.config.Product,
		},
	}, nil
}

// Close closes the ManageEngine exporter
func (m *ManageEngineExporter) Close(ctx context.Context) error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	m.SetInitialized(false)
	m.Logger().Info("ManageEngine exporter closed")
	return nil
}

// sendRequest sends an HTTP request to ManageEngine
func (m *ManageEngineExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Apikey "+m.config.APIKey)
	if m.config.AccountID != "" {
		req.Header.Set("X-Account-ID", m.config.AccountID)
	}

	// Add custom headers
	for k, v := range m.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("manageengine API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
