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
	"strings"
	"time"

	"go.uber.org/zap"
)

// ElasticsearchConfig contains Elasticsearch integration configuration
type ElasticsearchConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Addresses       []string          `mapstructure:"addresses"`
	Username        string            `mapstructure:"username"`
	Password        string            `mapstructure:"password"`
	APIKey          string            `mapstructure:"api_key"`
	CloudID         string            `mapstructure:"cloud_id"`
	IndexPrefix     string            `mapstructure:"index_prefix"`
	IndexPattern    string            `mapstructure:"index_pattern"`
	Pipeline        string            `mapstructure:"pipeline"`
	TLSEnabled      bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	TLSCertFile     string            `mapstructure:"tls_cert_file"`
	TLSKeyFile      string            `mapstructure:"tls_key_file"`
	TLSCAFile       string            `mapstructure:"tls_ca_file"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	BulkActions     int               `mapstructure:"bulk_actions"`
	RefreshInterval string            `mapstructure:"refresh_interval"`
	Headers         map[string]string `mapstructure:"headers"`
}

// ElasticsearchExporter exports telemetry data to Elasticsearch
type ElasticsearchExporter struct {
	*BaseExporter
	config     ElasticsearchConfig
	httpClient *http.Client
	baseURL    string
}

// NewElasticsearchExporter creates a new Elasticsearch exporter
func NewElasticsearchExporter(config ElasticsearchConfig, logger *zap.Logger) *ElasticsearchExporter {
	return &ElasticsearchExporter{
		BaseExporter: NewBaseExporter(
			"elasticsearch",
			"search",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Elasticsearch exporter
func (e *ElasticsearchExporter) Init(ctx context.Context) error {
	if !e.config.Enabled {
		return nil
	}

	if err := e.Validate(); err != nil {
		return err
	}

	// Set defaults
	if e.config.Timeout == 0 {
		e.config.Timeout = 30 * time.Second
	}
	if e.config.BatchSize == 0 {
		e.config.BatchSize = 1000
	}
	if e.config.FlushInterval == 0 {
		e.config.FlushInterval = 10 * time.Second
	}
	if e.config.IndexPrefix == "" {
		e.config.IndexPrefix = "telemetryflow"
	}
	if e.config.IndexPattern == "" {
		e.config.IndexPattern = "daily"
	}
	if e.config.BulkActions == 0 {
		e.config.BulkActions = 1000
	}

	// Set base URL from addresses
	if len(e.config.Addresses) > 0 {
		e.baseURL = strings.TrimSuffix(e.config.Addresses[0], "/")
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if e.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in Elasticsearch deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	e.httpClient = &http.Client{
		Transport: transport,
		Timeout:   e.config.Timeout,
	}

	e.SetInitialized(true)
	e.Logger().Info("Elasticsearch exporter initialized",
		zap.Strings("addresses", e.config.Addresses),
		zap.String("indexPrefix", e.config.IndexPrefix),
	)

	return nil
}

// Validate validates the Elasticsearch configuration
func (e *ElasticsearchExporter) Validate() error {
	if !e.config.Enabled {
		return nil
	}

	if len(e.config.Addresses) == 0 && e.config.CloudID == "" {
		return NewValidationError("elasticsearch", "addresses", "addresses or cloud_id is required")
	}

	return nil
}

// Export exports telemetry data to Elasticsearch
func (e *ElasticsearchExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !e.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := e.ExportMetrics(ctx, data.Metrics)
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
		result, err := e.ExportTraces(ctx, data.Traces)
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
		result, err := e.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to Elasticsearch
func (e *ElasticsearchExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !e.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !e.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()
	index := e.getIndex("metrics")

	// Build bulk request
	var buf bytes.Buffer
	for _, m := range metrics {
		// Action line
		action := map[string]interface{}{
			"index": map[string]string{
				"_index": index,
			},
		}
		actionJSON, _ := json.Marshal(action)
		buf.Write(actionJSON)
		buf.WriteByte('\n')

		// Document line
		doc := map[string]interface{}{
			"@timestamp": m.Timestamp.Format(time.RFC3339Nano),
			"name":       m.Name,
			"value":      m.Value,
			"type":       string(m.Type),
			"unit":       m.Unit,
			"tags":       m.Tags,
		}
		docJSON, _ := json.Marshal(doc)
		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	result, err := e.sendBulkRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		e.RecordError(err)
		return result, err
	}

	e.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Elasticsearch
func (e *ElasticsearchExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !e.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !e.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()
	index := e.getIndex("traces")

	// Build bulk request
	var buf bytes.Buffer
	for _, t := range traces {
		// Action line
		action := map[string]interface{}{
			"index": map[string]string{
				"_index": index,
			},
		}
		actionJSON, _ := json.Marshal(action)
		buf.Write(actionJSON)
		buf.WriteByte('\n')

		// Document line
		doc := map[string]interface{}{
			"@timestamp":     t.StartTime.Format(time.RFC3339Nano),
			"trace_id":       t.TraceID,
			"span_id":        t.SpanID,
			"parent_span_id": t.ParentSpanID,
			"operation_name": t.OperationName,
			"service_name":   t.ServiceName,
			"duration_ms":    t.Duration.Milliseconds(),
			"status":         string(t.Status),
			"tags":           t.Tags,
		}
		docJSON, _ := json.Marshal(doc)
		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	result, err := e.sendBulkRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		e.RecordError(err)
		return result, err
	}

	e.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Elasticsearch
func (e *ElasticsearchExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !e.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !e.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()
	index := e.getIndex("logs")

	// Build bulk request
	var buf bytes.Buffer
	for _, l := range logs {
		// Action line
		action := map[string]interface{}{
			"index": map[string]string{
				"_index": index,
			},
		}
		actionJSON, _ := json.Marshal(action)
		buf.Write(actionJSON)
		buf.WriteByte('\n')

		// Document line
		doc := map[string]interface{}{
			"@timestamp": l.Timestamp.Format(time.RFC3339Nano),
			"message":    l.Message,
			"level":      string(l.Level),
			"source":     l.Source,
			"trace_id":   l.TraceID,
			"span_id":    l.SpanID,
			"attributes": l.Attributes,
		}
		docJSON, _ := json.Marshal(doc)
		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	result, err := e.sendBulkRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		e.RecordError(err)
		return result, err
	}

	e.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the Elasticsearch cluster
func (e *ElasticsearchExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !e.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", e.baseURL+"/_cluster/health", nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	e.setAuthHeaders(req)

	resp, err := e.httpClient.Do(req)
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

	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err == nil {
		status, _ := health["status"].(string)
		return &HealthStatus{
			Healthy:   status == "green" || status == "yellow",
			Message:   fmt.Sprintf("cluster status: %s", status),
			LastCheck: time.Now(),
			Latency:   time.Since(startTime),
			Details:   health,
		}, nil
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   "cluster reachable",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
	}, nil
}

// Close closes the Elasticsearch exporter
func (e *ElasticsearchExporter) Close(ctx context.Context) error {
	if e.httpClient != nil {
		e.httpClient.CloseIdleConnections()
	}
	e.SetInitialized(false)
	e.Logger().Info("Elasticsearch exporter closed")
	return nil
}

// getIndex returns the index name for the given data type
func (e *ElasticsearchExporter) getIndex(dataType string) string {
	now := time.Now()
	var suffix string

	switch e.config.IndexPattern {
	case "daily":
		suffix = now.Format("2006.01.02")
	case "weekly":
		year, week := now.ISOWeek()
		suffix = fmt.Sprintf("%d.%02d", year, week)
	case "monthly":
		suffix = now.Format("2006.01")
	default:
		suffix = now.Format("2006.01.02")
	}

	return fmt.Sprintf("%s-%s-%s", e.config.IndexPrefix, dataType, suffix)
}

// sendBulkRequest sends a bulk request to Elasticsearch
func (e *ElasticsearchExporter) sendBulkRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	url := e.baseURL + "/_bulk"
	if e.config.Pipeline != "" {
		url += "?pipeline=" + e.config.Pipeline
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	e.setAuthHeaders(req)

	// Add custom headers
	for k, v := range e.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("elasticsearch bulk error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	// Check for errors in bulk response
	var bulkResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err == nil {
		if hasErrors, ok := bulkResp["errors"].(bool); ok && hasErrors {
			return &ExportResult{
				Success:   false,
				Error:     fmt.Errorf("bulk request had errors"),
				BytesSent: int64(len(body)),
			}, nil
		}
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets the authentication headers
func (e *ElasticsearchExporter) setAuthHeaders(req *http.Request) {
	if e.config.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.config.APIKey)
	} else if e.config.Username != "" && e.config.Password != "" {
		req.SetBasicAuth(e.config.Username, e.config.Password)
	}
}
