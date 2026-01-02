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

// GCPConfig contains Google Cloud Platform integration configuration
type GCPConfig struct {
	Enabled            bool              `mapstructure:"enabled"`
	ProjectID          string            `mapstructure:"project_id"`
	CredentialsFile    string            `mapstructure:"credentials_file"`
	CredentialsJSON    string            `mapstructure:"credentials_json"`
	ServiceAccountKey  string            `mapstructure:"service_account_key"`
	Region             string            `mapstructure:"region"`
	MetricPrefix       string            `mapstructure:"metric_prefix"`
	LogName            string            `mapstructure:"log_name"`
	ResourceType       string            `mapstructure:"resource_type"`
	ResourceLabels     map[string]string `mapstructure:"resource_labels"`
	MonitoredResource  string            `mapstructure:"monitored_resource"`
	BatchSize          int               `mapstructure:"batch_size"`
	FlushInterval      time.Duration     `mapstructure:"flush_interval"`
	Timeout            time.Duration     `mapstructure:"timeout"`
	UseMetadataServer  bool              `mapstructure:"use_metadata_server"`
	MonitoringEndpoint string            `mapstructure:"monitoring_endpoint"`
	LoggingEndpoint    string            `mapstructure:"logging_endpoint"`
	TraceEndpoint      string            `mapstructure:"trace_endpoint"`
	Headers            map[string]string `mapstructure:"headers"`
}

// GCPExporter exports telemetry data to Google Cloud Platform
type GCPExporter struct {
	*BaseExporter
	config      GCPConfig
	httpClient  *http.Client
	accessToken string
}

// GCP metric structure
type gcpMetricDescriptor struct {
	Type        string            `json:"type"`
	Labels      map[string]string `json:"labels,omitempty"`
	MetricKind  string            `json:"metricKind"`
	ValueType   string            `json:"valueType"`
	Unit        string            `json:"unit,omitempty"`
	Description string            `json:"description,omitempty"`
}

type gcpTimeSeries struct {
	Metric     gcpMetricDescriptor  `json:"metric"`
	Resource   gcpMonitoredResource `json:"resource"`
	MetricKind string               `json:"metricKind"`
	ValueType  string               `json:"valueType"`
	Points     []gcpPoint           `json:"points"`
}

type gcpMonitoredResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type gcpPoint struct {
	Interval gcpTimeInterval `json:"interval"`
	Value    gcpTypedValue   `json:"value"`
}

type gcpTimeInterval struct {
	EndTime   string `json:"endTime"`
	StartTime string `json:"startTime,omitempty"`
}

type gcpTypedValue struct {
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	Int64Value  *int64   `json:"int64Value,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	StringValue *string  `json:"stringValue,omitempty"`
}

type gcpLogEntry struct {
	LogName     string                 `json:"logName"`
	Resource    gcpMonitoredResource   `json:"resource"`
	Timestamp   string                 `json:"timestamp"`
	Severity    string                 `json:"severity"`
	TextPayload string                 `json:"textPayload,omitempty"`
	JSONPayload map[string]interface{} `json:"jsonPayload,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Trace       string                 `json:"trace,omitempty"`
	SpanID      string                 `json:"spanId,omitempty"`
}

// NewGCPExporter creates a new GCP exporter
func NewGCPExporter(config GCPConfig, logger *zap.Logger) *GCPExporter {
	return &GCPExporter{
		BaseExporter: NewBaseExporter(
			"gcp",
			"cloud",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs, DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the GCP exporter
func (g *GCPExporter) Init(ctx context.Context) error {
	if !g.config.Enabled {
		return nil
	}

	if err := g.Validate(); err != nil {
		return err
	}

	// Set defaults
	if g.config.Region == "" {
		g.config.Region = "us-central1"
	}
	if g.config.MetricPrefix == "" {
		g.config.MetricPrefix = "custom.googleapis.com/telemetryflow"
	}
	if g.config.LogName == "" {
		g.config.LogName = "telemetryflow"
	}
	if g.config.ResourceType == "" {
		g.config.ResourceType = "global"
	}
	if g.config.MonitoringEndpoint == "" {
		g.config.MonitoringEndpoint = "https://monitoring.googleapis.com/v3"
	}
	if g.config.LoggingEndpoint == "" {
		g.config.LoggingEndpoint = "https://logging.googleapis.com/v2"
	}
	if g.config.TraceEndpoint == "" {
		g.config.TraceEndpoint = "https://cloudtrace.googleapis.com/v2"
	}
	if g.config.BatchSize == 0 {
		g.config.BatchSize = 200 // GCP limit is 200 time series per request
	}
	if g.config.FlushInterval == 0 {
		g.config.FlushInterval = 60 * time.Second
	}
	if g.config.Timeout == 0 {
		g.config.Timeout = 30 * time.Second
	}

	// Create HTTP client
	g.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: g.config.Timeout,
	}

	g.SetInitialized(true)
	g.Logger().Info("GCP exporter initialized",
		zap.String("projectId", g.config.ProjectID),
		zap.String("region", g.config.Region),
	)

	return nil
}

// Validate validates the GCP configuration
func (g *GCPExporter) Validate() error {
	if !g.config.Enabled {
		return nil
	}

	if g.config.ProjectID == "" {
		return NewValidationError("gcp", "project_id", "project_id is required")
	}

	// Check for credentials
	hasCredentials := g.config.CredentialsFile != "" ||
		g.config.CredentialsJSON != "" ||
		g.config.ServiceAccountKey != "" ||
		g.config.UseMetadataServer

	if !hasCredentials {
		g.Logger().Debug("No explicit credentials provided, will use Application Default Credentials")
	}

	return nil
}

// Export exports telemetry data to GCP
func (g *GCPExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !g.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := g.ExportMetrics(ctx, data.Metrics)
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
		result, err := g.ExportTraces(ctx, data.Traces)
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
		result, err := g.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to Google Cloud Monitoring
func (g *GCPExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !g.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !g.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to GCP time series format
	timeSeries := make([]gcpTimeSeries, 0, len(metrics))
	for _, m := range metrics {
		ts := gcpTimeSeries{
			Metric: gcpMetricDescriptor{
				Type:   fmt.Sprintf("%s/%s", g.config.MetricPrefix, m.Name),
				Labels: m.Tags,
			},
			Resource: gcpMonitoredResource{
				Type:   g.config.ResourceType,
				Labels: g.config.ResourceLabels,
			},
			MetricKind: "GAUGE",
			ValueType:  "DOUBLE",
			Points: []gcpPoint{
				{
					Interval: gcpTimeInterval{
						EndTime: m.Timestamp.Format(time.RFC3339Nano),
					},
					Value: gcpTypedValue{
						DoubleValue: &m.Value,
					},
				},
			},
		}
		timeSeries = append(timeSeries, ts)
	}

	// Build request
	payload := map[string]interface{}{
		"timeSeries": timeSeries,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		g.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Send to Cloud Monitoring API
	url := fmt.Sprintf("%s/projects/%s/timeSeries", g.config.MonitoringEndpoint, g.config.ProjectID)
	result, err := g.sendRequest(ctx, "POST", url, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		g.RecordError(err)
		return result, err
	}

	g.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Google Cloud Trace
func (g *GCPExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !g.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !g.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Cloud Trace format
	spans := make([]map[string]interface{}, 0, len(traces))
	for _, t := range traces {
		span := map[string]interface{}{
			"name":        fmt.Sprintf("projects/%s/traces/%s/spans/%s", g.config.ProjectID, t.TraceID, t.SpanID),
			"spanId":      t.SpanID,
			"displayName": map[string]string{"value": t.OperationName},
			"startTime":   t.StartTime.Format(time.RFC3339Nano),
			"endTime":     t.StartTime.Add(t.Duration).Format(time.RFC3339Nano),
			"attributes": map[string]interface{}{
				"attributeMap": g.convertAttributes(t.Tags),
			},
		}
		if t.ParentSpanID != "" {
			span["parentSpanId"] = t.ParentSpanID
		}
		if t.Status == TraceStatusError {
			span["status"] = map[string]interface{}{
				"code":    2, // ERROR
				"message": "Error",
			}
		}
		spans = append(spans, span)
	}

	payload := map[string]interface{}{
		"spans": spans,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		g.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	url := fmt.Sprintf("%s/projects/%s/traces:batchWrite", g.config.TraceEndpoint, g.config.ProjectID)
	result, err := g.sendRequest(ctx, "POST", url, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		g.RecordError(err)
		return result, err
	}

	g.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Google Cloud Logging
func (g *GCPExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !g.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !g.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Cloud Logging format
	entries := make([]gcpLogEntry, 0, len(logs))
	for _, l := range logs {
		entry := gcpLogEntry{
			LogName: fmt.Sprintf("projects/%s/logs/%s", g.config.ProjectID, g.config.LogName),
			Resource: gcpMonitoredResource{
				Type:   g.config.ResourceType,
				Labels: g.config.ResourceLabels,
			},
			Timestamp:   l.Timestamp.Format(time.RFC3339Nano),
			Severity:    g.mapSeverity(l.Level),
			TextPayload: l.Message,
			Labels:      l.Attributes,
		}
		if l.TraceID != "" {
			entry.Trace = fmt.Sprintf("projects/%s/traces/%s", g.config.ProjectID, l.TraceID)
		}
		if l.SpanID != "" {
			entry.SpanID = l.SpanID
		}
		entries = append(entries, entry)
	}

	payload := map[string]interface{}{
		"entries": entries,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		g.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	url := fmt.Sprintf("%s/entries:write", g.config.LoggingEndpoint)
	result, err := g.sendRequest(ctx, "POST", url, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		g.RecordError(err)
		return result, err
	}

	g.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of GCP connectivity
func (g *GCPExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !g.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check connectivity by listing metric descriptors
	url := fmt.Sprintf("%s/projects/%s/metricDescriptors", g.config.MonitoringEndpoint, g.config.ProjectID)
	req, err := http.NewRequestWithContext(ctx, "GET", url+"?pageSize=1", nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	g.setAuthHeaders(req)

	resp, err := g.httpClient.Do(req)
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
		Message:   "GCP connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"project_id": g.config.ProjectID,
			"region":     g.config.Region,
		},
	}, nil
}

// Close closes the GCP exporter
func (g *GCPExporter) Close(ctx context.Context) error {
	if g.httpClient != nil {
		g.httpClient.CloseIdleConnections()
	}
	g.SetInitialized(false)
	g.Logger().Info("GCP exporter closed")
	return nil
}

// sendRequest sends an HTTP request to GCP APIs
func (g *GCPExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	g.setAuthHeaders(req)

	// Add custom headers
	for k, v := range g.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("GCP API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets authentication headers for GCP requests
func (g *GCPExporter) setAuthHeaders(req *http.Request) {
	if g.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.accessToken)
	}
}

// SetAccessToken sets the access token for GCP API authentication
func (g *GCPExporter) SetAccessToken(token string) {
	g.accessToken = token
}

// mapSeverity maps log levels to GCP severity
func (g *GCPExporter) mapSeverity(level LogLevel) string {
	switch level {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARNING"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "CRITICAL"
	default:
		return "DEFAULT"
	}
}

// convertAttributes converts tags to GCP attribute format
func (g *GCPExporter) convertAttributes(tags map[string]string) map[string]interface{} {
	attrs := make(map[string]interface{})
	for k, v := range tags {
		attrs[k] = map[string]interface{}{
			"stringValue": map[string]string{"value": v},
		}
	}
	return attrs
}
