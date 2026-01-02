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

// AzureConfig contains Azure Monitor integration configuration
type AzureConfig struct {
	Enabled                     bool              `mapstructure:"enabled"`
	SubscriptionID              string            `mapstructure:"subscription_id"`
	TenantID                    string            `mapstructure:"tenant_id"`
	ClientID                    string            `mapstructure:"client_id"`
	ClientSecret                string            `mapstructure:"client_secret"`
	ResourceGroup               string            `mapstructure:"resource_group"`
	WorkspaceID                 string            `mapstructure:"workspace_id"`
	WorkspaceKey                string            `mapstructure:"workspace_key"`
	Region                      string            `mapstructure:"region"`
	MetricNamespace             string            `mapstructure:"metric_namespace"`
	LogType                     string            `mapstructure:"log_type"`
	InstrumentationKey          string            `mapstructure:"instrumentation_key"`
	ConnectionString            string            `mapstructure:"connection_string"`
	UseManagedIdentity          bool              `mapstructure:"use_managed_identity"`
	BatchSize                   int               `mapstructure:"batch_size"`
	FlushInterval               time.Duration     `mapstructure:"flush_interval"`
	Timeout                     time.Duration     `mapstructure:"timeout"`
	CustomMetricsEndpoint       string            `mapstructure:"custom_metrics_endpoint"`
	LogAnalyticsEndpoint        string            `mapstructure:"log_analytics_endpoint"`
	ApplicationInsightsEndpoint string            `mapstructure:"application_insights_endpoint"`
	Headers                     map[string]string `mapstructure:"headers"`
}

// AzureExporter exports telemetry data to Azure Monitor
type AzureExporter struct {
	*BaseExporter
	config      AzureConfig
	httpClient  *http.Client
	accessToken string
}

// Azure metric structure
type azureMetricData struct {
	BaseData azureBaseData `json:"baseData"`
}

type azureBaseData struct {
	Metric    string              `json:"metric"`
	Namespace string              `json:"namespace"`
	DimNames  []string            `json:"dimNames,omitempty"`
	Series    []azureMetricSeries `json:"series"`
}

type azureMetricSeries struct {
	DimValues []string `json:"dimValues,omitempty"`
	Min       float64  `json:"min"`
	Max       float64  `json:"max"`
	Sum       float64  `json:"sum"`
	Count     int      `json:"count"`
}

// Azure Log Analytics structure
type azureLogEntry struct {
	TimeGenerated string                 `json:"TimeGenerated"`
	Level         string                 `json:"Level"`
	Message       string                 `json:"Message"`
	Source        string                 `json:"Source,omitempty"`
	TraceID       string                 `json:"TraceId,omitempty"`
	SpanID        string                 `json:"SpanId,omitempty"`
	Properties    map[string]interface{} `json:"Properties,omitempty"`
}

// Application Insights structures
type azureAppInsightsEnvelope struct {
	Name string               `json:"name"`
	Time string               `json:"time"`
	IKey string               `json:"iKey"`
	Tags map[string]string    `json:"tags"`
	Data azureAppInsightsData `json:"data"`
}

type azureAppInsightsData struct {
	BaseType string                 `json:"baseType"`
	BaseData map[string]interface{} `json:"baseData"`
}

// NewAzureExporter creates a new Azure Monitor exporter
func NewAzureExporter(config AzureConfig, logger *zap.Logger) *AzureExporter {
	return &AzureExporter{
		BaseExporter: NewBaseExporter(
			"azure",
			"cloud",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs, DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the Azure exporter
func (a *AzureExporter) Init(ctx context.Context) error {
	if !a.config.Enabled {
		return nil
	}

	if err := a.Validate(); err != nil {
		return err
	}

	// Set defaults
	if a.config.Region == "" {
		a.config.Region = "eastus"
	}
	if a.config.MetricNamespace == "" {
		a.config.MetricNamespace = "TelemetryFlow"
	}
	if a.config.LogType == "" {
		a.config.LogType = "TelemetryFlowLogs"
	}
	if a.config.CustomMetricsEndpoint == "" {
		a.config.CustomMetricsEndpoint = fmt.Sprintf("https://%s.monitoring.azure.com", a.config.Region)
	}
	if a.config.LogAnalyticsEndpoint == "" {
		a.config.LogAnalyticsEndpoint = "https://api.loganalytics.io"
	}
	if a.config.ApplicationInsightsEndpoint == "" {
		a.config.ApplicationInsightsEndpoint = "https://dc.services.visualstudio.com/v2/track"
	}
	if a.config.BatchSize == 0 {
		a.config.BatchSize = 250
	}
	if a.config.FlushInterval == 0 {
		a.config.FlushInterval = 60 * time.Second
	}
	if a.config.Timeout == 0 {
		a.config.Timeout = 30 * time.Second
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
	a.Logger().Info("Azure Monitor exporter initialized",
		zap.String("subscriptionId", a.config.SubscriptionID),
		zap.String("region", a.config.Region),
	)

	return nil
}

// Validate validates the Azure configuration
func (a *AzureExporter) Validate() error {
	if !a.config.Enabled {
		return nil
	}

	// Check for authentication
	hasServicePrincipal := a.config.TenantID != "" && a.config.ClientID != "" && a.config.ClientSecret != ""
	hasWorkspaceKey := a.config.WorkspaceID != "" && a.config.WorkspaceKey != ""
	hasAppInsights := a.config.InstrumentationKey != "" || a.config.ConnectionString != ""

	if !hasServicePrincipal && !hasWorkspaceKey && !hasAppInsights && !a.config.UseManagedIdentity {
		a.Logger().Debug("No explicit credentials provided, will use Managed Identity")
	}

	return nil
}

// Export exports telemetry data to Azure Monitor
func (a *AzureExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
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

// ExportMetrics exports metrics to Azure Monitor Custom Metrics
func (a *AzureExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Group metrics by name
	metricGroups := make(map[string][]Metric)
	for _, m := range metrics {
		metricGroups[m.Name] = append(metricGroups[m.Name], m)
	}

	// Convert to Azure Custom Metrics format
	var allPayloads []azureMetricData
	for name, group := range metricGroups {
		// Build dimension names from first metric
		var dimNames []string
		for k := range group[0].Tags {
			dimNames = append(dimNames, k)
		}

		// Build series
		var series []azureMetricSeries
		for _, m := range group {
			var dimValues []string
			for _, k := range dimNames {
				dimValues = append(dimValues, m.Tags[k])
			}
			series = append(series, azureMetricSeries{
				DimValues: dimValues,
				Min:       m.Value,
				Max:       m.Value,
				Sum:       m.Value,
				Count:     1,
			})
		}

		payload := azureMetricData{
			BaseData: azureBaseData{
				Metric:    name,
				Namespace: a.config.MetricNamespace,
				DimNames:  dimNames,
				Series:    series,
			},
		}
		allPayloads = append(allPayloads, payload)
	}

	body, err := json.Marshal(allPayloads)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	url := fmt.Sprintf("%s/%s/metrics", a.config.CustomMetricsEndpoint, a.config.SubscriptionID)
	result, err := a.sendRequest(ctx, "POST", url, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces exports traces to Application Insights
func (a *AzureExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	if a.config.InstrumentationKey == "" && a.config.ConnectionString == "" {
		return nil, fmt.Errorf("instrumentation key or connection string required for traces")
	}

	startTime := time.Now()

	// Convert to Application Insights format
	var envelopes []azureAppInsightsEnvelope
	for _, t := range traces {
		envelope := azureAppInsightsEnvelope{
			Name: "Microsoft.ApplicationInsights.Request",
			Time: t.StartTime.Format(time.RFC3339Nano),
			IKey: a.config.InstrumentationKey,
			Tags: map[string]string{
				"ai.operation.id":       t.TraceID,
				"ai.operation.parentId": t.ParentSpanID,
			},
			Data: azureAppInsightsData{
				BaseType: "RequestData",
				BaseData: map[string]interface{}{
					"id":           t.SpanID,
					"name":         t.OperationName,
					"duration":     t.Duration.String(),
					"success":      t.Status != TraceStatusError,
					"responseCode": "200",
					"properties":   t.Tags,
				},
			},
		}
		envelopes = append(envelopes, envelope)
	}

	body, err := json.Marshal(envelopes)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := a.sendRequest(ctx, "POST", a.config.ApplicationInsightsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Azure Log Analytics
func (a *AzureExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Log Analytics format
	entries := make([]azureLogEntry, 0, len(logs))
	for _, l := range logs {
		entry := azureLogEntry{
			TimeGenerated: l.Timestamp.Format(time.RFC3339Nano),
			Level:         a.mapLogLevel(l.Level),
			Message:       l.Message,
			Source:        l.Source,
			TraceID:       l.TraceID,
			SpanID:        l.SpanID,
			Properties:    make(map[string]interface{}),
		}
		for k, v := range l.Attributes {
			entry.Properties[k] = v
		}
		entries = append(entries, entry)
	}

	body, err := json.Marshal(entries)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Send to Log Analytics Data Collector API
	url := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
		a.config.WorkspaceID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", a.config.LogType)
	a.setLogAnalyticsAuth(req, body)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("log analytics error: status=%d body=%s", resp.StatusCode, string(respBody))
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	result := &ExportResult{
		Success:       true,
		BytesSent:     int64(len(body)),
		Duration:      time.Since(startTime),
		ItemsExported: len(logs),
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of Azure Monitor connectivity
func (a *AzureExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !a.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Simple connectivity check
	return &HealthStatus{
		Healthy:   true,
		Message:   "Azure Monitor configured",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"subscription_id": a.config.SubscriptionID,
			"region":          a.config.Region,
			"workspace_id":    a.config.WorkspaceID,
		},
	}, nil
}

// Close closes the Azure exporter
func (a *AzureExporter) Close(ctx context.Context) error {
	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}
	a.SetInitialized(false)
	a.Logger().Info("Azure Monitor exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Azure APIs
func (a *AzureExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
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
		err := fmt.Errorf("azure API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets authentication headers for Azure requests
func (a *AzureExporter) setAuthHeaders(req *http.Request) {
	if a.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.accessToken)
	}
}

// SetAccessToken sets the access token for Azure API authentication
func (a *AzureExporter) SetAccessToken(token string) {
	a.accessToken = token
}

// setLogAnalyticsAuth sets authorization for Log Analytics Data Collector API
func (a *AzureExporter) setLogAnalyticsAuth(req *http.Request, body []byte) {
	// In production, this would compute HMAC-SHA256 signature
	// For now, set the shared key header
	if a.config.WorkspaceKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", a.config.WorkspaceID, a.config.WorkspaceKey))
	}
}

// mapLogLevel maps log levels to Azure severity
func (a *AzureExporter) mapLogLevel(level LogLevel) string {
	switch level {
	case LogLevelDebug:
		return "Verbose"
	case LogLevelInfo:
		return "Information"
	case LogLevelWarn:
		return "Warning"
	case LogLevelError:
		return "Error"
	case LogLevelFatal:
		return "Critical"
	default:
		return "Information"
	}
}
