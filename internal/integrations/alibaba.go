// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- SHA1 required by Alibaba Cloud API signature (HMAC-SHA1)
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AlibabaConfig contains Alibaba Cloud integration configuration
type AlibabaConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	AccessKeyID     string            `mapstructure:"access_key_id"`
	AccessKeySecret string            `mapstructure:"access_key_secret"`
	SecurityToken   string            `mapstructure:"security_token"`
	RegionID        string            `mapstructure:"region_id"`
	Project         string            `mapstructure:"project"`
	Logstore        string            `mapstructure:"logstore"`
	Endpoint        string            `mapstructure:"endpoint"`
	SLSEndpoint     string            `mapstructure:"sls_endpoint"`
	ARMSEndpoint    string            `mapstructure:"arms_endpoint"`
	CMSEndpoint     string            `mapstructure:"cms_endpoint"`
	Namespace       string            `mapstructure:"namespace"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	UseRAMRole      bool              `mapstructure:"use_ram_role"`
	Headers         map[string]string `mapstructure:"headers"`
	Tags            map[string]string `mapstructure:"tags"`
}

// AlibabaExporter exports telemetry data to Alibaba Cloud
type AlibabaExporter struct {
	*BaseExporter
	config     AlibabaConfig
	httpClient *http.Client
}

// Alibaba Cloud Monitoring (CMS) metric structure
type alibabaMetricData struct {
	GroupID    int64                  `json:"groupId,omitempty"`
	MetricName string                 `json:"metricName"`
	Dimensions []alibabaDimension     `json:"dimensions"`
	Time       int64                  `json:"time"`
	Type       int                    `json:"type"` // 0: raw, 1: aggregated
	Period     int                    `json:"period,omitempty"`
	Values     map[string]interface{} `json:"values"`
}

type alibabaDimension struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Alibaba SLS log structure
type alibabaSLSLogGroup struct {
	Logs    []alibabaSLSLog `json:"logs"`
	Topic   string          `json:"topic,omitempty"`
	Source  string          `json:"source,omitempty"`
	LogTags []alibabaSLSTag `json:"logTags,omitempty"`
}

type alibabaSLSLog struct {
	Time     int64           `json:"time"`
	Contents []alibabaSLSTag `json:"contents"`
}

type alibabaSLSTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// NewAlibabaExporter creates a new Alibaba Cloud exporter
func NewAlibabaExporter(config AlibabaConfig, logger *zap.Logger) *AlibabaExporter {
	return &AlibabaExporter{
		BaseExporter: NewBaseExporter(
			"alibaba",
			"cloud",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs, DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the Alibaba Cloud exporter
func (a *AlibabaExporter) Init(ctx context.Context) error {
	if !a.config.Enabled {
		return nil
	}

	if err := a.Validate(); err != nil {
		return err
	}

	// Set defaults
	if a.config.RegionID == "" {
		a.config.RegionID = "cn-hangzhou"
	}
	if a.config.Namespace == "" {
		a.config.Namespace = "acs_custom_telemetryflow"
	}
	if a.config.Project == "" {
		a.config.Project = "telemetryflow"
	}
	if a.config.Logstore == "" {
		a.config.Logstore = "telemetryflow-logs"
	}
	if a.config.SLSEndpoint == "" {
		a.config.SLSEndpoint = fmt.Sprintf("https://%s.log.aliyuncs.com", a.config.RegionID)
	}
	if a.config.ARMSEndpoint == "" {
		a.config.ARMSEndpoint = fmt.Sprintf("https://arms.%s.aliyuncs.com", a.config.RegionID)
	}
	if a.config.CMSEndpoint == "" {
		a.config.CMSEndpoint = fmt.Sprintf("https://metrics.%s.aliyuncs.com", a.config.RegionID)
	}
	if a.config.BatchSize == 0 {
		a.config.BatchSize = 4096 // SLS supports up to 4096 logs per request
	}
	if a.config.FlushInterval == 0 {
		a.config.FlushInterval = 30 * time.Second
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
	a.Logger().Info("Alibaba Cloud exporter initialized",
		zap.String("regionId", a.config.RegionID),
		zap.String("project", a.config.Project),
	)

	return nil
}

// Validate validates the Alibaba Cloud configuration
func (a *AlibabaExporter) Validate() error {
	if !a.config.Enabled {
		return nil
	}

	// Check for credentials
	hasCredentials := a.config.AccessKeyID != "" && a.config.AccessKeySecret != ""

	if !hasCredentials && !a.config.UseRAMRole {
		return NewValidationError("alibaba", "credentials", "access_key_id and access_key_secret are required, or enable use_ram_role")
	}

	return nil
}

// Export exports telemetry data to Alibaba Cloud
func (a *AlibabaExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
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

// ExportMetrics exports metrics to Alibaba Cloud Monitoring (CMS)
func (a *AlibabaExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to CMS metric format
	metricData := make([]alibabaMetricData, 0, len(metrics))
	for _, m := range metrics {
		dimensions := make([]alibabaDimension, 0, len(m.Tags))
		for k, v := range m.Tags {
			dimensions = append(dimensions, alibabaDimension{Key: k, Value: v})
		}
		// Add configured tags
		for k, v := range a.config.Tags {
			dimensions = append(dimensions, alibabaDimension{Key: k, Value: v})
		}

		data := alibabaMetricData{
			MetricName: m.Name,
			Dimensions: dimensions,
			Time:       m.Timestamp.UnixMilli(),
			Type:       0, // Raw data
			Values: map[string]interface{}{
				"value": m.Value,
			},
		}
		metricData = append(metricData, data)
	}

	body, err := json.Marshal(metricData)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Send to CMS PutCustomMetric API
	url := fmt.Sprintf("%s/?Action=PutCustomMetric&Version=2019-01-01", a.config.CMSEndpoint)
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

// ExportTraces exports traces to Alibaba Cloud ARMS
func (a *AlibabaExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to ARMS compatible format (OpenTracing/Jaeger compatible)
	spans := make([]map[string]interface{}, 0, len(traces))
	for _, t := range traces {
		span := map[string]interface{}{
			"traceId":       t.TraceID,
			"spanId":        t.SpanID,
			"parentSpanId":  t.ParentSpanID,
			"operationName": t.OperationName,
			"serviceName":   t.ServiceName,
			"startTime":     t.StartTime.UnixMicro(),
			"duration":      t.Duration.Microseconds(),
			"tags":          t.Tags,
			"logs":          []interface{}{},
		}
		if t.Status == TraceStatusError {
			span["status"] = "ERROR"
		} else {
			span["status"] = "OK"
		}
		spans = append(spans, span)
	}

	payload := map[string]interface{}{
		"spans": spans,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Send to ARMS trace API
	url := fmt.Sprintf("%s/trace/spans", a.config.ARMSEndpoint)
	result, err := a.sendRequest(ctx, "POST", url, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs exports logs to Alibaba Cloud SLS
func (a *AlibabaExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to SLS log format
	slsLogs := make([]alibabaSLSLog, 0, len(logs))
	for _, l := range logs {
		contents := []alibabaSLSTag{
			{Key: "__level__", Value: string(l.Level)},
			{Key: "__message__", Value: l.Message},
			{Key: "__source__", Value: l.Source},
		}
		if l.TraceID != "" {
			contents = append(contents, alibabaSLSTag{Key: "__trace_id__", Value: l.TraceID})
		}
		if l.SpanID != "" {
			contents = append(contents, alibabaSLSTag{Key: "__span_id__", Value: l.SpanID})
		}
		for k, v := range l.Attributes {
			contents = append(contents, alibabaSLSTag{Key: k, Value: v})
		}

		slsLogs = append(slsLogs, alibabaSLSLog{
			Time:     l.Timestamp.Unix(),
			Contents: contents,
		})
	}

	// Add configured tags as log tags
	var logTags []alibabaSLSTag
	for k, v := range a.config.Tags {
		logTags = append(logTags, alibabaSLSTag{Key: k, Value: v})
	}

	logGroup := alibabaSLSLogGroup{
		Logs:    slsLogs,
		Topic:   "telemetryflow",
		Source:  "telemetryflow-agent",
		LogTags: logTags,
	}

	body, err := json.Marshal(logGroup)
	if err != nil {
		a.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Send to SLS PostLogstoreLogs API
	slsURL := fmt.Sprintf("%s/logstores/%s/shards/lb", a.config.SLSEndpoint, a.config.Logstore)
	result, err := a.sendSLSRequest(ctx, slsURL, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		a.RecordError(err)
		return result, err
	}

	a.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of Alibaba Cloud connectivity
func (a *AlibabaExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !a.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check SLS project exists
	slsURL := fmt.Sprintf("%s/logstores", a.config.SLSEndpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", slsURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	a.signSLSRequest(req, nil)

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
		Message:   "Alibaba Cloud connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"region_id": a.config.RegionID,
			"project":   a.config.Project,
		},
	}, nil
}

// Close closes the Alibaba Cloud exporter
func (a *AlibabaExporter) Close(ctx context.Context) error {
	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}
	a.SetInitialized(false)
	a.Logger().Info("Alibaba Cloud exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Alibaba Cloud APIs
func (a *AlibabaExporter) sendRequest(ctx context.Context, method, endpoint string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	a.signRequest(req, body)

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
		err := fmt.Errorf("alibaba cloud API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// sendSLSRequest sends a request to SLS with proper signing
func (a *AlibabaExporter) sendSLSRequest(ctx context.Context, endpoint string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-log-bodyrawsize", fmt.Sprintf("%d", len(body)))
	req.Header.Set("x-log-apiversion", "0.6.0")
	a.signSLSRequest(req, body)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("SLS API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// signRequest signs the request using Alibaba Cloud signature v1
func (a *AlibabaExporter) signRequest(req *http.Request, body []byte) {
	now := time.Now().UTC()
	req.Header.Set("x-acs-date", now.Format("2006-01-02T15:04:05Z"))
	req.Header.Set("x-acs-signature-method", "HMAC-SHA1")
	req.Header.Set("x-acs-signature-version", "1.0")

	if a.config.SecurityToken != "" {
		req.Header.Set("x-acs-security-token", a.config.SecurityToken)
	}

	// Build string to sign
	stringToSign := a.buildStringToSign(req, body)

	// Calculate signature
	signature := a.calculateSignature(stringToSign, a.config.AccessKeySecret)
	req.Header.Set("Authorization", fmt.Sprintf("acs %s:%s", a.config.AccessKeyID, signature))
}

// signSLSRequest signs the request for SLS API
func (a *AlibabaExporter) signSLSRequest(req *http.Request, body []byte) {
	now := time.Now().UTC()
	req.Header.Set("Date", now.Format(time.RFC1123))
	req.Header.Set("Host", req.URL.Host)

	if a.config.SecurityToken != "" {
		req.Header.Set("x-acs-security-token", a.config.SecurityToken)
	}

	// Build canonical headers
	var canonicalHeaders []string
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-log-") || strings.HasPrefix(lk, "x-acs-") {
			canonicalHeaders = append(canonicalHeaders, fmt.Sprintf("%s:%s", lk, v[0]))
		}
	}
	sort.Strings(canonicalHeaders)

	// Build string to sign
	stringToSign := fmt.Sprintf("%s\n\n%s\n%s\n%s\n%s",
		req.Method,
		req.Header.Get("Content-Type"),
		req.Header.Get("Date"),
		strings.Join(canonicalHeaders, "\n"),
		req.URL.Path,
	)

	// Calculate signature
	signature := a.calculateSignature(stringToSign, a.config.AccessKeySecret)
	req.Header.Set("Authorization", fmt.Sprintf("LOG %s:%s", a.config.AccessKeyID, signature))
}

// buildStringToSign builds the string to sign for API requests
func (a *AlibabaExporter) buildStringToSign(req *http.Request, body []byte) string {
	// Simplified signature string
	return fmt.Sprintf("%s\n%s\n%s\n%s",
		req.Method,
		req.Header.Get("Content-Type"),
		req.Header.Get("x-acs-date"),
		req.URL.Path,
	)
}

// calculateSignature calculates HMAC-SHA1 signature
func (a *AlibabaExporter) calculateSignature(stringToSign, secret string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// PercentEncode encodes string for Alibaba Cloud signature
func PercentEncode(s string) string {
	return url.QueryEscape(s)
}
