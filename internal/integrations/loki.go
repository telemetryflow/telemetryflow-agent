// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"go.uber.org/zap"
)

// LokiConfig contains Grafana Loki integration configuration
type LokiConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	Endpoint      string            `mapstructure:"endpoint"`
	TenantID      string            `mapstructure:"tenant_id"`
	Username      string            `mapstructure:"username"`
	Password      string            `mapstructure:"password"`
	BearerToken   string            `mapstructure:"bearer_token"`
	TLSEnabled    bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify bool              `mapstructure:"tls_skip_verify"`
	BatchSize     int               `mapstructure:"batch_size"`
	BatchWait     time.Duration     `mapstructure:"batch_wait"`
	Timeout       time.Duration     `mapstructure:"timeout"`
	Labels        map[string]string `mapstructure:"labels"`
	Headers       map[string]string `mapstructure:"headers"`
}

// LokiExporter exports logs to Grafana Loki
type LokiExporter struct {
	*BaseExporter
	config     LokiConfig
	httpClient *http.Client
}

// Loki push API structures
type lokiPushRequest struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// NewLokiExporter creates a new Loki exporter
func NewLokiExporter(config LokiConfig, logger *zap.Logger) *LokiExporter {
	return &LokiExporter{
		BaseExporter: NewBaseExporter(
			"loki",
			"logging",
			config.Enabled,
			logger,
			[]DataType{DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Loki exporter
func (l *LokiExporter) Init(ctx context.Context) error {
	if !l.config.Enabled {
		return nil
	}

	if err := l.Validate(); err != nil {
		return err
	}

	// Set defaults
	if l.config.BatchSize == 0 {
		l.config.BatchSize = 1000
	}
	if l.config.BatchWait == 0 {
		l.config.BatchWait = time.Second
	}
	if l.config.Timeout == 0 {
		l.config.Timeout = 30 * time.Second
	}

	// Create HTTP client
	l.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: l.config.Timeout,
	}

	l.SetInitialized(true)
	l.Logger().Info("Loki exporter initialized",
		zap.String("endpoint", l.config.Endpoint),
		zap.String("tenantId", l.config.TenantID),
	)

	return nil
}

// Validate validates the Loki configuration
func (l *LokiExporter) Validate() error {
	if !l.config.Enabled {
		return nil
	}

	if l.config.Endpoint == "" {
		return NewValidationError("loki", "endpoint", "endpoint is required")
	}

	return nil
}

// Export exports telemetry data to Loki
func (l *LokiExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !l.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Logs) > 0 {
		return l.ExportLogs(ctx, data.Logs)
	}

	return &ExportResult{Success: true}, nil
}

// ExportMetrics is not supported by Loki
func (l *LokiExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("loki does not support metrics export")
}

// ExportTraces is not supported by Loki
func (l *LokiExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("loki does not support traces export")
}

// ExportLogs exports logs to Loki
func (l *LokiExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !l.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !l.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Group logs by labels
	streamMap := make(map[string]*lokiStream)

	for _, log := range logs {
		// Build label set
		labels := make(map[string]string)
		for k, v := range l.config.Labels {
			labels[k] = v
		}
		labels["level"] = string(log.Level)
		if log.Source != "" {
			labels["source"] = log.Source
		}

		// Create label key for grouping
		labelKey := l.labelKey(labels)

		stream, exists := streamMap[labelKey]
		if !exists {
			stream = &lokiStream{
				Stream: labels,
				Values: make([][]string, 0),
			}
			streamMap[labelKey] = stream
		}

		// Add log entry (timestamp in nanoseconds, message)
		timestamp := strconv.FormatInt(log.Timestamp.UnixNano(), 10)
		stream.Values = append(stream.Values, []string{timestamp, log.Message})
	}

	// Build push request
	streams := make([]lokiStream, 0, len(streamMap))
	for _, stream := range streamMap {
		streams = append(streams, *stream)
	}

	payload := lokiPushRequest{Streams: streams}
	body, err := json.Marshal(payload)
	if err != nil {
		l.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Send to Loki
	result, err := l.sendRequest(ctx, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		l.RecordError(err)
		return result, err
	}

	l.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of Loki
func (l *LokiExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !l.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check Loki ready endpoint
	readyURL := l.config.Endpoint
	if readyURL[len(readyURL)-1] == '/' {
		readyURL = readyURL[:len(readyURL)-1]
	}
	// Remove /loki/api/v1/push if present and add /ready
	readyURL = readyURL + "/ready"

	req, err := http.NewRequestWithContext(ctx, "GET", readyURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	l.setAuthHeaders(req)

	resp, err := l.httpClient.Do(req)
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
	}, nil
}

// Close closes the Loki exporter
func (l *LokiExporter) Close(ctx context.Context) error {
	if l.httpClient != nil {
		l.httpClient.CloseIdleConnections()
	}
	l.SetInitialized(false)
	l.Logger().Info("Loki exporter closed")
	return nil
}

// sendRequest sends a push request to Loki
func (l *LokiExporter) sendRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	pushURL := l.config.Endpoint
	if pushURL[len(pushURL)-1] != '/' {
		pushURL += "/"
	}
	pushURL += "loki/api/v1/push"

	req, err := http.NewRequestWithContext(ctx, "POST", pushURL, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	l.setAuthHeaders(req)

	// Add custom headers
	for k, v := range l.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("loki push error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets authentication headers
func (l *LokiExporter) setAuthHeaders(req *http.Request) {
	if l.config.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", l.config.TenantID)
	}
	if l.config.Username != "" && l.config.Password != "" {
		req.SetBasicAuth(l.config.Username, l.config.Password)
	} else if l.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+l.config.BearerToken)
	}
}

// labelKey creates a unique key from labels for grouping
func (l *LokiExporter) labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var key string
	for _, k := range keys {
		key += k + "=" + labels[k] + ","
	}
	return key
}
