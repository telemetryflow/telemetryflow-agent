// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// InfluxDBConfig contains InfluxDB integration configuration
type InfluxDBConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	URL             string            `mapstructure:"url"`
	Token           string            `mapstructure:"token"`
	Organization    string            `mapstructure:"organization"`
	Bucket          string            `mapstructure:"bucket"`
	Precision       string            `mapstructure:"precision"`
	Username        string            `mapstructure:"username"`
	Password        string            `mapstructure:"password"`
	Database        string            `mapstructure:"database"`
	RetentionPolicy string            `mapstructure:"retention_policy"`
	TLSEnabled      bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	Headers         map[string]string `mapstructure:"headers"`
}

// InfluxDBExporter exports telemetry data to InfluxDB
type InfluxDBExporter struct {
	*BaseExporter
	config     InfluxDBConfig
	httpClient *http.Client
	writeURL   string
	isV2       bool
}

// NewInfluxDBExporter creates a new InfluxDB exporter
func NewInfluxDBExporter(config InfluxDBConfig, logger *zap.Logger) *InfluxDBExporter {
	return &InfluxDBExporter{
		BaseExporter: NewBaseExporter(
			"influxdb",
			"tsdb",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the InfluxDB exporter
func (i *InfluxDBExporter) Init(ctx context.Context) error {
	if !i.config.Enabled {
		return nil
	}

	if err := i.Validate(); err != nil {
		return err
	}

	// Set defaults
	if i.config.Timeout == 0 {
		i.config.Timeout = 30 * time.Second
	}
	if i.config.BatchSize == 0 {
		i.config.BatchSize = 5000
	}
	if i.config.FlushInterval == 0 {
		i.config.FlushInterval = 10 * time.Second
	}
	if i.config.Precision == "" {
		i.config.Precision = "ns"
	}

	// Determine InfluxDB version and build write URL
	baseURL := strings.TrimSuffix(i.config.URL, "/")
	if i.config.Token != "" && i.config.Organization != "" && i.config.Bucket != "" {
		// InfluxDB 2.x
		i.isV2 = true
		i.writeURL = fmt.Sprintf("%s/api/v2/write?org=%s&bucket=%s&precision=%s",
			baseURL,
			url.QueryEscape(i.config.Organization),
			url.QueryEscape(i.config.Bucket),
			i.config.Precision,
		)
	} else {
		// InfluxDB 1.x
		i.isV2 = false
		db := i.config.Database
		if db == "" {
			db = i.config.Bucket
		}
		i.writeURL = fmt.Sprintf("%s/write?db=%s&precision=%s",
			baseURL,
			url.QueryEscape(db),
			i.config.Precision,
		)
		if i.config.RetentionPolicy != "" {
			i.writeURL += "&rp=" + url.QueryEscape(i.config.RetentionPolicy)
		}
	}

	// Create HTTP client
	i.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: i.config.Timeout,
	}

	i.SetInitialized(true)
	i.Logger().Info("InfluxDB exporter initialized",
		zap.String("url", i.config.URL),
		zap.Bool("v2", i.isV2),
	)

	return nil
}

// Validate validates the InfluxDB configuration
func (i *InfluxDBExporter) Validate() error {
	if !i.config.Enabled {
		return nil
	}

	if i.config.URL == "" {
		return NewValidationError("influxdb", "url", "url is required")
	}

	// Check for v2 or v1 auth
	hasV2Auth := i.config.Token != "" && i.config.Organization != "" && i.config.Bucket != ""
	hasV1Auth := i.config.Database != "" || i.config.Bucket != ""

	if !hasV2Auth && !hasV1Auth {
		return NewValidationError("influxdb", "auth", "either (token, organization, bucket) for v2 or (database) for v1 is required")
	}

	return nil
}

// Export exports telemetry data to InfluxDB
func (i *InfluxDBExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Metrics) > 0 {
		return i.ExportMetrics(ctx, data.Metrics)
	}

	return &ExportResult{Success: true}, nil
}

// ExportMetrics exports metrics to InfluxDB
func (i *InfluxDBExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !i.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to InfluxDB line protocol
	var buf bytes.Buffer
	for _, m := range metrics {
		line := i.buildLineProtocol(m)
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	result, err := i.sendRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		i.RecordError(err)
		return result, err
	}

	i.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces is not supported by InfluxDB
func (i *InfluxDBExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("influxdb does not natively support traces export")
}

// ExportLogs exports logs as metrics to InfluxDB
func (i *InfluxDBExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	// Convert logs to metrics for storage
	if !i.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !i.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	var buf bytes.Buffer
	for _, l := range logs {
		// Store log as a point with message as field
		tags := make(map[string]string)
		tags["level"] = string(l.Level)
		if l.Source != "" {
			tags["source"] = l.Source
		}

		line := fmt.Sprintf("logs,%s message=%q %d",
			i.buildTags(tags),
			l.Message,
			l.Timestamp.UnixNano(),
		)
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	result, err := i.sendRequest(ctx, buf.Bytes())
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(logs)

	if err != nil {
		i.RecordError(err)
		return result, err
	}

	i.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of the InfluxDB instance
func (i *InfluxDBExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !i.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()
	baseURL := strings.TrimSuffix(i.config.URL, "/")

	var healthURL string
	if i.isV2 {
		healthURL = baseURL + "/health"
	} else {
		healthURL = baseURL + "/ping"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

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

	healthy := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent

	return &HealthStatus{
		Healthy:   healthy,
		Message:   fmt.Sprintf("status: %d", resp.StatusCode),
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"version": resp.Header.Get("X-Influxdb-Version"),
		},
	}, nil
}

// Close closes the InfluxDB exporter
func (i *InfluxDBExporter) Close(ctx context.Context) error {
	if i.httpClient != nil {
		i.httpClient.CloseIdleConnections()
	}
	i.SetInitialized(false)
	i.Logger().Info("InfluxDB exporter closed")
	return nil
}

// buildLineProtocol builds an InfluxDB line protocol string
func (i *InfluxDBExporter) buildLineProtocol(m Metric) string {
	// Measurement name
	measurement := escapeInfluxMeasurement(m.Name)

	// Tags
	tagStr := i.buildTags(m.Tags)

	// Fields
	fieldStr := fmt.Sprintf("value=%f", m.Value)
	if m.Unit != "" {
		fieldStr += fmt.Sprintf(",unit=%q", m.Unit)
	}

	// Timestamp
	var timestamp int64
	switch i.config.Precision {
	case "s":
		timestamp = m.Timestamp.Unix()
	case "ms":
		timestamp = m.Timestamp.UnixMilli()
	case "us":
		timestamp = m.Timestamp.UnixMicro()
	default:
		timestamp = m.Timestamp.UnixNano()
	}

	if tagStr != "" {
		return fmt.Sprintf("%s,%s %s %d", measurement, tagStr, fieldStr, timestamp)
	}
	return fmt.Sprintf("%s %s %d", measurement, fieldStr, timestamp)
}

// buildTags builds the tag string for line protocol
func (i *InfluxDBExporter) buildTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		v := tags[k]
		if v != "" {
			parts = append(parts, fmt.Sprintf("%s=%s",
				escapeInfluxTag(k),
				escapeInfluxTag(v),
			))
		}
	}

	return strings.Join(parts, ",")
}

// sendRequest sends a write request to InfluxDB
func (i *InfluxDBExporter) sendRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", i.writeURL, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	// Set authentication
	if i.isV2 {
		req.Header.Set("Authorization", "Token "+i.config.Token)
	} else if i.config.Username != "" && i.config.Password != "" {
		req.SetBasicAuth(i.config.Username, i.config.Password)
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
		err := fmt.Errorf("influxdb write error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// escapeInfluxMeasurement escapes measurement name for line protocol
func escapeInfluxMeasurement(s string) string {
	s = strings.ReplaceAll(s, ",", `\,`)
	s = strings.ReplaceAll(s, " ", `\ `)
	return s
}

// escapeInfluxTag escapes tag key/value for line protocol
func escapeInfluxTag(s string) string {
	s = strings.ReplaceAll(s, ",", `\,`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, " ", `\ `)
	return s
}
