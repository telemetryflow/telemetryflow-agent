// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// TelegrafConfig contains InfluxDB Telegraf integration configuration
type TelegrafConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Address         string            `mapstructure:"address"`
	Protocol        string            `mapstructure:"protocol"`
	Database        string            `mapstructure:"database"`
	RetentionPolicy string            `mapstructure:"retention_policy"`
	Precision       string            `mapstructure:"precision"`
	Username        string            `mapstructure:"username"`
	Password        string            `mapstructure:"password"`
	ContentEncoding string            `mapstructure:"content_encoding"`
	TLSEnabled      bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	Headers         map[string]string `mapstructure:"headers"`
	GlobalTags      map[string]string `mapstructure:"global_tags"`
}

// TelegrafExporter exports telemetry data to Telegraf
type TelegrafExporter struct {
	*BaseExporter
	config     TelegrafConfig
	httpClient *http.Client
	udpConn    *net.UDPConn
}

// NewTelegrafExporter creates a new Telegraf exporter
func NewTelegrafExporter(config TelegrafConfig, logger *zap.Logger) *TelegrafExporter {
	return &TelegrafExporter{
		BaseExporter: NewBaseExporter(
			"telegraf",
			"collector",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Telegraf exporter
func (t *TelegrafExporter) Init(ctx context.Context) error {
	if !t.config.Enabled {
		return nil
	}

	if err := t.Validate(); err != nil {
		return err
	}

	// Set defaults
	if t.config.Protocol == "" {
		t.config.Protocol = "http"
	}
	if t.config.Precision == "" {
		t.config.Precision = "ns"
	}
	if t.config.Timeout == 0 {
		t.config.Timeout = 30 * time.Second
	}
	if t.config.BatchSize == 0 {
		t.config.BatchSize = 1000
	}
	if t.config.FlushInterval == 0 {
		t.config.FlushInterval = 10 * time.Second
	}

	// Initialize based on protocol
	switch t.config.Protocol {
	case "http", "https":
		t.httpClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: t.config.Timeout,
		}
	case "udp":
		addr, err := net.ResolveUDPAddr("udp", t.config.Address)
		if err != nil {
			return NewValidationError("telegraf", "address", err.Error())
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return NewValidationError("telegraf", "address", err.Error())
		}
		t.udpConn = conn
	}

	t.SetInitialized(true)
	t.Logger().Info("Telegraf exporter initialized",
		zap.String("address", t.config.Address),
		zap.String("protocol", t.config.Protocol),
	)

	return nil
}

// Validate validates the Telegraf configuration
func (t *TelegrafExporter) Validate() error {
	if !t.config.Enabled {
		return nil
	}

	if t.config.Address == "" {
		return NewValidationError("telegraf", "address", "address is required")
	}

	validProtocols := map[string]bool{"http": true, "https": true, "udp": true, "tcp": true}
	if t.config.Protocol != "" && !validProtocols[t.config.Protocol] {
		return NewValidationError("telegraf", "protocol", "protocol must be http, https, udp, or tcp")
	}

	return nil
}

// Export exports telemetry data to Telegraf
func (t *TelegrafExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !t.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Metrics) > 0 {
		return t.ExportMetrics(ctx, data.Metrics)
	}

	return &ExportResult{Success: true}, nil
}

// ExportMetrics exports metrics to Telegraf in InfluxDB line protocol
func (t *TelegrafExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !t.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !t.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to InfluxDB line protocol
	var buf bytes.Buffer
	for _, m := range metrics {
		line := t.buildLineProtocol(m)
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	var result *ExportResult
	var err error

	switch t.config.Protocol {
	case "http", "https":
		result, err = t.sendHTTP(ctx, buf.Bytes())
	case "udp":
		result, err = t.sendUDP(buf.Bytes())
	default:
		result, err = t.sendHTTP(ctx, buf.Bytes())
	}

	if result != nil {
		result.Duration = time.Since(startTime)
		result.ItemsExported = len(metrics)
	}

	if err != nil {
		t.RecordError(err)
		return result, err
	}

	t.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces is not directly supported by Telegraf
func (t *TelegrafExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("telegraf does not natively support traces, use OpenTelemetry input plugin")
}

// ExportLogs exports logs as metrics (Telegraf can parse them)
func (t *TelegrafExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	// Convert logs to line protocol format
	if !t.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !t.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	var buf bytes.Buffer
	for _, l := range logs {
		// Create a metric-like representation of the log
		tags := make(map[string]string)
		tags["level"] = string(l.Level)
		if l.Source != "" {
			tags["source"] = l.Source
		}
		for k, v := range t.config.GlobalTags {
			tags[k] = v
		}

		tagStr := t.buildTags(tags)
		timestamp := t.formatTimestamp(l.Timestamp)

		// Escape message for line protocol
		escapedMsg := strings.ReplaceAll(l.Message, `"`, `\"`)
		escapedMsg = strings.ReplaceAll(escapedMsg, `\`, `\\`)

		line := fmt.Sprintf("logs,%s message=%q %s\n", tagStr, escapedMsg, timestamp)
		buf.WriteString(line)
	}

	var result *ExportResult
	var err error

	switch t.config.Protocol {
	case "http", "https":
		result, err = t.sendHTTP(ctx, buf.Bytes())
	case "udp":
		result, err = t.sendUDP(buf.Bytes())
	default:
		result, err = t.sendHTTP(ctx, buf.Bytes())
	}

	if result != nil {
		result.Duration = time.Since(startTime)
		result.ItemsExported = len(logs)
	}

	if err != nil {
		t.RecordError(err)
		return result, err
	}

	t.RecordSuccess(result.BytesSent)
	return result, nil
}

// Health checks the health of Telegraf
func (t *TelegrafExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !t.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	switch t.config.Protocol {
	case "http", "https":
		// Try to connect to Telegraf HTTP listener
		req, err := http.NewRequestWithContext(ctx, "HEAD", t.config.Address, nil)
		if err != nil {
			return &HealthStatus{
				Healthy:   false,
				Message:   err.Error(),
				LastCheck: time.Now(),
				LastError: err,
			}, nil
		}

		resp, err := t.httpClient.Do(req)
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
			Healthy:   resp.StatusCode < 500,
			Message:   fmt.Sprintf("status: %d", resp.StatusCode),
			LastCheck: time.Now(),
			Latency:   time.Since(startTime),
		}, nil

	case "udp":
		// UDP is connectionless, just verify address resolution
		return &HealthStatus{
			Healthy:   t.udpConn != nil,
			Message:   "UDP socket configured",
			LastCheck: time.Now(),
			Details: map[string]interface{}{
				"address": t.config.Address,
			},
		}, nil
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   "configured",
		LastCheck: time.Now(),
	}, nil
}

// Close closes the Telegraf exporter
func (t *TelegrafExporter) Close(ctx context.Context) error {
	if t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}
	if t.udpConn != nil {
		_ = t.udpConn.Close()
	}
	t.SetInitialized(false)
	t.Logger().Info("Telegraf exporter closed")
	return nil
}

// buildLineProtocol builds an InfluxDB line protocol string
func (t *TelegrafExporter) buildLineProtocol(m Metric) string {
	// Escape measurement name
	measurement := t.escapeMeasurement(m.Name)

	// Build tags (including global tags)
	allTags := make(map[string]string)
	for k, v := range t.config.GlobalTags {
		allTags[k] = v
	}
	for k, v := range m.Tags {
		allTags[k] = v
	}
	tagStr := t.buildTags(allTags)

	// Build fields
	fieldStr := fmt.Sprintf("value=%f", m.Value)
	if m.Unit != "" {
		fieldStr += fmt.Sprintf(",unit=%q", m.Unit)
	}

	// Timestamp
	timestamp := t.formatTimestamp(m.Timestamp)

	if tagStr != "" {
		return fmt.Sprintf("%s,%s %s %s", measurement, tagStr, fieldStr, timestamp)
	}
	return fmt.Sprintf("%s %s %s", measurement, fieldStr, timestamp)
}

// buildTags builds the tag string
func (t *TelegrafExporter) buildTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}

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
				t.escapeTag(k),
				t.escapeTag(v),
			))
		}
	}

	return strings.Join(parts, ",")
}

// formatTimestamp formats timestamp based on precision
func (t *TelegrafExporter) formatTimestamp(ts time.Time) string {
	switch t.config.Precision {
	case "s":
		return fmt.Sprintf("%d", ts.Unix())
	case "ms":
		return fmt.Sprintf("%d", ts.UnixMilli())
	case "us":
		return fmt.Sprintf("%d", ts.UnixMicro())
	default:
		return fmt.Sprintf("%d", ts.UnixNano())
	}
}

// sendHTTP sends data via HTTP
func (t *TelegrafExporter) sendHTTP(ctx context.Context, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", t.config.Address, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	// Add authentication
	if t.config.Username != "" && t.config.Password != "" {
		req.SetBasicAuth(t.config.Username, t.config.Password)
	}

	// Add custom headers
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("telegraf error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// sendUDP sends data via UDP
func (t *TelegrafExporter) sendUDP(body []byte) (*ExportResult, error) {
	if t.udpConn == nil {
		return &ExportResult{Success: false, Error: fmt.Errorf("UDP connection not initialized")}, nil
	}

	n, err := t.udpConn.Write(body)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(n),
	}, nil
}

// escapeMeasurement escapes measurement name for line protocol
func (t *TelegrafExporter) escapeMeasurement(s string) string {
	s = strings.ReplaceAll(s, ",", `\,`)
	s = strings.ReplaceAll(s, " ", `\ `)
	return s
}

// escapeTag escapes tag key/value for line protocol
func (t *TelegrafExporter) escapeTag(s string) string {
	s = strings.ReplaceAll(s, ",", `\,`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, " ", `\ `)
	return s
}
