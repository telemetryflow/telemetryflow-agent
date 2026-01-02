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
	"sync"
	"time"

	"go.uber.org/zap"
)

// PrometheusConfig contains Prometheus Remote Write configuration
type PrometheusConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	Endpoint       string            `mapstructure:"endpoint"`
	JobName        string            `mapstructure:"job_name"`
	Username       string            `mapstructure:"username"`
	Password       string            `mapstructure:"password"`
	BearerToken    string            `mapstructure:"bearer_token"`
	TLSEnabled     bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify  bool              `mapstructure:"tls_skip_verify"`
	TLSCertFile    string            `mapstructure:"tls_cert_file"`
	TLSKeyFile     string            `mapstructure:"tls_key_file"`
	TLSCAFile      string            `mapstructure:"tls_ca_file"`
	Timeout        time.Duration     `mapstructure:"timeout"`
	BatchSize      int               `mapstructure:"batch_size"`
	FlushInterval  time.Duration     `mapstructure:"flush_interval"`
	Headers        map[string]string `mapstructure:"headers"`
	ExternalLabels map[string]string `mapstructure:"external_labels"`
}

// PrometheusExporter exports metrics to Prometheus Remote Write endpoint
type PrometheusExporter struct {
	*BaseExporter
	config     PrometheusConfig
	httpClient *http.Client

	mu     sync.Mutex
	buffer []Metric
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(config PrometheusConfig, logger *zap.Logger) *PrometheusExporter {
	return &PrometheusExporter{
		BaseExporter: NewBaseExporter(
			"prometheus",
			"metrics",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
		buffer: make([]Metric, 0, config.BatchSize),
	}
}

// Init initializes the Prometheus exporter
func (p *PrometheusExporter) Init(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	if err := p.Validate(); err != nil {
		return err
	}

	// Set defaults
	if p.config.Timeout == 0 {
		p.config.Timeout = 30 * time.Second
	}
	if p.config.BatchSize == 0 {
		p.config.BatchSize = 1000
	}
	if p.config.FlushInterval == 0 {
		p.config.FlushInterval = 10 * time.Second
	}
	if p.config.JobName == "" {
		p.config.JobName = "telemetryflow-agent"
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	p.httpClient = &http.Client{
		Transport: transport,
		Timeout:   p.config.Timeout,
	}

	p.SetInitialized(true)
	p.Logger().Info("Prometheus exporter initialized",
		zap.String("endpoint", p.config.Endpoint),
		zap.String("job", p.config.JobName),
	)

	return nil
}

// Validate validates the Prometheus configuration
func (p *PrometheusExporter) Validate() error {
	if !p.config.Enabled {
		return nil
	}

	if p.config.Endpoint == "" {
		return NewValidationError("prometheus", "endpoint", "endpoint is required")
	}

	parsedURL, err := url.Parse(p.config.Endpoint)
	if err != nil {
		return NewValidationError("prometheus", "endpoint", fmt.Sprintf("invalid URL: %v", err))
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return NewValidationError("prometheus", "endpoint", "scheme must be http or https")
	}

	return nil
}

// Export exports telemetry data to Prometheus
func (p *PrometheusExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !p.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Metrics) == 0 {
		return &ExportResult{Success: true}, nil
	}

	return p.ExportMetrics(ctx, data.Metrics)
}

// ExportMetrics exports metrics to Prometheus Remote Write
func (p *PrometheusExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !p.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !p.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert metrics to Prometheus format and send
	payload := p.buildPrometheusPayload(metrics)

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.Endpoint, bytes.NewReader(payload))
	if err != nil {
		p.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	// Add authentication
	if p.config.Username != "" && p.config.Password != "" {
		req.SetBasicAuth(p.config.Username, p.config.Password)
	} else if p.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.config.BearerToken)
	}

	// Add custom headers
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.RecordError(err)
		return &ExportResult{Success: false, Error: err, Duration: time.Since(startTime)}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("prometheus remote write failed: status=%d body=%s", resp.StatusCode, string(body))
		p.RecordError(err)
		return &ExportResult{Success: false, Error: err, Duration: time.Since(startTime)}, err
	}

	bytesSent := int64(len(payload))
	p.RecordSuccess(bytesSent)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
		BytesSent:     bytesSent,
		Duration:      time.Since(startTime),
	}, nil
}

// ExportTraces is not supported by Prometheus
func (p *PrometheusExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("prometheus does not support traces export")
}

// ExportLogs is not supported by Prometheus
func (p *PrometheusExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("prometheus does not support logs export")
}

// Health checks the health of the Prometheus endpoint
func (p *PrometheusExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !p.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Try to connect to the endpoint
	req, err := http.NewRequestWithContext(ctx, "HEAD", p.config.Endpoint, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	resp, err := p.httpClient.Do(req)
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
		Healthy:   true,
		Message:   "connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"status_code": resp.StatusCode,
		},
	}, nil
}

// Close closes the Prometheus exporter
func (p *PrometheusExporter) Close(ctx context.Context) error {
	// Flush any remaining metrics
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.buffer) > 0 && p.IsInitialized() {
		if _, err := p.ExportMetrics(ctx, p.buffer); err != nil {
			p.Logger().Warn("Failed to flush remaining metrics", zap.Error(err))
		}
		p.buffer = p.buffer[:0]
	}

	if p.httpClient != nil {
		p.httpClient.CloseIdleConnections()
	}

	p.SetInitialized(false)
	p.Logger().Info("Prometheus exporter closed")
	return nil
}

// buildPrometheusPayload builds the Prometheus Remote Write payload
// In production, this would use proper protobuf encoding with snappy compression
func (p *PrometheusExporter) buildPrometheusPayload(metrics []Metric) []byte {
	// This is a simplified text format representation
	// In production, use github.com/prometheus/prometheus/prompb for proper protobuf
	var buf bytes.Buffer

	for _, m := range metrics {
		// Build label string
		labels := make([]string, 0, len(m.Tags)+1)
		labels = append(labels, fmt.Sprintf(`__name__="%s"`, escapePrometheusValue(m.Name)))

		// Add job label
		labels = append(labels, fmt.Sprintf(`job="%s"`, p.config.JobName))

		// Add external labels
		for k, v := range p.config.ExternalLabels {
			labels = append(labels, fmt.Sprintf(`%s="%s"`, escapePrometheusName(k), escapePrometheusValue(v)))
		}

		// Add metric tags
		for k, v := range m.Tags {
			labels = append(labels, fmt.Sprintf(`%s="%s"`, escapePrometheusName(k), escapePrometheusValue(v)))
		}

		sort.Strings(labels)
		timestamp := m.Timestamp.UnixMilli()

		buf.WriteString(fmt.Sprintf("{%s} %f %d\n", strings.Join(labels, ","), m.Value, timestamp))
	}

	return buf.Bytes()
}

// escapePrometheusName escapes a Prometheus label name
func escapePrometheusName(s string) string {
	// Replace invalid characters with underscores
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)

	// Ensure it doesn't start with a digit
	if len(result) > 0 && result[0] >= '0' && result[0] <= '9' {
		result = "_" + result
	}

	return result
}

// escapePrometheusValue escapes a Prometheus label value
func escapePrometheusValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
