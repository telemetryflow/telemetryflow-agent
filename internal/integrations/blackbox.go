// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// BlackboxConfig contains Prometheus Blackbox Exporter integration configuration
type BlackboxConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	Endpoint       string            `mapstructure:"endpoint"`
	Module         string            `mapstructure:"module"`
	Targets        []BlackboxTarget  `mapstructure:"targets"`
	ScrapeInterval time.Duration     `mapstructure:"scrape_interval"`
	Timeout        time.Duration     `mapstructure:"timeout"`
	TLSEnabled     bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify  bool              `mapstructure:"tls_skip_verify"`
	Username       string            `mapstructure:"username"`
	Password       string            `mapstructure:"password"`
	Headers        map[string]string `mapstructure:"headers"`
	Labels         map[string]string `mapstructure:"labels"`
}

// BlackboxTarget represents a target to probe
type BlackboxTarget struct {
	Name   string            `mapstructure:"name"`
	Target string            `mapstructure:"target"`
	Module string            `mapstructure:"module"`
	Labels map[string]string `mapstructure:"labels"`
}

// BlackboxExporter integrates with Prometheus Blackbox Exporter for synthetic monitoring
type BlackboxExporter struct {
	*BaseExporter
	config     BlackboxConfig
	httpClient *http.Client
}

// BlackboxProbeResult represents the result of a probe
type BlackboxProbeResult struct {
	Target        string            `json:"target"`
	Module        string            `json:"module"`
	Success       bool              `json:"success"`
	Duration      time.Duration     `json:"duration"`
	DNSLookup     time.Duration     `json:"dns_lookup,omitempty"`
	TCPConnect    time.Duration     `json:"tcp_connect,omitempty"`
	TLSHandshake  time.Duration     `json:"tls_handshake,omitempty"`
	FirstByte     time.Duration     `json:"first_byte,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// NewBlackboxExporter creates a new Blackbox exporter
func NewBlackboxExporter(config BlackboxConfig, logger *zap.Logger) *BlackboxExporter {
	return &BlackboxExporter{
		BaseExporter: NewBaseExporter(
			"blackbox",
			"synthetic",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Blackbox exporter
func (b *BlackboxExporter) Init(ctx context.Context) error {
	if !b.config.Enabled {
		return nil
	}

	if err := b.Validate(); err != nil {
		return err
	}

	// Set defaults
	if b.config.Module == "" {
		b.config.Module = "http_2xx"
	}
	if b.config.ScrapeInterval == 0 {
		b.config.ScrapeInterval = 30 * time.Second
	}
	if b.config.Timeout == 0 {
		b.config.Timeout = 10 * time.Second
	}

	// Create HTTP client
	b.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: b.config.Timeout,
	}

	b.SetInitialized(true)
	b.Logger().Info("Blackbox exporter initialized",
		zap.String("endpoint", b.config.Endpoint),
		zap.String("module", b.config.Module),
		zap.Int("targets", len(b.config.Targets)),
	)

	return nil
}

// Validate validates the Blackbox configuration
func (b *BlackboxExporter) Validate() error {
	if !b.config.Enabled {
		return nil
	}

	if b.config.Endpoint == "" {
		return NewValidationError("blackbox", "endpoint", "endpoint is required")
	}

	if len(b.config.Targets) == 0 {
		return NewValidationError("blackbox", "targets", "at least one target is required")
	}

	for i, target := range b.config.Targets {
		if target.Target == "" {
			return NewValidationError("blackbox", fmt.Sprintf("targets[%d].target", i), "target URL is required")
		}
	}

	return nil
}

// Export exports probe results as metrics
func (b *BlackboxExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !b.config.Enabled {
		return nil, ErrNotEnabled
	}

	// Blackbox exporter is a pull-based system; we probe targets and convert results to metrics
	results, err := b.ProbeAll(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	// Convert probe results to metrics
	metrics := b.resultsToMetrics(results)
	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(results),
	}, nil
}

// ExportMetrics exports metrics (not typically used as Blackbox is pull-based)
func (b *BlackboxExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	// Blackbox is a pull-based exporter, metrics come from probes
	return nil, fmt.Errorf("blackbox exporter generates metrics via probes, not by exporting")
}

// ExportTraces is not supported by Blackbox
func (b *BlackboxExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("blackbox does not support traces export")
}

// ExportLogs is not supported by Blackbox
func (b *BlackboxExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("blackbox does not support logs export")
}

// ProbeAll probes all configured targets
func (b *BlackboxExporter) ProbeAll(ctx context.Context) ([]BlackboxProbeResult, error) {
	if !b.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !b.IsInitialized() {
		return nil, ErrNotInitialized
	}

	results := make([]BlackboxProbeResult, 0, len(b.config.Targets))

	for _, target := range b.config.Targets {
		result, err := b.Probe(ctx, target)
		if err != nil {
			b.Logger().Warn("Probe failed",
				zap.String("target", target.Target),
				zap.Error(err),
			)
			// Still add a failed result
			results = append(results, BlackboxProbeResult{
				Target:    target.Target,
				Module:    target.Module,
				Success:   false,
				Labels:    target.Labels,
				Timestamp: time.Now(),
			})
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}

// Probe probes a single target via the Blackbox exporter
func (b *BlackboxExporter) Probe(ctx context.Context, target BlackboxTarget) (*BlackboxProbeResult, error) {
	module := target.Module
	if module == "" {
		module = b.config.Module
	}

	// Build probe URL
	probeURL := fmt.Sprintf("%s/probe?target=%s&module=%s",
		b.config.Endpoint,
		url.QueryEscape(target.Target),
		url.QueryEscape(module),
	)

	startTime := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication
	if b.config.Username != "" && b.config.Password != "" {
		req.SetBasicAuth(b.config.Username, b.config.Password)
	}

	// Add custom headers
	for k, v := range b.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(startTime)

	// Parse Prometheus exposition format response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the probe result from Prometheus metrics
	result := &BlackboxProbeResult{
		Target:    target.Target,
		Module:    module,
		Duration:  duration,
		Labels:    target.Labels,
		Timestamp: time.Now(),
	}

	// Check if probe was successful by looking for probe_success metric
	result.Success = bytes.Contains(body, []byte("probe_success 1"))

	// Parse timing metrics from response (simplified)
	result.StatusCode = resp.StatusCode

	return result, nil
}

// Health checks the health of the Blackbox exporter
func (b *BlackboxExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !b.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check Blackbox exporter metrics endpoint
	metricsURL := b.config.Endpoint + "/metrics"
	req, err := http.NewRequestWithContext(ctx, "GET", metricsURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	if b.config.Username != "" && b.config.Password != "" {
		req.SetBasicAuth(b.config.Username, b.config.Password)
	}

	resp, err := b.httpClient.Do(req)
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
		Details: map[string]interface{}{
			"targets": len(b.config.Targets),
			"module":  b.config.Module,
		},
	}, nil
}

// Close closes the Blackbox exporter
func (b *BlackboxExporter) Close(ctx context.Context) error {
	if b.httpClient != nil {
		b.httpClient.CloseIdleConnections()
	}
	b.SetInitialized(false)
	b.Logger().Info("Blackbox exporter closed")
	return nil
}

// resultsToMetrics converts probe results to metrics
func (b *BlackboxExporter) resultsToMetrics(results []BlackboxProbeResult) []Metric {
	metrics := make([]Metric, 0, len(results)*5)

	for _, r := range results {
		baseTags := make(map[string]string)
		for k, v := range b.config.Labels {
			baseTags[k] = v
		}
		for k, v := range r.Labels {
			baseTags[k] = v
		}
		baseTags["target"] = r.Target
		baseTags["module"] = r.Module

		// probe_success
		successValue := 0.0
		if r.Success {
			successValue = 1.0
		}
		metrics = append(metrics, Metric{
			Name:      "probe_success",
			Value:     successValue,
			Type:      MetricTypeGauge,
			Timestamp: r.Timestamp,
			Tags:      baseTags,
		})

		// probe_duration_seconds
		metrics = append(metrics, Metric{
			Name:      "probe_duration_seconds",
			Value:     r.Duration.Seconds(),
			Type:      MetricTypeGauge,
			Timestamp: r.Timestamp,
			Tags:      baseTags,
			Unit:      "seconds",
		})

		// Additional timing metrics if available
		if r.DNSLookup > 0 {
			metrics = append(metrics, Metric{
				Name:      "probe_dns_lookup_time_seconds",
				Value:     r.DNSLookup.Seconds(),
				Type:      MetricTypeGauge,
				Timestamp: r.Timestamp,
				Tags:      baseTags,
				Unit:      "seconds",
			})
		}

		if r.TCPConnect > 0 {
			metrics = append(metrics, Metric{
				Name:      "probe_tcp_connect_time_seconds",
				Value:     r.TCPConnect.Seconds(),
				Type:      MetricTypeGauge,
				Timestamp: r.Timestamp,
				Tags:      baseTags,
				Unit:      "seconds",
			})
		}

		if r.StatusCode > 0 {
			metrics = append(metrics, Metric{
				Name:      "probe_http_status_code",
				Value:     float64(r.StatusCode),
				Type:      MetricTypeGauge,
				Timestamp: r.Timestamp,
				Tags:      baseTags,
			})
		}
	}

	return metrics
}

// MarshalJSON implements json.Marshaler for BlackboxProbeResult
func (r BlackboxProbeResult) MarshalJSON() ([]byte, error) {
	type Alias BlackboxProbeResult
	return json.Marshal(&struct {
		Duration     int64 `json:"duration_ms"`
		DNSLookup    int64 `json:"dns_lookup_ms,omitempty"`
		TCPConnect   int64 `json:"tcp_connect_ms,omitempty"`
		TLSHandshake int64 `json:"tls_handshake_ms,omitempty"`
		FirstByte    int64 `json:"first_byte_ms,omitempty"`
		*Alias
	}{
		Duration:     r.Duration.Milliseconds(),
		DNSLookup:    r.DNSLookup.Milliseconds(),
		TCPConnect:   r.TCPConnect.Milliseconds(),
		TLSHandshake: r.TLSHandshake.Milliseconds(),
		FirstByte:    r.FirstByte.Milliseconds(),
		Alias:        (*Alias)(&r),
	})
}
