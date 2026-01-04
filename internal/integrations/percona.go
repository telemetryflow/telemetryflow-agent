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

// PerconaConfig contains Percona PMM integration configuration
type PerconaConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	ServerURL      string            `mapstructure:"server_url"`
	APIKey         string            `mapstructure:"api_key"`
	Username       string            `mapstructure:"username"`
	Password       string            `mapstructure:"password"`
	NodeID         string            `mapstructure:"node_id"`
	NodeName       string            `mapstructure:"node_name"`
	NodeType       string            `mapstructure:"node_type"`
	Environment    string            `mapstructure:"environment"`
	Cluster        string            `mapstructure:"cluster"`
	ReplicationSet string            `mapstructure:"replication_set"`
	CustomLabels   map[string]string `mapstructure:"custom_labels"`
	TLSEnabled     bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify  bool              `mapstructure:"tls_skip_verify"`
	Timeout        time.Duration     `mapstructure:"timeout"`
	BatchSize      int               `mapstructure:"batch_size"`
	FlushInterval  time.Duration     `mapstructure:"flush_interval"`
	Headers        map[string]string `mapstructure:"headers"`
}

// PerconaExporter exports telemetry data to Percona PMM
type PerconaExporter struct {
	*BaseExporter
	config     PerconaConfig
	httpClient *http.Client
}

// Percona PMM metric payload
type perconaMetricBatch struct {
	Metrics []perconaMetric `json:"metrics"`
}

type perconaMetric struct {
	MetricName string            `json:"metric_name"`
	Type       string            `json:"type"`
	Value      float64           `json:"value"`
	Timestamp  int64             `json:"timestamp"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// NewPerconaExporter creates a new Percona exporter
func NewPerconaExporter(config PerconaConfig, logger *zap.Logger) *PerconaExporter {
	return &PerconaExporter{
		BaseExporter: NewBaseExporter(
			"percona",
			"database",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Percona exporter
func (p *PerconaExporter) Init(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	if err := p.Validate(); err != nil {
		return err
	}

	// Set defaults
	if p.config.NodeType == "" {
		p.config.NodeType = "generic"
	}
	if p.config.Timeout == 0 {
		p.config.Timeout = 30 * time.Second
	}
	if p.config.BatchSize == 0 {
		p.config.BatchSize = 1000
	}
	if p.config.FlushInterval == 0 {
		p.config.FlushInterval = 10 * time.Second
	}

	// Create HTTP client
	p.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: p.config.Timeout,
	}

	p.SetInitialized(true)
	p.Logger().Info("Percona PMM exporter initialized",
		zap.String("serverURL", p.config.ServerURL),
		zap.String("nodeID", p.config.NodeID),
		zap.String("nodeType", p.config.NodeType),
	)

	return nil
}

// Validate validates the Percona configuration
func (p *PerconaConfig) Validate() error {
	if !p.Enabled {
		return nil
	}

	if p.ServerURL == "" {
		return NewValidationError("percona", "server_url", "server_url is required")
	}

	// Either API key or username/password required
	if p.APIKey == "" && (p.Username == "" || p.Password == "") {
		return NewValidationError("percona", "auth", "api_key or username/password is required")
	}

	return nil
}

// Validate on exporter delegates to config
func (p *PerconaExporter) Validate() error {
	return p.config.Validate()
}

// Export exports telemetry data to Percona PMM
func (p *PerconaExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !p.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Metrics) > 0 {
		return p.ExportMetrics(ctx, data.Metrics)
	}

	return &ExportResult{Success: true}, nil
}

// ExportMetrics exports metrics to Percona PMM
func (p *PerconaExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !p.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !p.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Percona format
	pmmMetrics := make([]perconaMetric, 0, len(metrics))
	for _, m := range metrics {
		labels := make(map[string]string)
		// Add node labels
		if p.config.NodeID != "" {
			labels["node_id"] = p.config.NodeID
		}
		if p.config.NodeName != "" {
			labels["node_name"] = p.config.NodeName
		}
		if p.config.NodeType != "" {
			labels["node_type"] = p.config.NodeType
		}
		if p.config.Environment != "" {
			labels["environment"] = p.config.Environment
		}
		if p.config.Cluster != "" {
			labels["cluster"] = p.config.Cluster
		}
		if p.config.ReplicationSet != "" {
			labels["replication_set"] = p.config.ReplicationSet
		}
		// Add custom labels
		for k, v := range p.config.CustomLabels {
			labels[k] = v
		}
		// Add metric tags
		for k, v := range m.Tags {
			labels[k] = v
		}

		pmmMetric := perconaMetric{
			MetricName: m.Name,
			Type:       string(m.Type),
			Value:      m.Value,
			Timestamp:  m.Timestamp.UnixMilli(),
			Labels:     labels,
		}
		pmmMetrics = append(pmmMetrics, pmmMetric)
	}

	batch := perconaMetricBatch{Metrics: pmmMetrics}
	body, err := json.Marshal(batch)
	if err != nil {
		p.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := p.sendRequest(ctx, "/v1/metrics", body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		p.RecordError(err)
		return result, err
	}

	p.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces is not supported by Percona PMM
func (p *PerconaExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("percona PMM does not support traces export")
}

// ExportLogs is not supported by Percona PMM (use VictoriaMetrics/Loki)
func (p *PerconaExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("percona PMM does not directly support logs export")
}

// Health checks the health of Percona PMM
func (p *PerconaExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !p.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check PMM server status
	statusURL := p.config.ServerURL + "/v1/Settings/Get"
	req, err := http.NewRequestWithContext(ctx, "POST", statusURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	p.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

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
		Healthy:   resp.StatusCode == http.StatusOK,
		Message:   fmt.Sprintf("status: %d", resp.StatusCode),
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"node_id":   p.config.NodeID,
			"node_type": p.config.NodeType,
		},
	}, nil
}

// Close closes the Percona exporter
func (p *PerconaExporter) Close(ctx context.Context) error {
	if p.httpClient != nil {
		p.httpClient.CloseIdleConnections()
	}
	p.SetInitialized(false)
	p.Logger().Info("Percona PMM exporter closed")
	return nil
}

// sendRequest sends a request to Percona PMM
func (p *PerconaExporter) sendRequest(ctx context.Context, path string, body []byte) (*ExportResult, error) {
	url := p.config.ServerURL + path

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	p.setAuthHeaders(req)

	// Add custom headers
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("percona PMM error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// setAuthHeaders sets authentication headers
func (p *PerconaExporter) setAuthHeaders(req *http.Request) {
	if p.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	} else if p.config.Username != "" && p.config.Password != "" {
		req.SetBasicAuth(p.config.Username, p.config.Password)
	}
}
