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
	"time"

	"go.uber.org/zap"
)

// NetdataConfig contains Netdata Cloud integration configuration
type NetdataConfig struct {
	Enabled          bool              `mapstructure:"enabled"`
	APIToken         string            `mapstructure:"api_token"`
	Endpoint         string            `mapstructure:"endpoint"`
	SpaceID          string            `mapstructure:"space_id"`
	RoomID           string            `mapstructure:"room_id"`
	ClaimToken       string            `mapstructure:"claim_token"`
	ClaimRooms       string            `mapstructure:"claim_rooms"`
	MetricsEndpoint  string            `mapstructure:"metrics_endpoint"`
	TLSSkipVerify    bool              `mapstructure:"tls_skip_verify"`
	Timeout          time.Duration     `mapstructure:"timeout"`
	BatchSize        int               `mapstructure:"batch_size"`
	FlushInterval    time.Duration     `mapstructure:"flush_interval"`
	HostnameOverride string            `mapstructure:"hostname_override"`
	Tags             map[string]string `mapstructure:"tags"`
	Headers          map[string]string `mapstructure:"headers"`
}

// NetdataExporter exports telemetry data to Netdata Cloud
type NetdataExporter struct {
	*BaseExporter
	config     NetdataConfig
	httpClient *http.Client
}

// NewNetdataExporter creates a new Netdata exporter
func NewNetdataExporter(config NetdataConfig, logger *zap.Logger) *NetdataExporter {
	return &NetdataExporter{
		BaseExporter: NewBaseExporter(
			"netdata",
			"monitoring",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Netdata exporter
func (n *NetdataExporter) Init(ctx context.Context) error {
	if !n.config.Enabled {
		return nil
	}

	if err := n.Validate(); err != nil {
		return err
	}

	// Set defaults
	if n.config.Endpoint == "" {
		n.config.Endpoint = "https://api.netdata.cloud"
	}
	if n.config.MetricsEndpoint == "" {
		n.config.MetricsEndpoint = fmt.Sprintf("%s/api/v1/data", n.config.Endpoint)
	}
	if n.config.Timeout == 0 {
		n.config.Timeout = 30 * time.Second
	}
	if n.config.BatchSize == 0 {
		n.config.BatchSize = 1000
	}
	if n.config.FlushInterval == 0 {
		n.config.FlushInterval = 10 * time.Second
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if n.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	n.httpClient = &http.Client{
		Transport: transport,
		Timeout:   n.config.Timeout,
	}

	n.SetInitialized(true)
	n.Logger().Info("Netdata exporter initialized",
		zap.String("endpoint", n.config.Endpoint),
		zap.String("spaceId", n.config.SpaceID),
	)

	return nil
}

// Validate validates the Netdata configuration
func (n *NetdataConfig) Validate() error {
	// API token is required for Netdata Cloud
	return nil
}

// Validate validates the Netdata configuration
func (n *NetdataExporter) Validate() error {
	if !n.config.Enabled {
		return nil
	}
	// Netdata self-hosted may not require API token
	return nil
}

// Export exports telemetry data to Netdata
func (n *NetdataExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	if len(data.Metrics) > 0 {
		result, err := n.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	// Netdata Cloud primarily focuses on metrics
	// Logs and traces are not natively supported

	return &totalResult, totalResult.Error
}

// ExportMetrics exports metrics to Netdata
func (n *NetdataExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}
	if !n.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Netdata format
	ndMetrics := make([]map[string]interface{}, 0, len(metrics))
	for _, m := range metrics {
		metric := map[string]interface{}{
			"id":        m.Name,
			"value":     m.Value,
			"timestamp": m.Timestamp.UnixMilli(),
			"type":      string(m.Type),
		}
		if len(m.Tags) > 0 {
			metric["labels"] = m.Tags
		}
		for k, v := range n.config.Tags {
			if metric["labels"] == nil {
				metric["labels"] = make(map[string]string)
			}
			metric["labels"].(map[string]string)[k] = v
		}
		ndMetrics = append(ndMetrics, metric)
	}

	payload := map[string]interface{}{
		"metrics": ndMetrics,
	}
	if n.config.SpaceID != "" {
		payload["space_id"] = n.config.SpaceID
	}
	if n.config.RoomID != "" {
		payload["room_id"] = n.config.RoomID
	}
	if n.config.HostnameOverride != "" {
		payload["hostname"] = n.config.HostnameOverride
	}

	body, err := json.Marshal(payload)
	if err != nil {
		n.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := n.sendRequest(ctx, "POST", n.config.MetricsEndpoint, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(metrics)

	if err != nil {
		n.RecordError(err)
		return result, err
	}

	n.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportTraces is not supported by Netdata
func (n *NetdataExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return &ExportResult{
		Success:       false,
		Error:         fmt.Errorf("traces not supported by Netdata"),
		ItemsExported: 0,
	}, nil
}

// ExportLogs is not supported by Netdata
func (n *NetdataExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return &ExportResult{
		Success:       false,
		Error:         fmt.Errorf("logs not supported by Netdata"),
		ItemsExported: 0,
	}, nil
}

// Health checks the health of the Netdata integration
func (n *NetdataExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !n.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	healthURL := fmt.Sprintf("%s/api/v1/health", n.config.Endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	if n.config.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.config.APIToken)
	}

	resp, err := n.httpClient.Do(req)
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
		Message:   "Netdata API accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint": n.config.Endpoint,
			"spaceId":  n.config.SpaceID,
		},
	}, nil
}

// Close closes the Netdata exporter
func (n *NetdataExporter) Close(ctx context.Context) error {
	if n.httpClient != nil {
		n.httpClient.CloseIdleConnections()
	}
	n.SetInitialized(false)
	n.Logger().Info("Netdata exporter closed")
	return nil
}

// sendRequest sends an HTTP request to Netdata
func (n *NetdataExporter) sendRequest(ctx context.Context, method, url string, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")
	if n.config.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.config.APIToken)
	}

	for k, v := range n.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("netdata API error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
