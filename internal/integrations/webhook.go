// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// WebhookConfig contains Webhook integration configuration
type WebhookConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	URL             string            `mapstructure:"url"`
	Method          string            `mapstructure:"method"`
	Secret          string            `mapstructure:"secret"`
	SignatureHeader string            `mapstructure:"signature_header"`
	ContentType     string            `mapstructure:"content_type"`
	TLSEnabled      bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify   bool              `mapstructure:"tls_skip_verify"`
	Timeout         time.Duration     `mapstructure:"timeout"`
	RetryCount      int               `mapstructure:"retry_count"`
	RetryDelay      time.Duration     `mapstructure:"retry_delay"`
	BatchSize       int               `mapstructure:"batch_size"`
	FlushInterval   time.Duration     `mapstructure:"flush_interval"`
	Headers         map[string]string `mapstructure:"headers"`
	PayloadTemplate string            `mapstructure:"payload_template"`
}

// WebhookExporter exports telemetry data via webhooks
type WebhookExporter struct {
	*BaseExporter
	config     WebhookConfig
	httpClient *http.Client
}

// WebhookPayload represents the webhook payload
type WebhookPayload struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	AgentID   string                 `json:"agent_id,omitempty"`
	Hostname  string                 `json:"hostname,omitempty"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewWebhookExporter creates a new Webhook exporter
func NewWebhookExporter(config WebhookConfig, logger *zap.Logger) *WebhookExporter {
	return &WebhookExporter{
		BaseExporter: NewBaseExporter(
			"webhook",
			"custom",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the Webhook exporter
func (w *WebhookExporter) Init(ctx context.Context) error {
	if !w.config.Enabled {
		return nil
	}

	if err := w.Validate(); err != nil {
		return err
	}

	// Set defaults
	if w.config.Method == "" {
		w.config.Method = "POST"
	}
	if w.config.ContentType == "" {
		w.config.ContentType = "application/json"
	}
	if w.config.SignatureHeader == "" {
		w.config.SignatureHeader = "X-Webhook-Signature"
	}
	if w.config.Timeout == 0 {
		w.config.Timeout = 30 * time.Second
	}
	if w.config.RetryCount == 0 {
		w.config.RetryCount = 3
	}
	if w.config.RetryDelay == 0 {
		w.config.RetryDelay = time.Second
	}
	if w.config.BatchSize == 0 {
		w.config.BatchSize = 100
	}
	if w.config.FlushInterval == 0 {
		w.config.FlushInterval = 10 * time.Second
	}

	// Create HTTP client
	w.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: w.config.Timeout,
	}

	w.SetInitialized(true)
	w.Logger().Info("Webhook exporter initialized",
		zap.String("url", w.config.URL),
		zap.String("method", w.config.Method),
	)

	return nil
}

// Validate validates the Webhook configuration
func (w *WebhookExporter) Validate() error {
	if !w.config.Enabled {
		return nil
	}

	if w.config.URL == "" {
		return NewValidationError("webhook", "url", "url is required")
	}

	validMethods := map[string]bool{"POST": true, "PUT": true, "PATCH": true}
	if w.config.Method != "" && !validMethods[w.config.Method] {
		return NewValidationError("webhook", "method", "method must be POST, PUT, or PATCH")
	}

	return nil
}

// Export exports telemetry data via webhook
func (w *WebhookExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !w.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := w.ExportMetrics(ctx, data.Metrics)
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
		result, err := w.ExportTraces(ctx, data.Traces)
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
		result, err := w.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics via webhook
func (w *WebhookExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !w.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !w.IsInitialized() {
		return nil, ErrNotInitialized
	}

	payload := WebhookPayload{
		Type:      "metrics",
		Timestamp: time.Now(),
		Data:      metrics,
	}

	return w.sendWebhook(ctx, payload, len(metrics))
}

// ExportTraces exports traces via webhook
func (w *WebhookExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !w.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !w.IsInitialized() {
		return nil, ErrNotInitialized
	}

	payload := WebhookPayload{
		Type:      "traces",
		Timestamp: time.Now(),
		Data:      traces,
	}

	return w.sendWebhook(ctx, payload, len(traces))
}

// ExportLogs exports logs via webhook
func (w *WebhookExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !w.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !w.IsInitialized() {
		return nil, ErrNotInitialized
	}

	payload := WebhookPayload{
		Type:      "logs",
		Timestamp: time.Now(),
		Data:      logs,
	}

	return w.sendWebhook(ctx, payload, len(logs))
}

// Health checks the health of the webhook endpoint
func (w *WebhookExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !w.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Send a health check request
	req, err := http.NewRequestWithContext(ctx, "HEAD", w.config.URL, nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			LastError: err,
		}, nil
	}

	resp, err := w.httpClient.Do(req)
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
}

// Close closes the Webhook exporter
func (w *WebhookExporter) Close(ctx context.Context) error {
	if w.httpClient != nil {
		w.httpClient.CloseIdleConnections()
	}
	w.SetInitialized(false)
	w.Logger().Info("Webhook exporter closed")
	return nil
}

// sendWebhook sends data to the webhook endpoint with retry
func (w *WebhookExporter) sendWebhook(ctx context.Context, payload WebhookPayload, itemCount int) (*ExportResult, error) {
	startTime := time.Now()

	body, err := json.Marshal(payload)
	if err != nil {
		w.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	var lastErr error
	for attempt := 0; attempt <= w.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return &ExportResult{Success: false, Error: ctx.Err()}, ctx.Err()
			case <-time.After(w.config.RetryDelay):
			}
		}

		result, err := w.sendRequest(ctx, body)
		if err == nil {
			result.Duration = time.Since(startTime)
			result.ItemsExported = itemCount
			result.RetryCount = attempt
			w.RecordSuccess(result.BytesSent)
			return result, nil
		}

		lastErr = err
		w.Logger().Debug("Webhook request failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)
	}

	w.RecordError(lastErr)
	return &ExportResult{
		Success:    false,
		Error:      lastErr,
		Duration:   time.Since(startTime),
		RetryCount: w.config.RetryCount,
	}, lastErr
}

// sendRequest sends a single request to the webhook
func (w *WebhookExporter) sendRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, w.config.Method, w.config.URL, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", w.config.ContentType)
	req.Header.Set("User-Agent", "TelemetryFlow-Agent/1.0")

	// Add signature if secret is configured
	if w.config.Secret != "" {
		signature := w.signPayload(body)
		req.Header.Set(w.config.SignatureHeader, signature)
	}

	// Add custom headers
	for k, v := range w.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("webhook error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}

// signPayload creates an HMAC-SHA256 signature for the payload
func (w *WebhookExporter) signPayload(body []byte) string {
	mac := hmac.New(sha256.New, []byte(w.config.Secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
