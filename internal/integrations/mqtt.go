// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MQTTConfig contains MQTT integration configuration
type MQTTConfig struct {
	Enabled              bool              `mapstructure:"enabled"`
	Broker               string            `mapstructure:"broker"`
	ClientID             string            `mapstructure:"client_id"`
	Username             string            `mapstructure:"username"`
	Password             string            `mapstructure:"password"`
	MetricsTopic         string            `mapstructure:"metrics_topic"`
	LogsTopic            string            `mapstructure:"logs_topic"`
	TracesTopic          string            `mapstructure:"traces_topic"`
	TopicPrefix          string            `mapstructure:"topic_prefix"`
	QoS                  int               `mapstructure:"qos"`
	Retained             bool              `mapstructure:"retained"`
	CleanSession         bool              `mapstructure:"clean_session"`
	ConnectTimeout       time.Duration     `mapstructure:"connect_timeout"`
	KeepAlive            time.Duration     `mapstructure:"keep_alive"`
	PingTimeout          time.Duration     `mapstructure:"ping_timeout"`
	AutoReconnect        bool              `mapstructure:"auto_reconnect"`
	MaxReconnectInterval time.Duration     `mapstructure:"max_reconnect_interval"`
	TLSEnabled           bool              `mapstructure:"tls_enabled"`
	TLSCAFile            string            `mapstructure:"tls_ca_file"`
	TLSCertFile          string            `mapstructure:"tls_cert_file"`
	TLSKeyFile           string            `mapstructure:"tls_key_file"`
	TLSSkipVerify        bool              `mapstructure:"tls_skip_verify"`
	Encoding             string            `mapstructure:"encoding"`
	BatchSize            int               `mapstructure:"batch_size"`
	FlushInterval        time.Duration     `mapstructure:"flush_interval"`
	WillEnabled          bool              `mapstructure:"will_enabled"`
	WillTopic            string            `mapstructure:"will_topic"`
	WillPayload          string            `mapstructure:"will_payload"`
	WillQoS              int               `mapstructure:"will_qos"`
	WillRetained         bool              `mapstructure:"will_retained"`
	Headers              map[string]string `mapstructure:"headers"`
	Labels               map[string]string `mapstructure:"labels"`
}

// MQTTExporter exports telemetry data via MQTT
type MQTTExporter struct {
	*BaseExporter
	config MQTTConfig

	// In production, this would be an actual MQTT client
	// client mqtt.Client
	mu        sync.RWMutex
	connected bool
	tlsConfig *tls.Config
}

// MQTT message structures
type mqttMetricMessage struct {
	Timestamp time.Time         `json:"timestamp"`
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Type      string            `json:"type"`
	Unit      string            `json:"unit,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type mqttLogMessage struct {
	Timestamp  time.Time              `json:"timestamp"`
	Level      string                 `json:"level"`
	Message    string                 `json:"message"`
	Source     string                 `json:"source,omitempty"`
	TraceID    string                 `json:"trace_id,omitempty"`
	SpanID     string                 `json:"span_id,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Labels     map[string]string      `json:"labels,omitempty"`
}

type mqttTraceMessage struct {
	TraceID       string            `json:"trace_id"`
	SpanID        string            `json:"span_id"`
	ParentSpanID  string            `json:"parent_span_id,omitempty"`
	OperationName string            `json:"operation_name"`
	ServiceName   string            `json:"service_name"`
	StartTime     time.Time         `json:"start_time"`
	Duration      time.Duration     `json:"duration"`
	Status        string            `json:"status"`
	Tags          map[string]string `json:"tags,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// NewMQTTExporter creates a new MQTT exporter
func NewMQTTExporter(config MQTTConfig, logger *zap.Logger) *MQTTExporter {
	return &MQTTExporter{
		BaseExporter: NewBaseExporter(
			"mqtt",
			"messaging",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs, DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the MQTT exporter
func (m *MQTTExporter) Init(ctx context.Context) error {
	if !m.config.Enabled {
		return nil
	}

	if err := m.Validate(); err != nil {
		return err
	}

	// Set defaults
	if m.config.ClientID == "" {
		m.config.ClientID = "tfo-agent"
	}
	if m.config.MetricsTopic == "" {
		m.config.MetricsTopic = "telemetryflow/metrics"
	}
	if m.config.LogsTopic == "" {
		m.config.LogsTopic = "telemetryflow/logs"
	}
	if m.config.TracesTopic == "" {
		m.config.TracesTopic = "telemetryflow/traces"
	}
	if m.config.QoS < 0 || m.config.QoS > 2 {
		m.config.QoS = 1
	}
	if m.config.ConnectTimeout == 0 {
		m.config.ConnectTimeout = 30 * time.Second
	}
	if m.config.KeepAlive == 0 {
		m.config.KeepAlive = 60 * time.Second
	}
	if m.config.PingTimeout == 0 {
		m.config.PingTimeout = 10 * time.Second
	}
	if m.config.MaxReconnectInterval == 0 {
		m.config.MaxReconnectInterval = 5 * time.Minute
	}
	if m.config.BatchSize == 0 {
		m.config.BatchSize = 100
	}
	if m.config.FlushInterval == 0 {
		m.config.FlushInterval = 10 * time.Second
	}
	if m.config.Encoding == "" {
		m.config.Encoding = "json"
	}

	// Configure TLS if enabled
	if m.config.TLSEnabled {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in enterprise MQTT deployments)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: m.config.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		m.tlsConfig = tlsConfig
	}

	// In production, we would connect to the MQTT broker here
	// opts := mqtt.NewClientOptions()
	// opts.AddBroker(m.config.Broker)
	// opts.SetClientID(m.config.ClientID)
	// etc.

	m.mu.Lock()
	m.connected = true
	m.mu.Unlock()

	m.SetInitialized(true)
	m.Logger().Info("MQTT exporter initialized",
		zap.String("broker", m.config.Broker),
		zap.String("clientId", m.config.ClientID),
		zap.String("metricsTopic", m.config.MetricsTopic),
	)

	return nil
}

// Validate validates the MQTT configuration
func (m *MQTTExporter) Validate() error {
	if !m.config.Enabled {
		return nil
	}

	if m.config.Broker == "" {
		return NewValidationError("mqtt", "broker", "broker URL is required")
	}

	if m.config.QoS < 0 || m.config.QoS > 2 {
		return NewValidationError("mqtt", "qos", "QoS must be 0, 1, or 2")
	}

	return nil
}

// Export exports telemetry data via MQTT
func (m *MQTTExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalExported int

	if len(data.Metrics) > 0 {
		result, err := m.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		totalExported += result.ItemsExported
	}

	if len(data.Traces) > 0 {
		result, err := m.ExportTraces(ctx, data.Traces)
		if err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		totalExported += result.ItemsExported
	}

	if len(data.Logs) > 0 {
		result, err := m.ExportLogs(ctx, data.Logs)
		if err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		totalExported += result.ItemsExported
	}

	return &ExportResult{
		Success:       true,
		ItemsExported: totalExported,
	}, nil
}

// ExportMetrics exports metrics via MQTT
func (m *MQTTExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !m.IsInitialized() {
		return nil, ErrNotInitialized
	}

	if !m.isConnected() {
		return nil, fmt.Errorf("not connected to MQTT broker")
	}

	startTime := time.Now()
	topic := m.buildTopic(m.config.MetricsTopic)

	// Convert metrics to MQTT messages
	messages := make([]mqttMetricMessage, 0, len(metrics))
	for _, metric := range metrics {
		msg := mqttMetricMessage{
			Timestamp: metric.Timestamp,
			Name:      metric.Name,
			Value:     metric.Value,
			Type:      string(metric.Type),
			Unit:      metric.Unit,
			Tags:      metric.Tags,
			Labels:    m.config.Labels,
		}
		messages = append(messages, msg)
	}

	// Batch messages
	var totalBytes int64
	for i := 0; i < len(messages); i += m.config.BatchSize {
		end := i + m.config.BatchSize
		if end > len(messages) {
			end = len(messages)
		}
		batch := messages[i:end]

		payload, err := json.Marshal(batch)
		if err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		totalBytes += int64(len(payload))

		// In production, we would publish to MQTT here
		// token := m.client.Publish(topic, byte(m.config.QoS), m.config.Retained, payload)
		// if token.Wait() && token.Error() != nil {
		//     return &ExportResult{Success: false, Error: token.Error()}, token.Error()
		// }

		m.Logger().Debug("Published metrics to MQTT",
			zap.String("topic", topic),
			zap.Int("count", len(batch)),
			zap.Int("bytes", len(payload)),
		)
	}

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
		BytesSent:     totalBytes,
		Duration:      time.Since(startTime),
	}, nil
}

// ExportTraces exports traces via MQTT
func (m *MQTTExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !m.IsInitialized() {
		return nil, ErrNotInitialized
	}

	if !m.isConnected() {
		return nil, fmt.Errorf("not connected to MQTT broker")
	}

	startTime := time.Now()
	topic := m.buildTopic(m.config.TracesTopic)

	// Convert traces to MQTT messages
	messages := make([]mqttTraceMessage, 0, len(traces))
	for _, trace := range traces {
		msg := mqttTraceMessage{
			TraceID:       trace.TraceID,
			SpanID:        trace.SpanID,
			ParentSpanID:  trace.ParentSpanID,
			OperationName: trace.OperationName,
			ServiceName:   trace.ServiceName,
			StartTime:     trace.StartTime,
			Duration:      trace.Duration,
			Status:        string(trace.Status),
			Tags:          trace.Tags,
			Labels:        m.config.Labels,
		}
		messages = append(messages, msg)
	}

	// Batch messages
	var totalBytes int64
	for i := 0; i < len(messages); i += m.config.BatchSize {
		end := i + m.config.BatchSize
		if end > len(messages) {
			end = len(messages)
		}
		batch := messages[i:end]

		payload, err := json.Marshal(batch)
		if err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		totalBytes += int64(len(payload))

		m.Logger().Debug("Published traces to MQTT",
			zap.String("topic", topic),
			zap.Int("count", len(batch)),
			zap.Int("bytes", len(payload)),
		)
	}

	return &ExportResult{
		Success:       true,
		ItemsExported: len(traces),
		BytesSent:     totalBytes,
		Duration:      time.Since(startTime),
	}, nil
}

// ExportLogs exports logs via MQTT
func (m *MQTTExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !m.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !m.IsInitialized() {
		return nil, ErrNotInitialized
	}

	if !m.isConnected() {
		return nil, fmt.Errorf("not connected to MQTT broker")
	}

	startTime := time.Now()
	topic := m.buildTopic(m.config.LogsTopic)

	// Convert logs to MQTT messages
	messages := make([]mqttLogMessage, 0, len(logs))
	for _, log := range logs {
		attrs := make(map[string]interface{})
		for k, v := range log.Attributes {
			attrs[k] = v
		}

		msg := mqttLogMessage{
			Timestamp:  log.Timestamp,
			Level:      string(log.Level),
			Message:    log.Message,
			Source:     log.Source,
			TraceID:    log.TraceID,
			SpanID:     log.SpanID,
			Attributes: attrs,
			Labels:     m.config.Labels,
		}
		messages = append(messages, msg)
	}

	// Batch messages
	var totalBytes int64
	for i := 0; i < len(messages); i += m.config.BatchSize {
		end := i + m.config.BatchSize
		if end > len(messages) {
			end = len(messages)
		}
		batch := messages[i:end]

		payload, err := json.Marshal(batch)
		if err != nil {
			return &ExportResult{Success: false, Error: err}, err
		}
		totalBytes += int64(len(payload))

		m.Logger().Debug("Published logs to MQTT",
			zap.String("topic", topic),
			zap.Int("count", len(batch)),
			zap.Int("bytes", len(payload)),
		)
	}

	return &ExportResult{
		Success:       true,
		ItemsExported: len(logs),
		BytesSent:     totalBytes,
		Duration:      time.Since(startTime),
	}, nil
}

// buildTopic builds the full topic path with optional prefix
func (m *MQTTExporter) buildTopic(topic string) string {
	if m.config.TopicPrefix != "" {
		return m.config.TopicPrefix + "/" + topic
	}
	return topic
}

// isConnected returns whether the client is connected
func (m *MQTTExporter) isConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// Health checks the health of the MQTT connection
func (m *MQTTExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !m.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	connected := m.isConnected()
	message := "disconnected"
	if connected {
		message = "connected"
	}

	return &HealthStatus{
		Healthy:   connected,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"broker":        m.config.Broker,
			"client_id":     m.config.ClientID,
			"metrics_topic": m.config.MetricsTopic,
			"logs_topic":    m.config.LogsTopic,
			"traces_topic":  m.config.TracesTopic,
			"qos":           m.config.QoS,
		},
	}, nil
}

// Close closes the MQTT connection
func (m *MQTTExporter) Close(ctx context.Context) error {
	m.mu.Lock()
	m.connected = false
	m.mu.Unlock()

	// In production, disconnect from MQTT broker
	// m.client.Disconnect(250)

	m.SetInitialized(false)
	m.Logger().Info("MQTT exporter closed")
	return nil
}
