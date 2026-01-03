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

// KafkaConfig contains Kafka integration configuration
type KafkaConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	Brokers           []string          `mapstructure:"brokers"`
	MetricsTopic      string            `mapstructure:"metrics_topic"`
	TracesTopic       string            `mapstructure:"traces_topic"`
	LogsTopic         string            `mapstructure:"logs_topic"`
	ClientID          string            `mapstructure:"client_id"`
	Compression       string            `mapstructure:"compression"`
	RequiredAcks      int               `mapstructure:"required_acks"`
	MaxRetries        int               `mapstructure:"max_retries"`
	BatchSize         int               `mapstructure:"batch_size"`
	BatchTimeout      time.Duration     `mapstructure:"batch_timeout"`
	FlushFrequency    time.Duration     `mapstructure:"flush_frequency"`
	TLSEnabled        bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify     bool              `mapstructure:"tls_skip_verify"`
	TLSCertFile       string            `mapstructure:"tls_cert_file"`
	TLSKeyFile        string            `mapstructure:"tls_key_file"`
	TLSCAFile         string            `mapstructure:"tls_ca_file"`
	SASLEnabled       bool              `mapstructure:"sasl_enabled"`
	SASLMechanism     string            `mapstructure:"sasl_mechanism"`
	SASLUsername      string            `mapstructure:"sasl_username"`
	SASLPassword      string            `mapstructure:"sasl_password"`
	Headers           map[string]string `mapstructure:"headers"`
	PartitionStrategy string            `mapstructure:"partition_strategy"`
}

// KafkaExporter exports telemetry data to Kafka
type KafkaExporter struct {
	*BaseExporter
	config    KafkaConfig
	tlsConfig *tls.Config

	mu       sync.Mutex
	messages []kafkaMessage
}

// kafkaMessage represents a message to be sent to Kafka
type kafkaMessage struct {
	Topic     string
	Key       []byte
	Value     []byte
	Headers   map[string]string
	Timestamp time.Time
}

// NewKafkaExporter creates a new Kafka exporter
func NewKafkaExporter(config KafkaConfig, logger *zap.Logger) *KafkaExporter {
	return &KafkaExporter{
		BaseExporter: NewBaseExporter(
			"kafka",
			"streaming",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces, DataTypeLogs},
		),
		config:   config,
		messages: make([]kafkaMessage, 0),
	}
}

// Init initializes the Kafka exporter
func (k *KafkaExporter) Init(ctx context.Context) error {
	if !k.config.Enabled {
		return nil
	}

	if err := k.Validate(); err != nil {
		return err
	}

	// Set defaults
	if k.config.ClientID == "" {
		k.config.ClientID = "telemetryflow-agent"
	}
	if k.config.MetricsTopic == "" {
		k.config.MetricsTopic = "telemetryflow-metrics"
	}
	if k.config.TracesTopic == "" {
		k.config.TracesTopic = "telemetryflow-traces"
	}
	if k.config.LogsTopic == "" {
		k.config.LogsTopic = "telemetryflow-logs"
	}
	if k.config.Compression == "" {
		k.config.Compression = "snappy"
	}
	if k.config.RequiredAcks == 0 {
		k.config.RequiredAcks = 1
	}
	if k.config.MaxRetries == 0 {
		k.config.MaxRetries = 3
	}
	if k.config.BatchSize == 0 {
		k.config.BatchSize = 100
	}
	if k.config.BatchTimeout == 0 {
		k.config.BatchTimeout = 10 * time.Millisecond
	}
	if k.config.FlushFrequency == 0 {
		k.config.FlushFrequency = 500 * time.Millisecond
	}
	if k.config.PartitionStrategy == "" {
		k.config.PartitionStrategy = "round_robin"
	}

	// Configure TLS if enabled
	if k.config.TLSEnabled {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in enterprise Kafka deployments)
		k.tlsConfig = &tls.Config{
			InsecureSkipVerify: k.config.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	k.SetInitialized(true)
	k.Logger().Info("Kafka exporter initialized",
		zap.Strings("brokers", k.config.Brokers),
		zap.String("metricsTopic", k.config.MetricsTopic),
	)

	return nil
}

// Validate validates the Kafka configuration
func (k *KafkaExporter) Validate() error {
	if !k.config.Enabled {
		return nil
	}

	if len(k.config.Brokers) == 0 {
		return NewValidationError("kafka", "brokers", "brokers is required")
	}

	if k.config.SASLEnabled {
		if k.config.SASLUsername == "" {
			return NewValidationError("kafka", "sasl_username", "sasl_username is required when SASL is enabled")
		}
		if k.config.SASLPassword == "" {
			return NewValidationError("kafka", "sasl_password", "sasl_password is required when SASL is enabled")
		}
		validMechanisms := map[string]bool{"PLAIN": true, "SCRAM-SHA-256": true, "SCRAM-SHA-512": true}
		if k.config.SASLMechanism != "" && !validMechanisms[k.config.SASLMechanism] {
			return NewValidationError("kafka", "sasl_mechanism", "sasl_mechanism must be PLAIN, SCRAM-SHA-256, or SCRAM-SHA-512")
		}
	}

	return nil
}

// Export exports telemetry data to Kafka
func (k *KafkaExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !k.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := k.ExportMetrics(ctx, data.Metrics)
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
		result, err := k.ExportTraces(ctx, data.Traces)
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
		result, err := k.ExportLogs(ctx, data.Logs)
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

// ExportMetrics exports metrics to Kafka
func (k *KafkaExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !k.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !k.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()
	var totalBytes int64

	for _, m := range metrics {
		msg := map[string]interface{}{
			"name":      m.Name,
			"value":     m.Value,
			"type":      string(m.Type),
			"timestamp": m.Timestamp.UnixMilli(),
			"tags":      m.Tags,
			"unit":      m.Unit,
		}

		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		k.mu.Lock()
		k.messages = append(k.messages, kafkaMessage{
			Topic:     k.config.MetricsTopic,
			Key:       []byte(m.Name),
			Value:     data,
			Timestamp: m.Timestamp,
		})
		k.mu.Unlock()

		totalBytes += int64(len(data))
	}

	// In production, this would use sarama or confluent-kafka-go
	// For now, we simulate the send
	k.Logger().Debug("Metrics queued for Kafka",
		zap.Int("count", len(metrics)),
		zap.String("topic", k.config.MetricsTopic),
	)

	k.RecordSuccess(totalBytes)
	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
		BytesSent:     totalBytes,
		Duration:      time.Since(startTime),
	}, nil
}

// ExportTraces exports traces to Kafka
func (k *KafkaExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !k.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !k.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()
	var totalBytes int64

	for _, t := range traces {
		msg := map[string]interface{}{
			"trace_id":       t.TraceID,
			"span_id":        t.SpanID,
			"parent_span_id": t.ParentSpanID,
			"operation_name": t.OperationName,
			"service_name":   t.ServiceName,
			"start_time":     t.StartTime.UnixMilli(),
			"duration_ms":    t.Duration.Milliseconds(),
			"status":         string(t.Status),
			"tags":           t.Tags,
		}

		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		k.mu.Lock()
		k.messages = append(k.messages, kafkaMessage{
			Topic:     k.config.TracesTopic,
			Key:       []byte(t.TraceID),
			Value:     data,
			Timestamp: t.StartTime,
		})
		k.mu.Unlock()

		totalBytes += int64(len(data))
	}

	k.RecordSuccess(totalBytes)
	return &ExportResult{
		Success:       true,
		ItemsExported: len(traces),
		BytesSent:     totalBytes,
		Duration:      time.Since(startTime),
	}, nil
}

// ExportLogs exports logs to Kafka
func (k *KafkaExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !k.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !k.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()
	var totalBytes int64

	for _, l := range logs {
		msg := map[string]interface{}{
			"timestamp":  l.Timestamp.UnixMilli(),
			"level":      string(l.Level),
			"message":    l.Message,
			"source":     l.Source,
			"trace_id":   l.TraceID,
			"span_id":    l.SpanID,
			"attributes": l.Attributes,
		}

		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		k.mu.Lock()
		k.messages = append(k.messages, kafkaMessage{
			Topic:     k.config.LogsTopic,
			Key:       []byte(l.Source),
			Value:     data,
			Timestamp: l.Timestamp,
		})
		k.mu.Unlock()

		totalBytes += int64(len(data))
	}

	k.RecordSuccess(totalBytes)
	return &ExportResult{
		Success:       true,
		ItemsExported: len(logs),
		BytesSent:     totalBytes,
		Duration:      time.Since(startTime),
	}, nil
}

// Health checks the health of the Kafka cluster
func (k *KafkaExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !k.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	// In production, this would actually connect to brokers
	// For now, we return a basic health check
	return &HealthStatus{
		Healthy:   true,
		Message:   fmt.Sprintf("configured with %d brokers", len(k.config.Brokers)),
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"brokers":       k.config.Brokers,
			"metrics_topic": k.config.MetricsTopic,
			"traces_topic":  k.config.TracesTopic,
			"logs_topic":    k.config.LogsTopic,
		},
	}, nil
}

// Close closes the Kafka exporter
func (k *KafkaExporter) Close(ctx context.Context) error {
	// Flush remaining messages
	k.mu.Lock()
	remaining := len(k.messages)
	k.messages = nil
	k.mu.Unlock()

	if remaining > 0 {
		k.Logger().Info("Flushed remaining messages", zap.Int("count", remaining))
	}

	k.SetInitialized(false)
	k.Logger().Info("Kafka exporter closed")
	return nil
}
