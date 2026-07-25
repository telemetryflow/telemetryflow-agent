// Package exporter: kafka_output.go implements a Kafka output plugin that
// serialises plugin.Metric batches into JSON, OTLP protobuf, or Prometheus
// remote-write protobuf and publishes them to a Kafka topic via a Sarama
// SyncProducer (M5.4).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/prometheus/prometheus/prompb"
	"github.com/xdg-go/scram"
	metricsv1 "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	otlpcommonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	otlpmetricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	otlpresourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// SHA256SCRAM / SHA512SCRAM are the xdg-go/scram hash generator functions
// used to back Sarama's SCRAMClient interface for SCRAM-SHA-256 / -512.
var (
	SHA256SCRAM = scram.SHA256
	SHA512SCRAM = scram.SHA512
)

// newXDGSCRAMClient builds a sarama.SCRAMClient backed by xdg-go/scram using
// the provided hash generator function. The actual username/password are
// injected by Sarama via Begin() at handshake time.
func newXDGSCRAMClient(fcn scram.HashGeneratorFcn) sarama.SCRAMClient {
	return &xdgSCRAMClient{fcn: fcn}
}

// xdgSCRAMClient adapts xdg-go/scram.ClientConversation onto sarama's
// SCRAMClient interface.
type xdgSCRAMClient struct {
	fcn  scram.HashGeneratorFcn
	conv *scram.ClientConversation
}

func (c *xdgSCRAMClient) Begin(username, password, authzID string) error {
	client, err := c.fcn.NewClient(username, password, authzID)
	if err != nil {
		return err
	}
	c.conv = client.NewConversation()
	return nil
}

func (c *xdgSCRAMClient) Step(challenge string) (string, error) {
	return c.conv.Step(challenge)
}

func (c *xdgSCRAMClient) Done() bool {
	return c.conv.Done()
}

// Kafka format identifiers selectable via KafkaOutputConfig.Format.
const (
	KafkaFormatJSON         = "json"
	KafkaFormatOTLPProto    = "otlp_proto"
	KafkaFormatPrometheusRW = "prometheus_rw"
)

// Kafka auth type identifiers selectable via KafkaAuth.Type.
const (
	KafkaAuthNone            = "none"
	KafkaAuthSASLPlaintext   = "sasl_plaintext"
	KafkaAuthSASLSCRAMSHA256 = "sasl_scram_sha256"
	KafkaAuthSASLSCRAMSHA512 = "sasl_scram_sha512"
	KafkaAuthTLS             = "tls"
)

// Kafka compression identifiers selectable via KafkaOutputConfig.Compression.
const (
	KafkaCompressionNone   = "none"
	KafkaCompressionGZIP   = "gzip"
	KafkaCompressionSnappy = "snappy"
	KafkaCompressionLZ4    = "lz4"
	KafkaCompressionZSTD   = "zstd"
)

// Kafka ack identifiers selectable via KafkaOutputConfig.Acks.
const (
	KafkaAcksAll  = "all"
	KafkaAcksOne  = "1"
	KafkaAcksZero = "0"
)

// KafkaOutputConfig configures a KafkaOutput. Brokers and Topic are required;
// every other field has a sensible default applied by NewKafkaOutput.
type KafkaOutputConfig struct {
	// Brokers is the bootstrap list, e.g. ["kafka-1:9092","kafka-2:9092"].
	Brokers []string
	// Topic is the destination Kafka topic.
	Topic string
	// Format selects the wire encoding: "json" (default), "otlp_proto",
	// or "prometheus_rw".
	Format string
	// Auth selects the authentication scheme.
	Auth KafkaAuth
	// Compression selects the producer compression codec: "none" (default),
	// "gzip", "snappy", "lz4", "zstd".
	Compression string
	// Acks selects the durability level: "all" (default), "1", "0".
	Acks string
	// BatchSize is the producer channel batch size (default 1000).
	BatchSize int
	// Logger receives structured diagnostics. Defaults to a nop logger.
	Logger *zap.Logger
}

// KafkaAuth configures broker authentication. The zero value is anonymous
// (Type == "none").
type KafkaAuth struct {
	// Type selects the scheme; see the KafkaAuth* constants.
	Type string
	// Username + Password are used for SASL PLAIN/SCRAM.
	Username string
	Password string
	// TLS enables TLS transport (independent of SASL).
	TLS bool
	// TLSSkipVerify disables certificate verification (dev/test only).
	TLSSkipVerify bool
	// CACertPath is the path to a PEM CA bundle. Optional.
	CACertPath string
	// ClientCertPath + ClientKeyPath enable mutual TLS when both set.
	ClientCertPath string
	ClientKeyPath  string
}

// KafkaOutput is a plugin.Output that publishes metric batches to Kafka.
type KafkaOutput struct {
	cfg  KafkaOutputConfig
	log  *zap.Logger
	cfgS *sarama.Config

	mu       sync.Mutex
	producer sarama.SyncProducer
}

// producerFactory is the default Sarama constructor; overridable from tests
// via SetProducerFactory so unit tests never dial a real broker.
var producerFactory = func(brokers []string, cfg *sarama.Config) (sarama.SyncProducer, error) {
	return sarama.NewSyncProducer(brokers, cfg)
}

// SetProducerFactory overrides the Sarama SyncProducer constructor. Intended
// for unit tests that want to capture ProducerMessages without dialing Kafka.
// Calling with nil restores the default factory.
func SetProducerFactory(f func(brokers []string, cfg *sarama.Config) (sarama.SyncProducer, error)) {
	if f == nil {
		f = func(brokers []string, cfg *sarama.Config) (sarama.SyncProducer, error) {
			return sarama.NewSyncProducer(brokers, cfg)
		}
	}
	producerFactory = f
}

// NewKafkaOutput validates the configuration and returns a ready KafkaOutput.
// Connect must still be called before Write.
func NewKafkaOutput(cfg KafkaOutputConfig) (*KafkaOutput, error) {
	if err := applyKafkaDefaults(&cfg); err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("kafka_output")

	sc, err := buildSaramaConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &KafkaOutput{cfg: cfg, log: logger, cfgS: sc}, nil
}

// Name implements plugin.Output.
func (o *KafkaOutput) Name() string { return "kafka" }

// Connect builds the Sarama SyncProducer. Safe to call multiple times; the
// existing producer is closed before a new one is created.
func (o *KafkaOutput) Connect() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.producer != nil {
		_ = o.producer.Close()
		o.producer = nil
	}
	p, err := producerFactory(o.cfg.Brokers, o.cfgS)
	if err != nil {
		return fmt.Errorf("kafka: create producer: %w", err)
	}
	o.producer = p
	o.log.Info("kafka producer connected",
		zap.Strings("brokers", o.cfg.Brokers),
		zap.String("topic", o.cfg.Topic),
		zap.String("format", o.cfg.Format),
	)
	return nil
}

// Close closes the underlying Sarama SyncProducer.
func (o *KafkaOutput) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.producer == nil {
		return nil
	}
	err := o.producer.Close()
	o.producer = nil
	return err
}

// Write implements plugin.Output. The whole batch is serialised into a single
// Kafka ProducerMessage (single batch) keyed by the first metric name (or the
// first label value when present) for partition affinity.
func (o *KafkaOutput) Write(metrics []plugin.Metric) error {
	if len(metrics) == 0 {
		return nil
	}
	o.mu.Lock()
	p := o.producer
	o.mu.Unlock()
	if p == nil {
		return errors.New("kafka: not connected")
	}

	value, err := o.encode(metrics)
	if err != nil {
		return fmt.Errorf("kafka: encode: %w", err)
	}

	key := kafkaKeyFor(metrics[0])
	msg := &sarama.ProducerMessage{
		Topic: o.cfg.Topic,
		Key:   sarama.ByteEncoder(key),
		Value: sarama.ByteEncoder(value),
	}

	if _, _, err := p.SendMessage(msg); err != nil {
		return fmt.Errorf("kafka: send: %w", err)
	}
	o.log.Debug("kafka message produced",
		zap.Int("metrics", len(metrics)),
		zap.Int("bytes", len(value)),
		zap.String("topic", o.cfg.Topic),
	)
	return nil
}

// encode dispatches to the configured serializer and returns the Kafka value
// bytes.
func (o *KafkaOutput) encode(metrics []plugin.Metric) ([]byte, error) {
	switch o.cfg.Format {
	case KafkaFormatJSON:
		return json.Marshal(metrics)
	case KafkaFormatOTLPProto:
		req := buildOTLPExportRequest(metrics)
		return proto.Marshal(req)
	case KafkaFormatPrometheusRW:
		wr := buildKafkaPromWriteRequest(metrics)
		return wr.Marshal()
	default:
		return nil, fmt.Errorf("unsupported format %q", o.cfg.Format)
	}
}

// kafkaKeyFor picks a stable partitioning key: the value of the first label
// (alphabetically) when labels exist, otherwise the metric name. Empty keys
// fall back to the metric name so consumers always see a non-empty key.
func kafkaKeyFor(m plugin.Metric) string {
	if len(m.Labels) > 0 {
		keys := make([]string, 0, len(m.Labels))
		for k := range m.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		first := keys[0]
		if v := m.Labels[first]; v != "" {
			return v
		}
	}
	return m.Name
}

// applyKafkaDefaults validates required fields and fills in defaults for
// Format, Auth.Type, Compression, Acks, and BatchSize. It mutates cfg in
// place so callers (constructor + buildSaramaConfig) see identical values.
func applyKafkaDefaults(cfg *KafkaOutputConfig) error {
	if len(cfg.Brokers) == 0 {
		return errors.New("kafka: brokers is required")
	}
	if cfg.Topic == "" {
		return errors.New("kafka: topic is required")
	}
	if cfg.Format == "" {
		cfg.Format = KafkaFormatJSON
	}
	switch cfg.Format {
	case KafkaFormatJSON, KafkaFormatOTLPProto, KafkaFormatPrometheusRW:
	default:
		return fmt.Errorf("kafka: unsupported format %q", cfg.Format)
	}
	if cfg.Auth.Type == "" {
		cfg.Auth.Type = KafkaAuthNone
	}
	if cfg.Compression == "" {
		cfg.Compression = KafkaCompressionNone
	}
	if cfg.Acks == "" {
		cfg.Acks = KafkaAcksAll
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1000
	}
	return nil
}

// buildSaramaConfig constructs the sarama.Config from KafkaOutputConfig,
// honouring auth, compression, acks, and batch size. Defaults are applied
// first so callers passing a partial config still get a valid sarama.Config.
func buildSaramaConfig(cfgIn KafkaOutputConfig) (*sarama.Config, error) {
	cfg := cfgIn
	if err := applyKafkaDefaults(&cfg); err != nil {
		return nil, err
	}

	sc := sarama.NewConfig()
	sc.ClientID = version.UserAgent()
	sc.Version = sarama.V2_1_0_0 // required for zstd; safe floor for modern brokers.

	// SyncProducer requires both return flags.
	sc.Producer.Return.Successes = true
	sc.Producer.Return.Errors = true

	// RequiredAcks.
	switch cfg.Acks {
	case KafkaAcksAll:
		sc.Producer.RequiredAcks = sarama.WaitForAll
	case KafkaAcksOne:
		sc.Producer.RequiredAcks = sarama.WaitForLocal
	case KafkaAcksZero:
		sc.Producer.RequiredAcks = sarama.NoResponse
	default:
		return nil, fmt.Errorf("kafka: unsupported acks %q", cfg.Acks)
	}

	// Compression.
	switch cfg.Compression {
	case KafkaCompressionNone:
		sc.Producer.Compression = sarama.CompressionNone
	case KafkaCompressionGZIP:
		sc.Producer.Compression = sarama.CompressionGZIP
	case KafkaCompressionSnappy:
		sc.Producer.Compression = sarama.CompressionSnappy
	case KafkaCompressionLZ4:
		sc.Producer.Compression = sarama.CompressionLZ4
	case KafkaCompressionZSTD:
		sc.Producer.Compression = sarama.CompressionZSTD
	default:
		return nil, fmt.Errorf("kafka: unsupported compression %q", cfg.Compression)
	}

	if cfg.BatchSize > 0 {
		sc.Producer.Flush.Frequency = 50 * time.Millisecond
		sc.Producer.Flush.Messages = cfg.BatchSize
	}

	// TLS.
	if cfg.Auth.TLS || cfg.Auth.Type == KafkaAuthTLS {
		tlsCfg, err := buildTLSConfig(cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("kafka: tls config: %w", err)
		}
		sc.Net.TLS.Enable = true
		sc.Net.TLS.Config = tlsCfg
	}

	// SASL.
	switch cfg.Auth.Type {
	case KafkaAuthSASLPlaintext:
		sc.Net.SASL.Enable = true
		sc.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		sc.Net.SASL.User = cfg.Auth.Username
		sc.Net.SASL.Password = cfg.Auth.Password
	case KafkaAuthSASLSCRAMSHA256:
		if err := configureSCRAM(sc, cfg.Auth, sarama.SASLTypeSCRAMSHA256); err != nil {
			return nil, err
		}
	case KafkaAuthSASLSCRAMSHA512:
		if err := configureSCRAM(sc, cfg.Auth, sarama.SASLTypeSCRAMSHA512); err != nil {
			return nil, err
		}
	case KafkaAuthNone, KafkaAuthTLS:
		// no SASL
	default:
		return nil, fmt.Errorf("kafka: unsupported auth type %q", cfg.Auth.Type)
	}

	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("kafka: config validate: %w", err)
	}
	return sc, nil
}

// configureSCRAM wires the xdg-go/scram generator into Sarama for the given
// hash mechanism.
func configureSCRAM(sc *sarama.Config, auth KafkaAuth, mechanism sarama.SASLMechanism) error {
	sc.Net.SASL.Enable = true
	sc.Net.SASL.Mechanism = mechanism
	sc.Net.SASL.User = auth.Username
	sc.Net.SASL.Password = auth.Password
	switch mechanism {
	case sarama.SASLTypeSCRAMSHA256:
		sc.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return newXDGSCRAMClient(SHA256SCRAM)
		}
	case sarama.SASLTypeSCRAMSHA512:
		sc.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return newXDGSCRAMClient(SHA512SCRAM)
		}
	default:
		return fmt.Errorf("unsupported SCRAM mechanism %q", mechanism)
	}
	return nil
}

// buildTLSConfig assembles the *tls.Config from the optional CA / client
// cert paths and the InsecureSkipVerify flag.
func buildTLSConfig(auth KafkaAuth) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: auth.TLSSkipVerify, // #nosec G402 -- opt-in dev/test escape hatch.
	}
	if auth.CACertPath != "" {
		caPEM, err := os.ReadFile(auth.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA cert %q contained no usable certificates", auth.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}
	if auth.ClientCertPath != "" && auth.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(auth.ClientCertPath, auth.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// buildOTLPExportRequest converts a batch of plugin.Metric into the canonical
// OTLP ExportMetricsServiceRequest envelope (cumulative for counters, gauge
// for everything else). One ResourceMetrics + one ScopeMetrics are emitted.
func buildOTLPExportRequest(metrics []plugin.Metric) *metricsv1.ExportMetricsServiceRequest {
	grouped := make(map[string][]plugin.Metric, len(metrics))
	for _, m := range metrics {
		grouped[m.Name] = append(grouped[m.Name], m)
	}

	otlpMetrics := make([]*otlpmetricsv1.Metric, 0, len(grouped))
	for name, points := range grouped {
		var description, unit string
		if len(points) > 0 {
			description = points[0].Description
			unit = points[0].Unit
		}
		dp := make([]*otlpmetricsv1.NumberDataPoint, 0, len(points))
		isCounter := false
		for _, p := range points {
			if p.Type == plugin.MetricTypeCounter {
				isCounter = true
			}
			dp = append(dp, &otlpmetricsv1.NumberDataPoint{
				Attributes:   kafkaLabelsToKV(p.Labels),
				TimeUnixNano: uint64(p.Timestamp.UnixNano()),
				Value: &otlpmetricsv1.NumberDataPoint_AsDouble{
					AsDouble: p.Value,
				},
			})
		}
		metric := &otlpmetricsv1.Metric{
			Name:        name,
			Description: description,
			Unit:        unit,
		}
		if isCounter {
			metric.Data = &otlpmetricsv1.Metric_Sum{
				Sum: &otlpmetricsv1.Sum{
					DataPoints:             dp,
					AggregationTemporality: otlpmetricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
					IsMonotonic:            true,
				},
			}
		} else {
			metric.Data = &otlpmetricsv1.Metric_Gauge{
				Gauge: &otlpmetricsv1.Gauge{DataPoints: dp},
			}
		}
		otlpMetrics = append(otlpMetrics, metric)
	}

	return &metricsv1.ExportMetricsServiceRequest{
		ResourceMetrics: []*otlpmetricsv1.ResourceMetrics{{
			Resource: &otlpresourcev1.Resource{
				Attributes: []*otlpcommonv1.KeyValue{
					{Key: "service.name", Value: &otlpcommonv1.AnyValue{
						Value: &otlpcommonv1.AnyValue_StringValue{StringValue: "telemetryflow-agent"},
					}},
				},
			},
			ScopeMetrics: []*otlpmetricsv1.ScopeMetrics{{
				Scope: &otlpcommonv1.InstrumentationScope{
					Name:    "github.com/telemetryflow/telemetryflow-agent",
					Version: version.Version,
				},
				Metrics: otlpMetrics,
			}},
		}},
	}
}

// buildKafkaPromWriteRequest converts a batch of plugin.Metric into a
// prompb.WriteRequest with one TimeSeries per metric point. Labels are sorted
// alphabetically (with __name__ first), matching the remote-write spec.
func buildKafkaPromWriteRequest(metrics []plugin.Metric) prompb.WriteRequest {
	ts := make([]prompb.TimeSeries, 0, len(metrics))
	for _, m := range metrics {
		ts = append(ts, prompb.TimeSeries{
			Labels: buildLabels(m),
			Samples: []prompb.Sample{{
				Value:     m.Value,
				Timestamp: m.Timestamp.UnixMilli(),
			}},
		})
	}
	return prompb.WriteRequest{Timeseries: ts}
}

// kafkaLabelsToKV converts a label map into a sorted slice of OTLP KeyValue.
func kafkaLabelsToKV(labels map[string]string) []*otlpcommonv1.KeyValue {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*otlpcommonv1.KeyValue, 0, len(keys))
	for _, k := range keys {
		out = append(out, &otlpcommonv1.KeyValue{
			Key: k,
			Value: &otlpcommonv1.AnyValue{
				Value: &otlpcommonv1.AnyValue_StringValue{StringValue: labels[k]},
			},
		})
	}
	return out
}

// Compile-time interface guards.
var (
	_ plugin.Output = (*KafkaOutput)(nil)
)

// init self-registers the output with the plugin registry so it is reachable
// by name. Real configuration goes through NewKafkaOutput before Connect.
func init() {
	plugin.MustAddOutput("kafka", func() plugin.Output {
		out, err := NewKafkaOutput(KafkaOutputConfig{})
		if err != nil {
			// Empty cfg is invalid (brokers/topic missing); fall back to a
			// zero struct so registration still succeeds. Real wiring always
			// uses the explicit constructor with a populated cfg.
			return &KafkaOutput{}
		}
		return out
	})
}
