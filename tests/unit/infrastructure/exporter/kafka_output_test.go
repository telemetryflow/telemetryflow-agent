// Package exporter_test contains unit tests for the Kafka output plugin.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	collectormetricsv1 "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	otlpmetricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// fakeProducer captures SendMessage calls so tests can assert the exact
// ProducerMessages the output constructs. It implements sarama.SyncProducer.
type fakeProducer struct {
	msgs    []*sarama.ProducerMessage
	closed  bool
	sendErr error
}

func (f *fakeProducer) SendMessage(msg *sarama.ProducerMessage) (int32, int64, error) {
	f.msgs = append(f.msgs, msg)
	if f.sendErr != nil {
		return 0, 0, f.sendErr
	}
	return 0, int64(len(f.msgs) - 1), nil
}

func (f *fakeProducer) SendMessages(msgs []*sarama.ProducerMessage) error {
	for _, m := range msgs {
		if _, _, err := f.SendMessage(m); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeProducer) Close() error {
	f.closed = true
	return nil
}

func (f *fakeProducer) TxnStatus() sarama.ProducerTxnStatusFlag { return 0 }
func (f *fakeProducer) IsTransactional() bool                   { return false }
func (f *fakeProducer) BeginTxn() error                         { return nil }
func (f *fakeProducer) CommitTxn() error                        { return nil }
func (f *fakeProducer) AbortTxn() error                         { return nil }
func (f *fakeProducer) AddOffsetsToTxn(_ map[string][]*sarama.PartitionOffsetMetadata, _ string) error {
	return nil
}
func (f *fakeProducer) AddMessageToTxn(_ *sarama.ConsumerMessage, _ string, _ *string) error {
	return nil
}

// installFakeFactory swaps the package-level producer factory for one that
// returns the supplied fakeProducer. The returned cleanup restores the
// canonical sarama.NewSyncProducer factory.
func installFakeFactory(t *testing.T, wantCfgCheck func(*sarama.Config)) (*fakeProducer, func()) {
	t.Helper()
	fp := &fakeProducer{}
	exporter.SetProducerFactory(func(brokers []string, cfg *sarama.Config) (sarama.SyncProducer, error) {
		if wantCfgCheck != nil {
			wantCfgCheck(cfg)
		}
		return fp, nil
	})
	cleanup := func() {
		exporter.SetProducerFactory(func(brokers []string, cfg *sarama.Config) (sarama.SyncProducer, error) {
			return sarama.NewSyncProducer(brokers, cfg)
		})
	}
	return fp, cleanup
}

func kafkaSampleMetrics() []plugin.Metric {
	now := time.UnixMilli(1_700_000_000_000).UTC()
	return []plugin.Metric{
		{
			Name:      "system.cpu.usage",
			Type:      plugin.MetricTypeGauge,
			Value:     0.42,
			Timestamp: now,
			Labels:    map[string]string{"host": "node-1", "cpu": "0"},
			Unit:      "percent",
		},
		{
			Name:      "http.requests_total",
			Type:      plugin.MetricTypeCounter,
			Value:     7,
			Timestamp: now,
			Labels:    map[string]string{"method": "GET"},
			Unit:      "1",
		},
	}
}

func TestKafkaOutput_Name(t *testing.T) {
	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)
	assert.Equal(t, "kafka", out.Name())
}

func TestKafkaOutput_NewRequiresBrokersAndTopic(t *testing.T) {
	_, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "brokers")

	_, err = exporter.NewKafkaOutput(exporter.KafkaOutputConfig{Brokers: []string{"kafka-1:9092"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "topic")
}

func TestKafkaOutput_NewRejectsBadFormat(t *testing.T) {
	_, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Format:  "xml",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestKafkaOutput_JSONSerialization(t *testing.T) {
	fp, restore := installFakeFactory(t, func(cfg *sarama.Config) {
		// Defaults: acks=all, compression=none.
		assert.Equal(t, sarama.WaitForAll, cfg.Producer.RequiredAcks)
		assert.Equal(t, sarama.CompressionNone, cfg.Producer.Compression)
		assert.True(t, cfg.Producer.Return.Successes)
		assert.True(t, cfg.Producer.Return.Errors)
	})
	defer restore()

	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Format:  "json",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	metrics := kafkaSampleMetrics()
	require.NoError(t, out.Write(metrics))
	require.Len(t, fp.msgs, 1, "single Write = single Kafka message")

	msg := fp.msgs[0]
	assert.Equal(t, "metrics", msg.Topic)

	// Key is the value of the alphabetically-first label of the first metric.
	// sampleMetrics[0].Labels = {host: node-1, cpu: 0} -> first key "cpu" -> "0".
	keyBytes, err := msg.Key.Encode()
	require.NoError(t, err)
	assert.Equal(t, "0", string(keyBytes))

	valBytes, err := msg.Value.Encode()
	require.NoError(t, err)

	var decoded []plugin.Metric
	require.NoError(t, json.Unmarshal(valBytes, &decoded), "value should be JSON array of metrics")
	require.Len(t, decoded, 2)
	assert.Equal(t, "system.cpu.usage", decoded[0].Name)
	assert.InDelta(t, 0.42, decoded[0].Value, 1e-9)
	assert.Equal(t, "http.requests_total", decoded[1].Name)
	assert.InDelta(t, 7.0, decoded[1].Value, 1e-9)

	require.NoError(t, out.Close())
	assert.True(t, fp.closed, "Close must close the underlying producer")
}

func TestKafkaOutput_OTLPProtoSerialization(t *testing.T) {
	fp, restore := installFakeFactory(t, nil)
	defer restore()

	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "otlp",
		Format:  "otlp_proto",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	require.NoError(t, out.Write(kafkaSampleMetrics()))
	require.Len(t, fp.msgs, 1)

	valBytes, err := fp.msgs[0].Value.Encode()
	require.NoError(t, err)

	var req collectormetricsv1.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(valBytes, &req), "value should decode as OTLP ExportMetricsServiceRequest")

	rm := req.GetResourceMetrics()
	require.Len(t, rm, 1)
	sm := rm[0].GetScopeMetrics()
	require.Len(t, sm, 1)

	for _, m := range sm[0].GetMetrics() {
		switch m.GetName() {
		case "system.cpu.usage":
			require.NotNil(t, m.GetGauge(), "non-counter metric must use Gauge")
		case "http.requests_total":
			require.NotNil(t, m.GetSum(), "counter metric must use Sum")
			assert.True(t, m.GetSum().GetIsMonotonic())
			assert.Equal(t, otlpmetricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				m.GetSum().GetAggregationTemporality())
		default:
			t.Fatalf("unexpected metric name %q", m.GetName())
		}
	}

	require.NoError(t, out.Close())
}

func TestKafkaOutput_PrometheusRWSerialization(t *testing.T) {
	fp, restore := installFakeFactory(t, nil)
	defer restore()

	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "prom",
		Format:  "prometheus_rw",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	require.NoError(t, out.Write(kafkaSampleMetrics()))
	require.Len(t, fp.msgs, 1)

	valBytes, err := fp.msgs[0].Value.Encode()
	require.NoError(t, err)

	var wr prompb.WriteRequest
	require.NoError(t, wr.Unmarshal(valBytes), "value should decode as prompb.WriteRequest")
	require.Len(t, wr.Timeseries, 2)

	// __name__ label must be present on every series and alphabetically sorted.
	for _, ts := range wr.Timeseries {
		assert.NotEmpty(t, ts.Labels)
		var hasName bool
		for i, l := range ts.Labels {
			if l.Name == "__name__" {
				hasName = true
			}
			if i > 0 {
				assert.True(t, ts.Labels[i-1].Name <= l.Name, "labels must be sorted alphabetically")
			}
		}
		assert.True(t, hasName, "every TimeSeries must carry __name__")
		require.Len(t, ts.Samples, 1)
	}

	require.NoError(t, out.Close())
}

func TestKafkaOutput_DefaultFormatIsJSON(t *testing.T) {
	// No explicit Format -> encode defaults to JSON.
	val, err := exporter.EncodeExported(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
	}, kafkaSampleMetrics())
	require.NoError(t, err)
	assert.NotEmpty(t, val)

	var decoded []plugin.Metric
	require.NoError(t, json.Unmarshal(val, &decoded))
	require.Len(t, decoded, 2)
}

func TestKafkaOutput_SASLConfigSetup(t *testing.T) {
	cases := []struct {
		name      string
		auth      exporter.KafkaAuth
		wantMech  sarama.SASLMechanism
		wantSCRAM bool
	}{
		{
			name:     "sasl_plaintext",
			auth:     exporter.KafkaAuth{Type: "sasl_plaintext", Username: "alice", Password: "s3cret"},
			wantMech: sarama.SASLTypePlaintext,
		},
		{
			name:      "sasl_scram_sha256",
			auth:      exporter.KafkaAuth{Type: "sasl_scram_sha256", Username: "bob", Password: "p@ss"},
			wantMech:  sarama.SASLTypeSCRAMSHA256,
			wantSCRAM: true,
		},
		{
			name:      "sasl_scram_sha512",
			auth:      exporter.KafkaAuth{Type: "sasl_scram_sha512", Username: "carol", Password: "p@ss"},
			wantMech:  sarama.SASLTypeSCRAMSHA512,
			wantSCRAM: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := exporter.SaramaConfigExported(exporter.KafkaOutputConfig{
				Brokers: []string{"kafka-1:9092"},
				Topic:   "metrics",
				Auth:    tc.auth,
			})
			require.NoError(t, err)
			assert.True(t, cfg.Net.SASL.Enable, "SASL must be enabled")
			assert.Equal(t, tc.wantMech, cfg.Net.SASL.Mechanism)
			assert.Equal(t, tc.auth.Username, cfg.Net.SASL.User)
			assert.Equal(t, tc.auth.Password, cfg.Net.SASL.Password)
			if tc.wantSCRAM {
				assert.NotNil(t, cfg.Net.SASL.SCRAMClientGeneratorFunc,
					"SCRAM mechanism must install SCRAMClientGeneratorFunc")
			}
		})
	}
}

func TestKafkaOutput_AcksAndCompression(t *testing.T) {
	cases := []struct {
		name        string
		acks        string
		compression string
		wantAcks    sarama.RequiredAcks
		wantCodec   sarama.CompressionCodec
	}{
		{"defaults", "", "", sarama.WaitForAll, sarama.CompressionNone},
		{"acks_1", "1", "", sarama.WaitForLocal, sarama.CompressionNone},
		{"acks_0", "0", "", sarama.NoResponse, sarama.CompressionNone},
		{"gzip", "all", "gzip", sarama.WaitForAll, sarama.CompressionGZIP},
		{"snappy", "all", "snappy", sarama.WaitForAll, sarama.CompressionSnappy},
		{"lz4", "all", "lz4", sarama.WaitForAll, sarama.CompressionLZ4},
		{"zstd", "all", "zstd", sarama.WaitForAll, sarama.CompressionZSTD},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := exporter.SaramaConfigExported(exporter.KafkaOutputConfig{
				Brokers:     []string{"kafka-1:9092"},
				Topic:       "metrics",
				Acks:        tc.acks,
				Compression: tc.compression,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAcks, cfg.Producer.RequiredAcks)
			assert.Equal(t, tc.wantCodec, cfg.Producer.Compression)
		})
	}
}

func TestKafkaOutput_TLSConfigSetup(t *testing.T) {
	cfg, err := exporter.SaramaConfigExported(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Auth: exporter.KafkaAuth{
			Type:          "tls",
			TLS:           true,
			TLSSkipVerify: true,
		},
	})
	require.NoError(t, err)
	assert.True(t, cfg.Net.TLS.Enable, "TLS must be enabled")
	require.NotNil(t, cfg.Net.TLS.Config)
	assert.True(t, cfg.Net.TLS.Config.InsecureSkipVerify)
}

func TestKafkaOutput_RejectsBadAcksAndCompression(t *testing.T) {
	_, err := exporter.SaramaConfigExported(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Acks:    "bogus",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acks")

	_, err = exporter.SaramaConfigExported(exporter.KafkaOutputConfig{
		Brokers:     []string{"kafka-1:9092"},
		Topic:       "metrics",
		Compression: "bogus",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compression")
}

func TestKafkaOutput_KeySelection(t *testing.T) {
	now := time.Now()

	// With labels: key = value of the alphabetically-first label.
	m1 := plugin.Metric{
		Name:      "system.cpu.usage",
		Value:     1,
		Timestamp: now,
		Labels:    map[string]string{"host": "node-1", "cpu": "0"},
	}
	assert.Equal(t, "0", exporter.KafkaKeyForExported(m1))

	// Without labels: key = metric name.
	m2 := plugin.Metric{Name: "no.labels", Value: 1, Timestamp: now}
	assert.Equal(t, "no.labels", exporter.KafkaKeyForExported(m2))

	// With a label whose value is empty: fall back to metric name.
	m3 := plugin.Metric{
		Name:      "empty.value",
		Value:     1,
		Timestamp: now,
		Labels:    map[string]string{"a": ""},
	}
	assert.Equal(t, "empty.value", exporter.KafkaKeyForExported(m3))
}

func TestKafkaOutput_ConnectAndCloseLifecycle(t *testing.T) {
	fp, restore := installFakeFactory(t, nil)
	defer restore()

	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)

	// Write before Connect must fail.
	err = out.Write(kafkaSampleMetrics())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	require.NoError(t, out.Connect())
	require.NoError(t, out.Write(kafkaSampleMetrics()))
	require.Len(t, fp.msgs, 1)

	// Close once: closes producer.
	require.NoError(t, out.Close())
	assert.True(t, fp.closed)

	// Close again: no panic, no error (idempotent).
	require.NoError(t, out.Close())
}

func TestKafkaOutput_EmptyBatchIsNoop(t *testing.T) {
	fp, restore := installFakeFactory(t, nil)
	defer restore()

	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	require.NoError(t, out.Write(nil))
	assert.Empty(t, fp.msgs, "empty Write must not produce a Kafka message")

	require.NoError(t, out.Close())
}

func TestKafkaOutput_SendErrorIsPropagated(t *testing.T) {
	fp, restore := installFakeFactory(t, nil)
	defer restore()

	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	fp.sendErr = errors.New("kafka broker down")
	err = out.Write(kafkaSampleMetrics())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kafka: send:")
	assert.Contains(t, err.Error(), "kafka broker down")

	require.NoError(t, out.Close())
}

func TestKafkaOutput_SatisfiesPluginOutputContract(t *testing.T) {
	out, err := exporter.NewKafkaOutput(exporter.KafkaOutputConfig{
		Brokers: []string{"kafka-1:9092"},
		Topic:   "metrics",
		Logger:  zap.NewNop(),
	})
	require.NoError(t, err)

	var _ interface {
		Name() string
		Connect() error
		Close() error
		Write([]plugin.Metric) error
	} = out
}
