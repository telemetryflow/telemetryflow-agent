// External black-box unit tests for the Apache Kafka JMX-exporter collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package kafka_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	kafka "github.com/telemetryflow/telemetryflow-agent/internal/collector/kafka"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const sampleExposition = `# HELP kafka_server_brokertopicmetrics_messages_in_persec Messages in
# TYPE kafka_server_brokertopicmetrics_messages_in_persec counter
kafka_server_brokertopicmetrics_messages_in_persec{topic="orders"} 1234
# HELP kafka_controller_active_controller_count Active controllers
# TYPE kafka_controller_active_controller_count gauge
kafka_controller_active_controller_count 1
`

func newExporterServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, body)
	}))
}

func TestNewKafkaCollector_Defaults(t *testing.T) {
	c := kafka.NewKafkaCollector(config.KafkaCollectorConfig{}, zap.NewNop())
	if c.Name() != "kafka" {
		t.Fatalf("name=%q", c.Name())
	}
	if c.IsRunning() {
		t.Fatal("should not be running initially")
	}

	// Non-default scrape interval must be preserved.
	c2 := kafka.NewKafkaCollector(config.KafkaCollectorConfig{ScrapeInterval: 5 * time.Second}, zap.NewNop())
	if c2 == nil {
		t.Fatal("nil collector")
	}
}

func TestKafkaCollector_Lifecycle(t *testing.T) {
	c := kafka.NewKafkaCollector(config.KafkaCollectorConfig{Enabled: true}, zap.NewNop())
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("not running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double Start should fail")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("still running after Stop")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop should be nil, got %v", err)
	}
}

func TestKafkaCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*kafka.KafkaCollector)(nil)
}

func TestKafkaCollector_CollectNoInstances(t *testing.T) {
	c := kafka.NewKafkaCollector(config.KafkaCollectorConfig{Enabled: true}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil,nil got %v %v", m, err)
	}
}

func TestKafkaCollector_CollectSuccess(t *testing.T) {
	srv := newExporterServer(t, sampleExposition, http.StatusOK)
	defer srv.Close()

	cfg := config.KafkaCollectorConfig{
		Enabled: true,
		Tags:    map[string]string{"env": "ci"},
		Instances: []config.KafkaInstanceConfig{{
			Name:        "broker-1",
			ExporterURL: srv.URL,
			Cluster:     "prod",
			Tags:        map[string]string{"role": "leader"},
		}},
	}
	c := kafka.NewKafkaCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	byName := map[string]collector.Metric{}
	for _, m := range metrics {
		byName[m.Name] = m
		if m.Labels["env"] != "ci" || m.Labels["kafka_cluster"] != "prod" ||
			m.Labels["kafka_instance"] != "broker-1" || m.Labels["queueing_system"] != "kafka" ||
			m.Labels["role"] != "leader" {
			t.Fatalf("labels not applied on %s: %+v", m.Name, m.Labels)
		}
	}
	msgs, ok := byName["queue.kafka.server_brokertopicmetrics_messages_in_persec"]
	if !ok {
		t.Fatal("missing messages metric")
	}
	if msgs.Value != 1234 || msgs.Type != collector.MetricTypeCounter || msgs.Labels["topic"] != "orders" {
		t.Fatalf("bad counter metric: %+v", msgs)
	}
	ctrl, ok := byName["queue.kafka.controller_active_controller_count"]
	if !ok || ctrl.Value != 1 || ctrl.Type != collector.MetricTypeGauge {
		t.Fatalf("bad gauge metric: %+v", ctrl)
	}
}

func TestKafkaCollector_CollectSkipsFailingInstance(t *testing.T) {
	srv := newExporterServer(t, sampleExposition, http.StatusOK)
	defer srv.Close()

	cfg := config.KafkaCollectorConfig{
		Enabled: true,
		Instances: []config.KafkaInstanceConfig{
			{Name: "no-url"}, // missing ExporterURL -> logged & skipped
			{Name: "bad-http", ExporterURL: srv.URL, Cluster: ""}, // ok
		},
	}
	c := kafka.NewKafkaCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned err: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics from healthy instance")
	}
}

func TestKafkaCollector_CollectHTTPError(t *testing.T) {
	srv := newExporterServer(t, "", http.StatusInternalServerError)
	defer srv.Close()

	cfg := config.KafkaCollectorConfig{
		Enabled:   true,
		Instances: []config.KafkaInstanceConfig{{Name: "err", ExporterURL: srv.URL}},
	}
	c := kafka.NewKafkaCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should swallow per-instance errors: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected no metrics, got %v", metrics)
	}
}

func TestScrape_Success_WithBasicAuthAndTLSSkip(t *testing.T) {
	var gotAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == "user" && p == "pass" {
			gotAuth = true
		}
		_, _ = io.WriteString(w, sampleExposition)
	}))
	defer srv.Close()

	inst := config.KafkaInstanceConfig{
		Name:          "auth",
		ExporterURL:   srv.URL,
		Username:      "user",
		Password:      "pass",
		TLSSkipVerify: true,
	}
	r, err := kafka.ScrapeExported(context.Background(), inst)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	b, _ := io.ReadAll(r)
	if !strings.Contains(string(b), "kafka_controller_active_controller_count") {
		t.Fatal("body not returned")
	}
	if !gotAuth {
		t.Fatal("basic auth not sent")
	}
}

func TestScrape_BuildRequestError(t *testing.T) {
	inst := config.KafkaInstanceConfig{Name: "bad", ExporterURL: "http://[::1]:namedport/x"}
	if _, err := kafka.ScrapeExported(context.Background(), inst); err == nil {
		t.Fatal("expected build request error")
	}
}

func TestScrape_ConnectionError(t *testing.T) {
	srv := newExporterServer(t, sampleExposition, http.StatusOK)
	url := srv.URL
	srv.Close() // ensure connection refused

	inst := config.KafkaInstanceConfig{Name: "down", ExporterURL: url}
	if _, err := kafka.ScrapeExported(context.Background(), inst); err == nil {
		t.Fatal("expected connection error")
	}
}

func TestScrape_HTTPStatusError(t *testing.T) {
	srv := newExporterServer(t, "", http.StatusForbidden)
	defer srv.Close()
	inst := config.KafkaInstanceConfig{Name: "forbidden", ExporterURL: srv.URL}
	if _, err := kafka.ScrapeExported(context.Background(), inst); err == nil {
		t.Fatal("expected HTTP status error")
	}
}

func TestParseText(t *testing.T) {
	families, err := kafka.ParseTextExported(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(families) != 2 {
		t.Fatalf("expected 2 families, got %d", len(families))
	}
}

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{
		"kafka_server_x": "queue.kafka.server_x",
		"other_metric":   "queue.kafka.other_metric",
	}
	for in, want := range cases {
		if got := kafka.NormalizeNameExported(in); got != want {
			t.Errorf("normalizeName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInstanceLabels_NoCluster(t *testing.T) {
	c := kafka.NewKafkaCollector(config.KafkaCollectorConfig{Tags: map[string]string{"g": "1"}}, zap.NewNop())
	lbl := c.InstanceLabelsExported(config.KafkaInstanceConfig{Name: "n"})
	if lbl["g"] != "1" || lbl["kafka_instance"] != "n" || lbl["queueing_system"] != "kafka" {
		t.Fatalf("labels=%+v", lbl)
	}
	if _, ok := lbl["kafka_cluster"]; ok {
		t.Fatal("kafka_cluster should be absent when Cluster empty")
	}
}

func TestBuildKafkaMetrics_AllTypes(t *testing.T) {
	families := map[string]*dto.MetricFamily{
		"kafka_counter": {
			Name: proto.String("kafka_counter"),
			Help: proto.String("c"),
			Type: dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{{
				Label:   []*dto.LabelPair{{Name: proto.String("topic"), Value: proto.String("t")}},
				Counter: &dto.Counter{Value: proto.Float64(10)},
			}},
		},
		"kafka_gauge": {
			Name:   proto.String("kafka_gauge"),
			Type:   dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(2.5)}}},
		},
		"kafka_untyped": {
			Name:   proto.String("kafka_untyped"),
			Type:   dto.MetricType_UNTYPED.Enum(),
			Metric: []*dto.Metric{{Untyped: &dto.Untyped{Value: proto.Float64(7)}}},
		},
		"kafka_untyped_nil": {
			Name:   proto.String("kafka_untyped_nil"),
			Type:   dto.MetricType_UNTYPED.Enum(),
			Metric: []*dto.Metric{{}}, // nil Untyped -> skipped
		},
		"kafka_histogram_ignored": {
			Name:   proto.String("kafka_histogram_ignored"),
			Type:   dto.MetricType_HISTOGRAM.Enum(),
			Metric: []*dto.Metric{{Histogram: &dto.Histogram{}}},
		},
	}

	out := kafka.BuildKafkaMetrics(map[string]string{"env": "ci"}, families)
	byName := map[string]collector.Metric{}
	for _, m := range out {
		byName[m.Name] = m
		if m.Labels["env"] != "ci" {
			t.Fatalf("base label missing on %s", m.Name)
		}
	}
	if m := byName["queue.kafka.counter"]; m.Value != 10 || m.Type != collector.MetricTypeCounter || m.Labels["topic"] != "t" {
		t.Fatalf("counter wrong: %+v", m)
	}
	if m := byName["queue.kafka.gauge"]; m.Value != 2.5 || m.Type != collector.MetricTypeGauge {
		t.Fatalf("gauge wrong: %+v", m)
	}
	if m := byName["queue.kafka.untyped"]; m.Value != 7 || m.Type != collector.MetricTypeGauge {
		t.Fatalf("untyped wrong: %+v", m)
	}
	if _, ok := byName["queue.kafka.untyped_nil"]; ok {
		t.Fatal("nil untyped should be skipped")
	}
	if _, ok := byName["queue.kafka.histogram_ignored"]; ok {
		t.Fatal("histogram should be ignored")
	}
}
