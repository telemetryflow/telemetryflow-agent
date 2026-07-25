// Package ping_test contains external unit tests for the ping collector.
// Tests inject fakePinger instances so they run deterministically in CI
// without depending on ICMP socket availability.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package ping_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/ping"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// fakePinger is a test stub for the ping.PingerExported interface.
type fakePinger struct {
	results map[string]ping.PingStatsExported
	err     error
	calls   int
}

func (f *fakePinger) Ping(host string, count int, timeout time.Duration) (ping.PingStatsExported, error) {
	f.calls++
	if f.err != nil {
		return ping.PingStatsExported{Host: host}, f.err
	}
	if s, ok := f.results[host]; ok {
		return s, nil
	}
	return ping.PingStatsExported{Host: host, State: 0}, errors.New("no fake result for " + host)
}

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func TestPingCollector_Defaults(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{}, zap.NewNop())
	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Count", c.CfgCountExported(), 5},
		{"Timeout", c.CfgTimeoutExported(), 5 * time.Second},
		{"IntervalBetween", c.CfgIntervalBetweenExported(), 1 * time.Second},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s=%v want %v", tc.name, tc.got, tc.want)
		}
	}
	if !c.DefaultPingerInstalledExported() {
		t.Errorf("expected defaultPinger, got %T", c)
	}
}

func TestPingCollector_Name(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{}, zap.NewNop())
	if c.Name() != "ping" {
		t.Fatalf("Name()=%q want %q", c.Name(), "ping")
	}
}

func TestPingCollector_Lifecycle(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{Enabled: true}, zap.NewNop())
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
		t.Fatalf("double Stop should be a no-op, got: %v", err)
	}
}

func TestPingCollector_NoTargets(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{Enabled: true}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect err: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil metrics, got %d", len(m))
	}
}

func TestPingCollector_UpTarget(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{
		Targets: []config.PingTarget{{Host: "127.0.0.1", Name: "localhost"}},
	}, zap.NewNop())
	c.SetPingerExported(&fakePinger{
		results: map[string]ping.PingStatsExported{
			"127.0.0.1": {
				Host:            "127.0.0.1",
				ResolvedIP:      "127.0.0.1",
				PacketsSent:     5,
				PacketsReceived: 5,
				Rtts: []time.Duration{
					1 * time.Millisecond,
					2 * time.Millisecond,
					1 * time.Millisecond,
				},
				TTL:   64,
				State: 1,
			},
		},
	})
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := len(metrics); got < 9 {
		t.Fatalf("expected at least 9 metrics, got %d", got)
	}

	stateMetric := findMetric(metrics, "network.ping.state")
	if stateMetric == nil {
		t.Fatal("missing network.ping.state metric")
	}
	if stateMetric.Value != 1 {
		t.Errorf("state=%v want 1", stateMetric.Value)
	}
	if stateMetric.Labels["target"] != "localhost" {
		t.Errorf("target label=%q want localhost", stateMetric.Labels["target"])
	}
	if stateMetric.Labels["host"] != "127.0.0.1" {
		t.Errorf("host label=%q want 127.0.0.1", stateMetric.Labels["host"])
	}
}

func TestPingCollector_DownTarget(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{
		Targets: []config.PingTarget{{Host: "192.0.2.1"}},
	}, zap.NewNop())
	c.SetPingerExported(&fakePinger{
		results: map[string]ping.PingStatsExported{
			"192.0.2.1": {
				Host:            "192.0.2.1",
				ResolvedIP:      "192.0.2.1",
				PacketsSent:     5,
				PacketsReceived: 0,
				State:           0,
			},
		},
	})
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	stateMetric := findMetric(metrics, "network.ping.state")
	if stateMetric == nil {
		t.Fatal("missing network.ping.state metric")
	}
	if stateMetric.Value != 0 {
		t.Errorf("state=%v want 0 (down)", stateMetric.Value)
	}
	if stateMetric.Labels["target"] != "192.0.2.1" {
		t.Errorf("target label=%q want 192.0.2.1 (falls back to Host)", stateMetric.Labels["target"])
	}

	lossMetric := findMetric(metrics, "network.ping.loss_percent")
	if lossMetric == nil {
		t.Fatal("missing network.ping.loss_percent metric")
	}
	if lossMetric.Value != 100 {
		t.Errorf("loss=%v want 100", lossMetric.Value)
	}
}

func TestPingCollector_InvalidHostStillEmitsDownState(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{
		Targets: []config.PingTarget{{Host: "nonexistent-host.invalid", Name: "ghost"}},
	}, zap.NewNop())
	c.SetPingerExported(&fakePinger{
		err: errors.New("lookup nonexistent-host.invalid: no such host"),
	})
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error on invalid host: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics for failed target, got none")
	}

	stateMetric := findMetric(metrics, "network.ping.state")
	if stateMetric == nil {
		t.Fatal("missing network.ping.state metric")
	}
	if stateMetric.Value != 0 {
		t.Errorf("state=%v want 0 on resolve failure", stateMetric.Value)
	}
	if stateMetric.Labels["target"] != "ghost" {
		t.Errorf("target label=%q want ghost", stateMetric.Labels["target"])
	}
}

func TestPingCollector_ContextCancellationStopsIteration(t *testing.T) {
	targets := []config.PingTarget{
		{Host: "a"}, {Host: "b"}, {Host: "c"},
	}
	c := ping.NewPingCollector(config.PingCollectorConfig{Targets: targets}, zap.NewNop())
	fp := &fakePinger{results: map[string]ping.PingStatsExported{}}
	c.SetPingerExported(fp)
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before first probe

	metrics, err := c.Collect(ctx)
	if err == nil {
		t.Fatal("expected ctx.Err() from cancelled Collect")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v want context.Canceled", err)
	}
	// At most one call before the select notices cancellation in this scheduling.
	if fp.calls > 1 {
		t.Errorf("calls=%d want <=1 after immediate cancel", fp.calls)
	}
	// Even with 0 calls there should be no metrics emitted.
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

func TestPingCollector_MultipleTargetsEachEmitMetrics(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{
		Targets: []config.PingTarget{
			{Host: "10.0.0.1", Name: "gw"},
			{Host: "10.0.0.2", Name: "dns"},
		},
	}, zap.NewNop())
	c.SetPingerExported(&fakePinger{
		results: map[string]ping.PingStatsExported{
			"10.0.0.1": {ResolvedIP: "10.0.0.1", PacketsSent: 3, PacketsReceived: 3, State: 1,
				Rtts: []time.Duration{1 * time.Millisecond}},
			"10.0.0.2": {ResolvedIP: "10.0.0.2", PacketsSent: 3, PacketsReceived: 0, State: 0},
		},
	})
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 2 targets * 9 metrics each = 18.
	if got := len(metrics); got != 18 {
		t.Fatalf("expected 18 metrics, got %d", got)
	}
}

func TestBuildPingMetrics_ExpectedSchema(t *testing.T) {
	stats := ping.PingStatsExported{
		Host:            "1.2.3.4",
		ResolvedIP:      "1.2.3.4",
		PacketsSent:     5,
		PacketsReceived: 4,
		Rtts: []time.Duration{
			1 * time.Millisecond,
			2 * time.Millisecond,
			3 * time.Millisecond,
			4 * time.Millisecond,
		},
		TTL:   64,
		State: 1,
	}
	metrics := ping.BuildPingMetricsExported(stats, config.PingTarget{Host: "1.2.3.4", Name: "router"}, time.Now())

	expected := []string{
		"network.ping.rtt_min_ms",
		"network.ping.rtt_avg_ms",
		"network.ping.rtt_max_ms",
		"network.ping.rtt_stddev_ms",
		"network.ping.packets_sent",
		"network.ping.packets_received",
		"network.ping.loss_percent",
		"network.ping.ttl",
		"network.ping.state",
	}
	seen := make(map[string]bool)
	for _, m := range metrics {
		seen[m.Name] = true
		if m.Type != collector.MetricTypeGauge {
			t.Errorf("%s type=%v want gauge", m.Name, m.Type)
		}
		if m.Labels["target"] != "router" {
			t.Errorf("%s target=%q want router", m.Name, m.Labels["target"])
		}
		if m.Labels["host"] != "1.2.3.4" {
			t.Errorf("%s host=%q want 1.2.3.4", m.Name, m.Labels["host"])
		}
	}
	for _, name := range expected {
		if !seen[name] {
			t.Errorf("missing metric %s", name)
		}
	}

	cases := []struct {
		name string
		want float64
	}{
		{"network.ping.rtt_min_ms", 1.0},
		{"network.ping.rtt_max_ms", 4.0},
		{"network.ping.rtt_avg_ms", 2.5},
		{"network.ping.packets_sent", 5},
		{"network.ping.packets_received", 4},
		{"network.ping.loss_percent", 20.0},
		{"network.ping.ttl", 64},
		{"network.ping.state", 1},
	}
	for _, tc := range cases {
		m := findMetric(metrics, tc.name)
		if m == nil {
			t.Fatalf("missing %s", tc.name)
		}
		if m.Value != tc.want {
			t.Errorf("%s value=%v want %v", tc.name, m.Value, tc.want)
		}
	}

	// stddev of {1,2,3,4}: mean=2.5, var=(2.25+0.25+0.25+2.25)/4=1.25, stddev≈1.118
	std := findMetric(metrics, "network.ping.rtt_stddev_ms")
	if std == nil {
		t.Fatal("missing stddev")
	}
	wantStd := 1.118033988749895
	if diff := std.Value - wantStd; diff < -1e-6 || diff > 1e-6 {
		t.Errorf("stddev=%v want %v", std.Value, wantStd)
	}
}

func TestBuildPingMetrics_AllPacketsLostReports100PercentLoss(t *testing.T) {
	stats := ping.PingStatsExported{
		ResolvedIP:      "192.0.2.1",
		PacketsSent:     0, // resolve failed; nothing sent
		PacketsReceived: 0,
		State:           0,
	}
	metrics := ping.BuildPingMetricsExported(stats, config.PingTarget{Host: "192.0.2.1"}, time.Now())
	if got := findMetric(metrics, "network.ping.loss_percent").Value; got != 100 {
		t.Errorf("loss=%v want 100 when no packets sent", got)
	}
	if got := findMetric(metrics, "network.ping.state").Value; got != 0 {
		t.Errorf("state=%v want 0", got)
	}
	if got := findMetric(metrics, "network.ping.packets_sent").Value; got != 0 {
		t.Errorf("packets_sent=%v want 0", got)
	}
}

func TestBuildPingMetrics_NameFallsBackToHost(t *testing.T) {
	stats := ping.PingStatsExported{ResolvedIP: "10.0.0.1"}
	metrics := ping.BuildPingMetricsExported(stats, config.PingTarget{Host: "10.0.0.1"}, time.Now())
	if target := metrics[0].Labels["target"]; target != "10.0.0.1" {
		t.Errorf("target label=%q want 10.0.0.1 (fallback to Host)", target)
	}
}

func TestPingCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*ping.PingCollector)(nil)
}
