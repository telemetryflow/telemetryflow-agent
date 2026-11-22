// Additional ping-collector coverage: driving the REAL default pinger (not a
// fake) against an RFC 2606 .invalid host so the DNS-lookup failure branch of
// defaultPinger.ping runs deterministically without sending any ICMP packets,
// plus the packetsSent==0 loss-default branch of buildPingMetrics. The ICMP
// send/recv loop and sleepBetween require a live network + raw sockets and are
// intentionally not exercised here.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package ping_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/ping"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// TestPing_RealPingerUnresolvableHost exercises defaultPinger.ping's
// net.LookupIP error path (it returns before any ICMP socket work) by using
// the production pinger — no fake injected — against a reserved .invalid name.
func TestPing_RealPingerUnresolvableHost(t *testing.T) {
	c := ping.NewPingCollector(config.PingCollectorConfig{
		Count:   1,
		Timeout: 500 * time.Millisecond,
		Targets: []config.PingTarget{{Host: "tfo-nonexistent.invalid", Name: "ghost"}},
	}, zap.NewNop())
	require.True(t, c.DefaultPingerInstalledExported(), "must use the real default pinger")

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err, "a failed probe still returns a down-state metric set")
	require.NotEmpty(t, metrics)

	// The target is unresolvable, so state must be down (0) and loss 100%.
	var state, loss float64
	var sawState, sawLoss bool
	for _, m := range metrics {
		switch m.Name {
		case "network.ping.state":
			state, sawState = m.Value, true
		case "network.ping.loss_percent":
			loss, sawLoss = m.Value, true
		}
	}
	require.True(t, sawState && sawLoss)
	assert.Equal(t, 0.0, state, "unresolvable host must be down")
	assert.Equal(t, 100.0, loss, "unresolvable host must report full loss")
}

// TestBuildPingMetrics_ZeroPacketsSent covers the loss-default branch: when no
// packets were sent the reported loss stays 100% (the packetsSent>0 guard is
// false) and the RTT stats are all zero (no rtts).
func TestBuildPingMetrics_ZeroPacketsSent(t *testing.T) {
	stats := ping.PingStatsExported{
		Host: "203.0.113.5", ResolvedIP: "203.0.113.5",
		PacketsSent: 0, PacketsReceived: 0, Rtts: nil, State: 0,
	}
	metrics := ping.BuildPingMetricsExported(stats, config.PingTarget{Host: "203.0.113.5"}, time.Now())

	got := map[string]float64{}
	for _, m := range metrics {
		got[m.Name] = m.Value
	}
	assert.Equal(t, 100.0, got["network.ping.loss_percent"])
	assert.Equal(t, 0.0, got["network.ping.rtt_avg_ms"])
	assert.Equal(t, 0.0, got["network.ping.rtt_min_ms"])
	assert.Equal(t, 0.0, got["network.ping.packets_sent"])
}

// TestBuildPingMetrics_NonMonotonicRTTs feeds RTTs that are neither ascending
// nor descending so both the min-reassignment and max-reassignment branches
// fire, and n>1 exercises the stddev computation.
func TestBuildPingMetrics_NonMonotonicRTTs(t *testing.T) {
	stats := ping.PingStatsExported{
		Host: "198.51.100.7", ResolvedIP: "198.51.100.7",
		PacketsSent: 3, PacketsReceived: 3, State: 1,
		Rtts: []time.Duration{30 * time.Millisecond, 10 * time.Millisecond, 50 * time.Millisecond},
	}
	metrics := ping.BuildPingMetricsExported(stats, config.PingTarget{Host: "198.51.100.7"}, time.Now())

	got := map[string]float64{}
	for _, m := range metrics {
		got[m.Name] = m.Value
	}
	assert.InDelta(t, 10.0, got["network.ping.rtt_min_ms"], 1e-6, "min must track the smallest RTT")
	assert.InDelta(t, 50.0, got["network.ping.rtt_max_ms"], 1e-6, "max must track the largest RTT")
	assert.InDelta(t, 30.0, got["network.ping.rtt_avg_ms"], 1e-6)
	assert.Greater(t, got["network.ping.rtt_stddev_ms"], 0.0, "stddev must be computed for n>1")
	assert.Equal(t, 0.0, got["network.ping.loss_percent"])
}
