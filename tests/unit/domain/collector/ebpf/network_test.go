// Package ebpf_test contains unit tests for the eBPF collector domain logic
// including configuration, network event handling, and syscall tracking.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ebpf_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func TestNetworkMetricLabels(t *testing.T) {
	// Verify that network metrics carry the expected label set
	labels := map[string]string{
		"pid":  "1234",
		"comm": "curl",
	}

	tcpMetricNames := []string{
		"ebpf.tcp.connections",
		"ebpf.tcp.bytes_sent",
		"ebpf.tcp.bytes_recv",
		"ebpf.tcp.retransmits",
	}

	for _, name := range tcpMetricNames {
		t.Run(name, func(t *testing.T) {
			m := collector.NewMetric(name, 100, collector.MetricTypeCounter).
				WithLabels(labels)

			assert.Equal(t, "1234", m.Labels["pid"])
			assert.Equal(t, "curl", m.Labels["comm"])
		})
	}
}

func TestTCPRttMetricIsGauge(t *testing.T) {
	// RTT is a gauge (instantaneous measurement), not a counter
	m := collector.NewMetric("ebpf.tcp.rtt_ns", 50000, collector.MetricTypeGauge).
		WithLabel("pid", "5678").
		WithLabel("comm", "nginx")

	assert.Equal(t, collector.MetricTypeGauge, m.Type)
	assert.Equal(t, float64(50000), m.Value)
}

func TestUDPMetricLabels(t *testing.T) {
	labels := map[string]string{
		"pid":  "9012",
		"comm": "coredns",
	}

	udpMetricNames := []string{
		"ebpf.udp.packets_sent",
		"ebpf.udp.packets_recv",
	}

	for _, name := range udpMetricNames {
		t.Run(name, func(t *testing.T) {
			m := collector.NewMetric(name, 200, collector.MetricTypeCounter).
				WithLabels(labels)

			assert.Equal(t, collector.MetricTypeCounter, m.Type)
			assert.Equal(t, "9012", m.Labels["pid"])
			assert.Equal(t, "coredns", m.Labels["comm"])
		})
	}
}

func TestTCPStateTransitionLabels(t *testing.T) {
	transitions := []struct {
		oldState string
		newState string
	}{
		{"SYN_SENT", "ESTABLISHED"},
		{"ESTABLISHED", "FIN_WAIT1"},
		{"FIN_WAIT1", "FIN_WAIT2"},
		{"FIN_WAIT2", "TIME_WAIT"},
		{"TIME_WAIT", "CLOSE"},
		{"ESTABLISHED", "CLOSE_WAIT"},
		{"CLOSE_WAIT", "LAST_ACK"},
		{"LAST_ACK", "CLOSE"},
		{"LISTEN", "SYN_RECV"},
		{"SYN_RECV", "ESTABLISHED"},
	}

	for _, tt := range transitions {
		name := tt.oldState + "_to_" + tt.newState
		t.Run(name, func(t *testing.T) {
			m := collector.NewMetric("ebpf.tcp.state_transitions", 1, collector.MetricTypeCounter).
				WithLabel("pid", "100").
				WithLabel("old_state", tt.oldState).
				WithLabel("new_state", tt.newState)

			assert.Equal(t, tt.oldState, m.Labels["old_state"])
			assert.Equal(t, tt.newState, m.Labels["new_state"])
		})
	}
}

func TestNonLinuxReturnsEmptyMetrics(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("This test is for non-Linux platforms only")
	}

	c := newTestCollector(t)
	metrics, err := c.Collect(t.Context())
	assert.NoError(t, err)
	assert.Empty(t, metrics, "non-Linux should return empty metrics")
}

func TestMetricWithLabelsChaining(t *testing.T) {
	// Verify that WithLabels merges correctly
	m := collector.NewMetric("ebpf.tcp.connections", 5, collector.MetricTypeCounter).
		WithLabel("pid", "100").
		WithLabel("comm", "test").
		WithLabels(map[string]string{
			"extra": "label",
		})

	assert.Equal(t, "100", m.Labels["pid"])
	assert.Equal(t, "test", m.Labels["comm"])
	assert.Equal(t, "label", m.Labels["extra"])
	assert.Len(t, m.Labels, 3)
}
