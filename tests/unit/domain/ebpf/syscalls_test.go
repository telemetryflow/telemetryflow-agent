// Package ebpf_test provides unit tests for eBPF syscall metric structures.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package ebpf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func TestSyscallMetricStructure(t *testing.T) {
	// Verify the expected metric structure for syscall metrics
	expectedMetrics := []struct {
		name       string
		metricType collector.MetricType
	}{
		{"ebpf.syscall.count", collector.MetricTypeCounter},
		{"ebpf.syscall.latency_ns", collector.MetricTypeCounter},
		{"ebpf.syscall.errors", collector.MetricTypeCounter},
	}

	for _, em := range expectedMetrics {
		t.Run(em.name, func(t *testing.T) {
			m := collector.NewMetric(em.name, 42, em.metricType).
				WithLabel("pid", "1234").
				WithLabel("comm", "test").
				WithLabel("syscall", "read")

			assert.Equal(t, em.name, m.Name)
			assert.Equal(t, em.metricType, m.Type)
			assert.Equal(t, float64(42), m.Value)
			assert.Equal(t, "1234", m.Labels["pid"])
			assert.Equal(t, "test", m.Labels["comm"])
			assert.Equal(t, "read", m.Labels["syscall"])
		})
	}
}

func TestNetworkMetricStructure(t *testing.T) {
	tcpMetrics := []struct {
		name       string
		metricType collector.MetricType
	}{
		{"ebpf.tcp.connections", collector.MetricTypeCounter},
		{"ebpf.tcp.bytes_sent", collector.MetricTypeCounter},
		{"ebpf.tcp.bytes_recv", collector.MetricTypeCounter},
		{"ebpf.tcp.retransmits", collector.MetricTypeCounter},
		{"ebpf.tcp.rtt_ns", collector.MetricTypeGauge},
	}

	for _, em := range tcpMetrics {
		t.Run(em.name, func(t *testing.T) {
			m := collector.NewMetric(em.name, 100, em.metricType).
				WithLabel("pid", "5678").
				WithLabel("comm", "nginx")

			assert.Equal(t, em.name, m.Name)
			assert.Equal(t, em.metricType, m.Type)
			assert.Contains(t, m.Labels, "pid")
			assert.Contains(t, m.Labels, "comm")
		})
	}

	udpMetrics := []string{
		"ebpf.udp.packets_sent",
		"ebpf.udp.packets_recv",
	}

	for _, name := range udpMetrics {
		t.Run(name, func(t *testing.T) {
			m := collector.NewMetric(name, 50, collector.MetricTypeCounter).
				WithLabel("pid", "9012").
				WithLabel("comm", "dns")

			assert.Equal(t, name, m.Name)
			assert.Equal(t, collector.MetricTypeCounter, m.Type)
		})
	}
}

func TestFileIOMetricStructure(t *testing.T) {
	metrics := []string{
		"ebpf.fileio.operations",
		"ebpf.fileio.bytes",
		"ebpf.fileio.latency_ns",
	}

	operations := []string{"read", "write", "open"}

	for _, name := range metrics {
		for _, op := range operations {
			t.Run(name+"/"+op, func(t *testing.T) {
				m := collector.NewMetric(name, 10, collector.MetricTypeCounter).
					WithLabel("pid", "100").
					WithLabel("comm", "cat").
					WithLabel("operation", op)

				assert.Equal(t, name, m.Name)
				assert.Equal(t, op, m.Labels["operation"])
			})
		}
	}
}

func TestSchedulerMetricStructure(t *testing.T) {
	metrics := []struct {
		name       string
		metricType collector.MetricType
	}{
		{"ebpf.sched.context_switches", collector.MetricTypeCounter},
		{"ebpf.sched.runq_latency_ns", collector.MetricTypeGauge},
		{"ebpf.sched.oncpu_ns", collector.MetricTypeCounter},
		{"ebpf.sched.migrations", collector.MetricTypeCounter},
	}

	for _, em := range metrics {
		t.Run(em.name, func(t *testing.T) {
			m := collector.NewMetric(em.name, 5, em.metricType).
				WithLabel("pid", "200").
				WithLabel("comm", "sched_test")

			assert.Equal(t, em.name, m.Name)
			assert.Equal(t, em.metricType, m.Type)
		})
	}
}

func TestMemoryMetricStructure(t *testing.T) {
	metrics := []string{
		"ebpf.memory.page_faults",
		"ebpf.memory.major_faults",
		"ebpf.memory.minor_faults",
	}

	for _, name := range metrics {
		t.Run(name, func(t *testing.T) {
			m := collector.NewMetric(name, 3, collector.MetricTypeCounter).
				WithLabel("pid", "300").
				WithLabel("comm", "mem_test")

			assert.Equal(t, name, m.Name)
			assert.Equal(t, collector.MetricTypeCounter, m.Type)
		})
	}
}

func TestTCPStateMetricStructure(t *testing.T) {
	m := collector.NewMetric("ebpf.tcp.state_transitions", 1, collector.MetricTypeCounter).
		WithLabel("pid", "400").
		WithLabel("old_state", "SYN_SENT").
		WithLabel("new_state", "ESTABLISHED")

	assert.Equal(t, "ebpf.tcp.state_transitions", m.Name)
	assert.Equal(t, collector.MetricTypeCounter, m.Type)
	assert.Equal(t, "SYN_SENT", m.Labels["old_state"])
	assert.Equal(t, "ESTABLISHED", m.Labels["new_state"])
}

func TestHubbleMetricStructure(t *testing.T) {
	hubbleMetrics := []string{
		"hubble.flows",
		"hubble.drops",
		"hubble.policy_verdicts",
		"hubble.http_requests",
		"hubble.dns_queries",
	}

	for _, name := range hubbleMetrics {
		t.Run(name, func(t *testing.T) {
			m := collector.NewMetric(name, 10, collector.MetricTypeCounter).
				WithLabel("source", "hubble")

			assert.Equal(t, name, m.Name)
			assert.Equal(t, collector.MetricTypeCounter, m.Type)
			assert.Equal(t, "hubble", m.Labels["source"])
		})
	}
}
