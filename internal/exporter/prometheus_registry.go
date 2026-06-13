// Package exporter contains all outbound data-path components: OTLP metric/
// trace/log export, periodic heartbeat to the TelemetryFlow backend, Kubernetes
// cluster-state sync, and the self-observability Prometheus registry and
// HTTP /metrics server.
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
package exporter

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// SelfMetrics contains agent self-observability Prometheus metrics.
type SelfMetrics struct {
	AgentInfo          *prometheus.GaugeVec
	Uptime             prometheus.Gauge
	CollectionDuration *prometheus.HistogramVec
	CollectionErrors   *prometheus.CounterVec
	MetricsCollected   *prometheus.CounterVec
	BufferSizeBytes    prometheus.Gauge
	BufferEntries      prometheus.Gauge
	ExportErrors       *prometheus.CounterVec
	ExportBytes        *prometheus.CounterVec
	HeartbeatSuccess   prometheus.Counter
	HeartbeatErrors    prometheus.Counter

	SupervisorCollectorsTotal   *prometheus.GaugeVec
	SupervisorCollectorRestarts *prometheus.CounterVec
}

// NewSelfMetrics creates and registers agent self-observability metrics
// in the given Prometheus registry.
func NewSelfMetrics(prefix string, registry *prometheus.Registry) *SelfMetrics {
	sm := &SelfMetrics{
		AgentInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "_agent_info",
			Help: "TelemetryFlow Agent build information",
		}, []string{"version", "go_version", "os", "arch"}),

		Uptime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prefix + "_agent_uptime_seconds",
			Help: "Agent uptime in seconds",
		}),

		CollectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    prefix + "_agent_collection_duration_seconds",
			Help:    "Time spent collecting metrics per collector",
			Buckets: prometheus.DefBuckets,
		}, []string{"collector"}),

		CollectionErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_agent_collection_errors_total",
			Help: "Collection error count per collector",
		}, []string{"collector"}),

		MetricsCollected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_agent_metrics_collected_total",
			Help: "Total metrics collected per collector",
		}, []string{"collector"}),

		BufferSizeBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prefix + "_agent_buffer_size_bytes",
			Help: "Current disk buffer size in bytes",
		}),

		BufferEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prefix + "_agent_buffer_entries",
			Help: "Current buffered entry count",
		}),

		ExportErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_agent_export_errors_total",
			Help: "Export error count per destination",
		}, []string{"destination"}),

		ExportBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_agent_export_bytes_total",
			Help: "Total bytes exported per destination",
		}, []string{"destination"}),

		HeartbeatSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_agent_heartbeat_success_total",
			Help: "Successful heartbeat count",
		}),

		HeartbeatErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_agent_heartbeat_errors_total",
			Help: "Failed heartbeat count",
		}),

		SupervisorCollectorsTotal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "_agent_supervisor_collectors",
			Help: "Number of collectors by state",
		}, []string{"state"}),

		SupervisorCollectorRestarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_agent_supervisor_collector_restarts_total",
			Help: "Number of collector restarts by collector name",
		}, []string{"collector"}),
	}

	// Register all metrics
	registry.MustRegister(
		sm.AgentInfo,
		sm.Uptime,
		sm.CollectionDuration,
		sm.CollectionErrors,
		sm.MetricsCollected,
		sm.BufferSizeBytes,
		sm.BufferEntries,
		sm.ExportErrors,
		sm.ExportBytes,
		sm.HeartbeatSuccess,
		sm.HeartbeatErrors,
		sm.SupervisorCollectorsTotal,
		sm.SupervisorCollectorRestarts,
	)

	// Set static agent info label
	sm.AgentInfo.With(prometheus.Labels{
		"version":    version.Short(),
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}).Set(1)

	return sm
}
