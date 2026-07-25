// Per-exporter self-observability stats.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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
package selfstat

// ExporterStats groups the per-exporter self-observability handles. Each
// field is pre-labelled with {"exporter": <name>} so multiple exporters can
// share the same metric names without colliding.
type ExporterStats struct {
	// MetricsWritten counts metrics successfully written by this exporter.
	MetricsWritten Stat
	// MetricsRejected counts metrics rejected by the remote endpoint.
	MetricsRejected Stat
	// MetricsDropped counts metrics dropped due to retries, buffer
	// overflow, or DLQ routing.
	MetricsDropped Stat
	// BufferedMetrics reports the current count of metrics buffered for
	// retry. Callers use Set (gauge semantics).
	BufferedMetrics Stat
	// BufferSize reports the current buffer occupancy in bytes; callers
	// use Set (gauge semantics).
	BufferSize Stat
	// BufferLimit reports the configured buffer capacity in bytes;
	// callers use Set (gauge semantics).
	BufferLimit Stat
	// WriteTimeNS accumulates per-batch write duration and reports the
	// running average (then clears) on each read.
	WriteTimeNS TimingStat
	// WriteErrors counts Write() failures.
	WriteErrors Stat
	// MetricsFiltered counts metrics removed by configured output
	// filters before reaching the wire.
	MetricsFiltered Stat
}

// ForExporter returns a populated ExporterStats for the named exporter.
// Handles are pre-labelled {"exporter": exporterName} and are stable for the
// lifetime of the process: calling ForExporter twice with the same name
// returns the same underlying stats.
func ForExporter(exporterName string) *ExporterStats {
	labels := map[string]string{"exporter": exporterName}
	return &ExporterStats{
		MetricsWritten:  RegisterStat("exporter.metrics_written", labels),
		MetricsRejected: RegisterStat("exporter.metrics_rejected", labels),
		MetricsDropped:  RegisterStat("exporter.metrics_dropped", labels),
		BufferedMetrics: RegisterStat("exporter.buffered_metrics", labels),
		BufferSize:      RegisterStat("exporter.buffer_size", labels),
		BufferLimit:     RegisterStat("exporter.buffer_limit", labels),
		WriteTimeNS:     RegisterTimingStat("exporter.write_time_ns", labels),
		WriteErrors:     RegisterStat("exporter.write_errors", labels),
		MetricsFiltered: RegisterStat("exporter.metrics_filtered", labels),
	}
}
