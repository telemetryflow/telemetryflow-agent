// Agent-level pre-registered self-observability stats.
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

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// Agent-level counters. Subsystems mutate these directly (e.g.
// AgentMetricsWritten.Incr(1)) to report aggregate agent behaviour; an
// internal collector turns them into emitted metrics via AllMetrics.
var (
	// AgentMetricsWritten counts metrics successfully handed off to an
	// exporter.
	AgentMetricsWritten Stat
	// AgentMetricsRejected counts metrics rejected upstream (e.g. by a
	// processor or validation step).
	AgentMetricsRejected Stat
	// AgentMetricsDropped counts metrics intentionally dropped (e.g.
	// overflow, rate-limit, filter rules).
	AgentMetricsDropped Stat
	// AgentMetricsGathered counts metrics gathered across all collectors.
	AgentMetricsGathered Stat
	// AgentGatherErrors counts collector Gather() failures.
	AgentGatherErrors Stat
	// AgentGatherTimeouts counts collector Gather() timeouts.
	AgentGatherTimeouts Stat
	// AgentWriteErrors counts exporter Write() failures.
	AgentWriteErrors Stat
	// AgentBufferSize reports the current buffer occupancy; callers use
	// Set (gauge semantics).
	AgentBufferSize Stat
	// AgentBufferLimit reports the configured buffer capacity; callers
	// use Set (gauge semantics).
	AgentBufferLimit Stat
	// AgentVersionInfo is a constant gauge pinned to 1 that carries the
	// agent's version, commit, and build_time as labels for Prometheus
	// info-style cardinality.
	AgentVersionInfo Stat
)

// init pre-registers every agent-level stat so they exist in the global
// registry from process start, with deterministic label sets. Re-acquiring
// the same handle via RegisterStat with identical arguments returns the
// pre-registered instance.
func init() {
	AgentMetricsWritten = RegisterStat("agent.metrics_written", nil)
	AgentMetricsRejected = RegisterStat("agent.metrics_rejected", nil)
	AgentMetricsDropped = RegisterStat("agent.metrics_dropped", nil)
	AgentMetricsGathered = RegisterStat("agent.metrics_gathered", nil)
	AgentGatherErrors = RegisterStat("agent.gather_errors", nil)
	AgentGatherTimeouts = RegisterStat("agent.gather_timeouts", nil)
	AgentWriteErrors = RegisterStat("agent.write_errors", nil)
	AgentBufferSize = RegisterStat("agent.buffer_size", nil)
	AgentBufferLimit = RegisterStat("agent.buffer_limit", nil)
	AgentVersionInfo = RegisterStat("agent.version_info", map[string]string{
		"version":    version.Version,
		"commit":     version.GitCommit,
		"build_time": version.BuildTime,
	})
	// Version info is a constant info-gauge: always 1.
	AgentVersionInfo.Set(1)
}
