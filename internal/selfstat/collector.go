// Per-collector self-observability stats.
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

// CollectorStats groups the per-collector self-observability handles. Each
// field is pre-labelled with {"collector": <name>} so multiple collectors can
// share the same metric names without colliding.
type CollectorStats struct {
	// MetricsGathered counts successful metric gathers by this collector.
	MetricsGathered Stat
	// GatherTimeNS accumulates per-tick gather duration and reports the
	// running average (then clears) on each read.
	GatherTimeNS TimingStat
	// GatherErrors counts Gather() failures.
	GatherErrors Stat
	// GatherTimeouts counts Gather() timeouts.
	GatherTimeouts Stat
	// StartupErrors counts startup (Init/Start) failures.
	StartupErrors Stat
	// State reports the collector's lifecycle state as an integer
	// (0=stopped, 1=running, 2=backoff, 3=failed). Callers use Set.
	State Stat
}

// collectorState enumerates the documented lifecycle values for
// CollectorStats.State. The values are stable: external dashboards may rely
// on them.
const (
	CollectorStateStopped = 0
	CollectorStateRunning = 1
	CollectorStateBackoff = 2
	CollectorStateFailed  = 3
)

// ForCollector returns a populated CollectorStats for the named collector.
// Handles are pre-labelled {"collector": collectorName} and are stable for
// the lifetime of the process: calling ForCollector twice with the same name
// returns the same underlying stats.
func ForCollector(collectorName string) *CollectorStats {
	labels := map[string]string{"collector": collectorName}
	return &CollectorStats{
		MetricsGathered: RegisterStat("collector.metrics_gathered", labels),
		GatherTimeNS:    RegisterTimingStat("collector.gather_time_ns", labels),
		GatherErrors:    RegisterStat("collector.gather_errors", labels),
		GatherTimeouts:  RegisterStat("collector.gather_timeouts", labels),
		StartupErrors:   RegisterStat("collector.startup_errors", labels),
		State:           RegisterStat("collector.state", labels),
	}
}
