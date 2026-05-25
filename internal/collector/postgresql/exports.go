// Package postgresql exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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

package postgresql

import (
	"context"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// PGTestInstance is a test-visible representation of the internal pgInstance.
// It mirrors the internal fields with exported names so that external test
// packages can construct and inspect instances without accessing unexported
// symbols.
type PGTestInstance struct {
	Config            config.PostgreSQLInstanceConfig
	Version           int
	VersionStr        string
	Flavor            string
	PrevCounters      map[string]uint64
	PrevTimestamp     time.Time
	TopQueriesLimit   int
	TopTablesLimit    int
	DeadTuplePrev     uint64
	DeadTuplePrevTime time.Time
}

func (p *PGTestInstance) toInternal() *pgInstance {
	return &pgInstance{
		config:            p.Config,
		version:           p.Version,
		versionStr:        p.VersionStr,
		flavor:            p.Flavor,
		prevCounters:      p.PrevCounters,
		prevTimestamp:     p.PrevTimestamp,
		topQueriesLimit:   p.TopQueriesLimit,
		topTablesLimit:    p.TopTablesLimit,
		deadTuplePrev:     p.DeadTuplePrev,
		deadTuplePrevTime: p.DeadTuplePrevTime,
	}
}

// NewPGTestInstance creates a PGTestInstance with sensible defaults.
func NewPGTestInstance(cfg config.PostgreSQLInstanceConfig) *PGTestInstance {
	return &PGTestInstance{
		Config:       cfg,
		PrevCounters: make(map[string]uint64),
	}
}

// --- Exported function wrappers ---

func SafeDivExported(num, denom float64) float64 { return safeDiv(num, denom) }

func ParseFloatExported(val string) float64 { return parseFloat(val) }

func MakeMetricExported(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}

func EmitCounterRateExported(name string, rate float64, labels map[string]string) collector.Metric {
	return emitCounterRate(name, rate, labels)
}

func InstanceLabelsExported(inst *PGTestInstance) map[string]string {
	return instanceLabels(inst.toInternal())
}

func BuildConnStringExported(cfg config.PostgreSQLInstanceConfig) string {
	return buildConnString(cfg)
}

func ResolveEnvVarsExported(s string) string { return resolveEnvVars(s) }

func CopyLabelsExported(src map[string]string) map[string]string { return copyLabels(src) }

func FingerprintQueryExported(query string) string { return fingerprintQuery(query) }

func HasPgStatWalExported(inst *PGTestInstance) bool {
	return hasPgStatWal(inst.toInternal())
}

func HasExecTimeColumnsExported(inst *PGTestInstance) bool {
	return hasExecTimeColumns(inst.toInternal())
}

func ResourceAttrsFromMetricExported(m collector.Metric) map[string]string {
	return resourceAttrsFromMetric(m)
}

func ResourceAttrsFromInstanceExported(inst *PGTestInstance) map[string]string {
	return resourceAttrsFromInstance(inst.toInternal())
}

func MakeTableLabelsExported(base map[string]string, schemaName, relName string) map[string]string {
	return makeTableLabels(base, schemaName, relName)
}

func MakeIndexLabelsExported(base map[string]string, schemaName, relName, idxName string) map[string]string {
	return makeIndexLabels(base, schemaName, relName, idxName)
}

func NewConfigExported(cfg config.PostgreSQLCollectorConfig) Config {
	return NewConfig(cfg)
}

// EmitMetricsForInstanceExported wraps OTLPEmitter.EmitMetricsForInstance
// for use by external test packages.
func (e *OTLPEmitter) EmitMetricsForInstanceExported(ctx context.Context, metrics []collector.Metric, inst *PGTestInstance) error {
	return e.EmitMetricsForInstance(ctx, metrics, inst.toInternal())
}
