// Package mssql exposes unexported symbols for external test packages.
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
//
// These wrappers forward to unexported symbols so that the external
// (black-box) test package tests/unit/domain/collector/mssql can exercise the
// query-collector functions that accept *sql.DB (via go-sqlmock) as well as the
// unexported collector internals, without any *_test.go living in-package.

package mssql

import (
	"context"
	"database/sql"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// MSSQLTestInstance is a test-visible representation of the internal
// mssqlInstance. It mirrors the internal fields with exported names so that
// external test packages can construct and inspect instances without accessing
// unexported symbols.
type MSSQLTestInstance struct {
	Config        config.MSSQLInstanceConfig
	Version       string
	EngineEdition int
	PrevCounters  map[string]float64
	PrevTimestamp time.Time
}

func (p *MSSQLTestInstance) toInternal() *mssqlInstance {
	return &mssqlInstance{
		config:        p.Config,
		version:       p.Version,
		engineEdition: p.EngineEdition,
		prevCounters:  p.PrevCounters,
		prevTimestamp: p.PrevTimestamp,
	}
}

// NewMSSQLTestInstance creates a MSSQLTestInstance with sensible defaults.
func NewMSSQLTestInstance(cfg config.MSSQLInstanceConfig) *MSSQLTestInstance {
	return &MSSQLTestInstance{
		Config:       cfg,
		PrevCounters: make(map[string]float64),
	}
}

// --- helpers.go ---

func SafeDivExported(num, denom float64) float64 { return safeDiv(num, denom) }

func ParseFloatExported(val interface{}) float64 { return parseFloat(val) }

func MakeMetricExported(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}

func EmitCounterRateExported(name string, rate float64, labels map[string]string) collector.Metric {
	return emitCounterRate(name, rate, labels)
}

func InstanceLabelsExported(inst *MSSQLTestInstance) map[string]string {
	return instanceLabels(inst.toInternal())
}

func CopyLabelsExported(src map[string]string) map[string]string { return copyLabels(src) }

// --- config.go ---

func NewConfigExported(cfg config.MSSQLCollectorConfig) Config {
	return NewConfig(cfg)
}

// --- connection.go ---

func ResolveEnvVarsExported(s string) string { return resolveEnvVars(s) }

func FindDefaultSepExported(s string) int { return findDefaultSep(s) }

func BuildConnStringExported(cfg config.MSSQLInstanceConfig) string {
	return buildConnString(cfg)
}

func HostPortExported(cfg config.MSSQLInstanceConfig) string { return hostPort(cfg) }

// --- version.go ---

// DetectVersionExported forwards to detectVersion and copies the detected
// version/edition back onto the test instance.
func DetectVersionExported(ctx context.Context, db *sql.DB, ti *MSSQLTestInstance, logger *zap.Logger) error {
	in := ti.toInternal()
	err := detectVersion(ctx, db, in, logger)
	ti.Version = in.version
	ti.EngineEdition = in.engineEdition
	return err
}

// --- waits.go ---

func CategorizeWaitExported(waitType string) string { return categorizeWait(waitType) }

func CollectWaitStatsExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectWaitStats(ctx, db, labels, logger)
}

// --- perfcounters.go ---

func PerfCounterQueriesLen() int { return len(perfCounterQueries) }

// CollectPerfCountersExported forwards to collectPerfCounters and copies the
// mutated prev-counter state back onto the test instance.
func CollectPerfCountersExported(ctx context.Context, db *sql.DB, ti *MSSQLTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	in := ti.toInternal()
	m, err := collectPerfCounters(ctx, db, in, labels, logger)
	ti.PrevCounters = in.prevCounters
	ti.PrevTimestamp = in.prevTimestamp
	return m, err
}

func QueryCounterExported(ctx context.Context, db *sql.DB, query string) (float64, error) {
	return queryCounter(ctx, db, query)
}

// --- fileio.go ---

func CollectFileIOExported(ctx context.Context, db *sql.DB, ti *MSSQLTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectFileIO(ctx, db, ti.toInternal(), labels, logger)
}

// --- tempdb.go ---

func CollectTempDBExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTempDB(ctx, db, labels, logger)
}

func CollectTempDBSpaceExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTempDBSpace(ctx, db, labels, logger)
}

func CollectTempDBContentionExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTempDBContention(ctx, db, labels, logger)
}

// --- ag.go ---

func CollectAGStatusExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectAGStatus(ctx, db, labels, logger)
}

// --- agentjobs.go ---

func HHMMSSToSecondsExported(hhmmss int) float64 { return hhmmssToSeconds(hhmmss) }

func CollectAgentJobsExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectAgentJobs(ctx, db, labels, logger)
}

// --- azure.go ---

func CollectAzureSQLDBMetricsExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectAzureSQLDBMetrics(ctx, db, labels, logger)
}

func CollectAzureDTUExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectAzureDTU(ctx, db, labels, logger)
}

func CollectAzureStorageExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectAzureStorage(ctx, db, labels, logger)
}

// --- indexes.go ---

func CollectIndexStatsExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectIndexStats(ctx, db, labels, logger)
}

func CollectMissingIndexesExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectMissingIndexes(ctx, db, labels, logger)
}

func CollectIndexFragmentationExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectIndexFragmentation(ctx, db, labels, logger)
}

func FmtNullStringExported(ns sql.NullString) string { return fmtNullString(ns) }

// --- queries.go ---

func CollectQueryStatsExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectQueryStats(ctx, db, labels, logger)
}

// --- querystore.go ---

func CollectQueryStoreExported(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectQueryStore(ctx, db, labels, logger)
}

// --- otlp_emit.go ---

func ResourceAttrsFromMetricExported(m collector.Metric) map[string]string {
	return resourceAttrsFromMetric(m)
}

func ResourceAttrsFromInstanceExported(inst *MSSQLTestInstance) map[string]string {
	return resourceAttrsFromInstance(inst.toInternal())
}

// EmitMetricsForInstanceExported wraps OTLPEmitter.EmitMetricsForInstance for
// use by external test packages.
func (e *OTLPEmitter) EmitMetricsForInstanceExported(ctx context.Context, metrics []collector.Metric, inst *MSSQLTestInstance) error {
	return e.EmitMetricsForInstance(ctx, metrics, inst.toInternal())
}

// --- MSSQLCollector internal accessors (mssql.go / connection.go) ---

func (c *MSSQLCollector) InstancesLen() int { return len(c.instances) }

func (c *MSSQLCollector) SetInstanceDB(i int, db *sql.DB) { c.instances[i].db = db }

func (c *MSSQLCollector) InstanceDB(i int) *sql.DB { return c.instances[i].db }

func (c *MSSQLCollector) SetInstanceEngineEdition(i, edition int) {
	c.instances[i].engineEdition = edition
}

func (c *MSSQLCollector) SetInstanceConnState(i int, lastConnErr time.Time, backoff time.Duration) {
	c.instances[i].lastConnErr = lastConnErr
	c.instances[i].backoff = backoff
}

func (c *MSSQLCollector) InstanceBackoff(i int) time.Duration { return c.instances[i].backoff }

func (c *MSSQLCollector) EnsureConnectionExported(ctx context.Context, i int) (*sql.DB, error) {
	return c.ensureConnection(ctx, c.instances[i])
}

func (c *MSSQLCollector) CloseConnectionExported(i int) { c.closeConnection(c.instances[i]) }

func (c *MSSQLCollector) AdvanceBackoffExported(i int) { c.advanceBackoff(c.instances[i]) }

func (c *MSSQLCollector) CollectAllQueriesExported(ctx context.Context) ([]collector.Metric, error) {
	return c.collectAllQueries(ctx)
}

func (c *MSSQLCollector) CollectAllIndexesExported(ctx context.Context) ([]collector.Metric, error) {
	return c.collectAllIndexes(ctx)
}

// --- QANMSSQLCollector internal accessors (qan_collector.go) ---

func BuildQANConnStringExported(cfg config.MSSQLInstanceConfig) string {
	return buildQANConnString(cfg)
}

func (c *QANMSSQLCollector) TopQueriesLimit() int { return c.cfg.TopQueriesLimit }

func (c *QANMSSQLCollector) QANInstancesLen() int { return len(c.instances) }

func (c *QANMSSQLCollector) SetQANInstanceDB(i int, db *sql.DB) { c.instances[i].db = db }

func (c *QANMSSQLCollector) QANInstanceDB(i int) *sql.DB { return c.instances[i].db }

func (c *QANMSSQLCollector) SetQANInstancePrevTime(i int, t time.Time) {
	c.instances[i].prevTime = t
}

func (c *QANMSSQLCollector) QANInstanceLabelsExported(i int) map[string]string {
	return c.instanceLabels(c.instances[i])
}

func (c *QANMSSQLCollector) QANEnsureConnectionExported(ctx context.Context, i int) (*sql.DB, error) {
	return c.ensureConnection(ctx, c.instances[i])
}

func (c *QANMSSQLCollector) CollectInstanceExported(ctx context.Context, i int) ([]qan.QANMetricsBucket, error) {
	return c.collectInstance(ctx, c.instances[i])
}
