// Package postgresql exposes unexported symbols for external test packages.
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

package postgresql

import (
	"context"
	"crypto/tls"
	"time"

	"go.uber.org/zap"

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

// --- Connection / lifecycle test seams (standard collector) ---

// ConnectFailurePathExported drives ensureConnection against an unreachable or
// mis-configured instance twice to exercise the connect-error and subsequent
// back-off branches, then closes the (nil) pool. It returns the error from each
// ensureConnection call. Used by external tests to cover connection.go without a
// live database.
func (c *PostgreSQLCollector) ConnectFailurePathExported(ctx context.Context, cfg config.PostgreSQLInstanceConfig) (firstErr, secondErr error) {
	inst := &pgInstance{config: cfg, prevCounters: make(map[string]uint64)}
	_, firstErr = c.ensureConnection(ctx, inst)
	_, secondErr = c.ensureConnection(ctx, inst)
	c.closeConnection(inst)
	return firstErr, secondErr
}

// AdvanceBackoffExported drives advanceBackoff n times on a fresh instance and
// returns the resulting backoff duration.
func (c *PostgreSQLCollector) AdvanceBackoffExported(n int) time.Duration {
	inst := &pgInstance{config: config.PostgreSQLInstanceConfig{Name: "t"}}
	for i := 0; i < n; i++ {
		c.advanceBackoff(inst)
	}
	return inst.backoff
}

// --- QAN collector test seams ---

func FingerprintQueryQANExported(query string) string { return fingerprintQueryQAN(query) }

// QANInstanceLabelsExported builds the QAN label set for an instance.
func QANInstanceLabelsExported(cfg QANConfig, inst config.PostgreSQLInstanceConfig) map[string]string {
	c := NewQANPostgreSQLCollector(cfg, zap.NewNop())
	return c.instanceLabels(&qanPgInstance{config: inst})
}

// --- RDS collector test seams ---

func BuildRDSConnStringExported(cfg config.RDSPostgreSQLInstanceConfig) string {
	return buildRDSConnString(cfg)
}

func RDSTLSConfigExported(caBundlePath string) (*tls.Config, error) {
	return rdsTLSConfig(caBundlePath)
}

func ApplyRDSInstanceDefaultsExported(inst *config.RDSPostgreSQLInstanceConfig) {
	applyRDSInstanceDefaults(inst)
}

func ContainsStringExported(s, substr string) bool { return containsString(s, substr) }

func HasRDSWalStatsExported(version int) bool {
	return hasRDSWalStats(&rdsPgInstance{version: version})
}

func RDSInstanceLabelsExported(inst config.RDSPostgreSQLInstanceConfig, versionStr string) map[string]string {
	return rdsInstanceLabels(&rdsPgInstance{config: inst, versionStr: versionStr})
}

// RDSToPgInstanceConfigExported converts an RDS instance config to the standard
// PostgreSQL instance config via rdsToPgInstance and returns the resulting config.
func RDSToPgInstanceConfigExported(inst config.RDSPostgreSQLInstanceConfig, version int) config.PostgreSQLInstanceConfig {
	return rdsToPgInstance(&rdsPgInstance{
		config:       inst,
		version:      version,
		prevCounters: make(map[string]uint64),
	}).config
}

// RDSConnectFailurePathExported drives ensureRDSConnection twice against an
// unreachable instance to exercise the connect-error, TLS-fallback, and back-off
// branches, then advances the backoff. It returns the error from each call.
func (c *RDSPostgreSQLCollector) RDSConnectFailurePathExported(ctx context.Context, cfg config.RDSPostgreSQLInstanceConfig) (firstErr, secondErr error) {
	inst := &rdsPgInstance{config: cfg, prevCounters: make(map[string]uint64)}
	_, firstErr = c.ensureRDSConnection(ctx, inst)
	_, secondErr = c.ensureRDSConnection(ctx, inst)
	return firstErr, secondErr
}

// EmitMetricsForInstanceExported wraps OTLPEmitter.EmitMetricsForInstance
// for use by external test packages.
func (e *OTLPEmitter) EmitMetricsForInstanceExported(ctx context.Context, metrics []collector.Metric, inst *PGTestInstance) error {
	return e.EmitMetricsForInstance(ctx, metrics, inst.toInternal())
}

// --- Query-path test seams (standard collector) ---
//
// These wrappers widen the unexported collect* functions to external test
// packages. Each accepts a PgxQuerier so that a pgxmock mock pool can drive the
// query-scanning bodies without a live database.

// DetectVersionExported runs detectVersion against the supplied querier and
// returns the resulting version, version string, and flavor.
func DetectVersionExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance) (int, string, string, error) {
	in := inst.toInternal()
	err := detectVersion(ctx, q, in)
	return in.version, in.versionStr, in.flavor, err
}

func CollectInstanceMetricsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectInstanceMetrics(ctx, q, inst.toInternal(), labels, logger)
}

func CollectConnectionMetricsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectConnectionMetrics(ctx, q, inst.toInternal(), labels)
}

func CollectTransactionMetricsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectTransactionMetrics(ctx, q, inst.toInternal(), labels)
}

func CollectBgWriterMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectBgWriterMetrics(ctx, q, labels)
}

func CollectWALMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectWALMetrics(ctx, q, labels)
}

func CollectDatabaseSizeMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectDatabaseSizeMetrics(ctx, q, labels)
}

func CollectLockMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectLockMetrics(ctx, q, labels, logger)
}

func CollectLocksByTypeExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectLocksByType(ctx, q, labels)
}

func CollectLocksByModeExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectLocksByMode(ctx, q, labels)
}

func CollectBlockedQueryMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectBlockedQueryMetrics(ctx, q, labels)
}

func CollectQueryAnalyticsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectQueryAnalytics(ctx, q, inst.toInternal(), labels, logger)
}

func CollectWaitEventsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectWaitEvents(ctx, q, labels, logger)
}

func CollectReplicationMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectReplicationMetrics(ctx, q, labels, logger)
}

func CollectReplicationLagExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectReplicationLag(ctx, q, labels, logger)
}

func CollectReplicationLagBytesExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectReplicationLagBytes(ctx, q, labels, logger)
}

func CollectReplicationSlotsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectReplicationSlots(ctx, q, labels, logger)
}

func CollectTableStatsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTableStats(ctx, q, inst.toInternal(), labels, logger)
}

func CollectTableStatMetricsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string, limit int, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTableStatMetrics(ctx, q, inst.toInternal(), labels, limit, logger)
}

func CollectTableIOMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTableIOMetrics(ctx, q, labels, logger)
}

func CollectIndexMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectIndexMetrics(ctx, q, labels, logger)
}

func CollectTableSizeMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, limit int, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTableSizeMetrics(ctx, q, labels, limit, logger)
}

func CollectBloatEstimatesExported(ctx context.Context, q PgxQuerier, labels map[string]string, limit int, logger *zap.Logger) ([]collector.Metric, error) {
	return collectBloatEstimates(ctx, q, labels, limit, logger)
}

func CollectIndexBloatEstimatesExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectIndexBloatEstimates(ctx, q, labels, logger)
}

func CollectUnusedIndexesExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectUnusedIndexes(ctx, q, labels, logger)
}

func CollectVacuumMetricsExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectVacuumMetrics(ctx, q, inst.toInternal(), labels, logger)
}

func CollectVacuumWorkersExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectVacuumWorkers(ctx, q, labels, logger)
}

func CollectVacuumProgressExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectVacuumProgress(ctx, q, labels, logger)
}

func CollectXIDAgeExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectXIDAge(ctx, q, labels, logger)
}

func CollectDeadTuplesExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectDeadTuples(ctx, q, labels, logger)
}

func CollectVacuumConfigExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectVacuumConfig(ctx, q, labels, logger)
}

func CollectTableXIDAgeExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTableXIDAge(ctx, q, labels, logger)
}

func CollectVacuumNeededExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectVacuumNeeded(ctx, q, labels, logger)
}

func CollectDeadTupleRateExported(ctx context.Context, q PgxQuerier, inst *PGTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectDeadTupleRate(ctx, q, inst.toInternal(), labels, logger)
}

func CollectSubscriptionMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectSubscriptionMetrics(ctx, q, labels, logger)
}

// --- Query-path test seams (RDS collector) ---

// RDSPGTestInstance is a test-visible representation of the internal
// rdsPgInstance for driving the RDS collect* functions from external tests.
type RDSPGTestInstance struct {
	Config        config.RDSPostgreSQLInstanceConfig
	Version       int
	VersionStr    string
	PrevCounters  map[string]uint64
	PrevTimestamp time.Time
}

func (p *RDSPGTestInstance) toInternal() *rdsPgInstance {
	return &rdsPgInstance{
		config:        p.Config,
		version:       p.Version,
		versionStr:    p.VersionStr,
		prevCounters:  p.PrevCounters,
		prevTimestamp: p.PrevTimestamp,
	}
}

// NewRDSPGTestInstance creates an RDSPGTestInstance with an initialised counter map.
func NewRDSPGTestInstance(cfg config.RDSPostgreSQLInstanceConfig) *RDSPGTestInstance {
	return &RDSPGTestInstance{Config: cfg, PrevCounters: make(map[string]uint64)}
}

// DetectRDSVersionExported runs detectRDSVersion and returns the resulting
// version number and version string.
func DetectRDSVersionExported(ctx context.Context, q PgxQuerier, inst *RDSPGTestInstance) (int, string, error) {
	in := inst.toInternal()
	err := detectRDSVersion(ctx, in, q, zap.NewNop())
	return in.version, in.versionStr, err
}

func CollectRDSConnectionMetricsExported(ctx context.Context, q PgxQuerier, inst *RDSPGTestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectRDSConnectionMetrics(ctx, q, inst.toInternal(), labels)
}

func CollectRDSTransactionMetricsExported(ctx context.Context, q PgxQuerier, inst *RDSPGTestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectRDSTransactionMetrics(ctx, q, inst.toInternal(), labels)
}

func CollectRDSBgWriterMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectRDSBgWriterMetrics(ctx, q, labels)
}

func CollectRDSWALMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectRDSWALMetrics(ctx, q, labels)
}

func CollectRDSLockMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectRDSLockMetrics(ctx, q, labels)
}

func CollectRDSReplicationMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectRDSReplicationMetrics(ctx, q, labels, logger)
}

func CollectRDSDatabaseSizeMetricsExported(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectRDSDatabaseSizeMetrics(ctx, q, labels)
}

// --- QAN collector query-path test seam ---

// CollectQANBucketsExported drives the QAN pg_stat_statements scan/delta body
// against the supplied querier for the collector's single configured instance.
func (c *QANPostgreSQLCollector) CollectQANBucketsExported(ctx context.Context, q PgxQuerier) (int, error) {
	if len(c.instances) == 0 {
		return 0, nil
	}
	buckets, err := c.collectQANBuckets(ctx, q, c.instances[0])
	return len(buckets), err
}

// CollectRDSActivityMetricsExported drives the RDS activity scan bodies against
// the supplied querier for the given test instance.
func (c *RDSPostgreSQLCollector) CollectRDSActivityMetricsExported(ctx context.Context, q PgxQuerier, inst *RDSPGTestInstance) []collector.Metric {
	return c.collectRDSActivityMetrics(ctx, q, inst.toInternal())
}
