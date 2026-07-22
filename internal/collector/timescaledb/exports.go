package timescaledb

import (
	"context"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// CollectInstanceMetricsExport drives the per-instance metric collection
// (version detection + all collect* calls) against a querier.
func CollectInstanceMetricsExport(ctx context.Context, q PgxQuerier, inst *TsdbInstanceExport, logger *zap.Logger) []collector.Metric {
	return collectInstanceMetrics(ctx, q, (*tsdbInstance)(inst), logger)
}

func DetectPGVersionExport(ctx context.Context, q PgxQuerier, inst *TsdbInstanceExport) error {
	return detectPGVersion(ctx, q, (*tsdbInstance)(inst))
}

func DetectTimescaleDBExport(ctx context.Context, q PgxQuerier, inst *TsdbInstanceExport) error {
	return detectTimescaleDB(ctx, q, (*tsdbInstance)(inst))
}

func BuildConnStringExport(cfg config.TimescaleDBInstanceConfig) string {
	return buildConnString(cfg)
}

// AdvanceBackoffExport / CloseConnectionExport exercise the connection
// back-off bookkeeping without a live pool.
func (c *TimescaleDBCollector) AdvanceBackoffExport(inst *TsdbInstanceExport) {
	c.advanceBackoff((*tsdbInstance)(inst))
}

func (c *TimescaleDBCollector) CloseConnectionExport(inst *TsdbInstanceExport) {
	c.closeConnection((*tsdbInstance)(inst))
}

// ForceBackoffAllExport puts every configured instance into connection
// back-off, so Collect/collectAll* exercise their error paths without a
// live database.
func (c *TimescaleDBCollector) ForceBackoffAllExport() {
	for _, inst := range c.instances {
		c.advanceBackoff(inst)
	}
}

// EnsureConnectionNoBackoffExport invokes ensureConnection against an instance
// that is NOT in back-off, so a config that fails pgxpool.ParseConfig exercises
// the parse-error branch (advanceBackoff + error return) without any network.
func (c *TimescaleDBCollector) EnsureConnectionNoBackoffExport(ctx context.Context, inst *TsdbInstanceExport) error {
	_, err := c.ensureConnection(ctx, (*tsdbInstance)(inst))
	return err
}

// EnsureConnectionExport invokes ensureConnection against an instance that is
// already in back-off, covering the early back-off return without a live DB.
func (c *TimescaleDBCollector) EnsureConnectionExport(ctx context.Context, inst *TsdbInstanceExport) error {
	real := (*tsdbInstance)(inst)
	c.advanceBackoff(real)
	_, err := c.ensureConnection(ctx, real)
	return err
}

// --- QAN seams ---

type QANTsInstanceExport qanTsInstance

func NewQANTsInstanceExport(cfg config.TimescaleDBInstanceConfig) *QANTsInstanceExport {
	return (*QANTsInstanceExport)(&qanTsInstance{
		config:       cfg,
		prevSnapshot: make(map[string]*tsSnapshot),
	})
}

func CollectQANBucketsExport(ctx context.Context, q PgxQuerier, inst *QANTsInstanceExport, topQueriesLimit int, globalLabels map[string]string) ([]qan.QANMetricsBucket, error) {
	return collectQANBuckets(ctx, q, (*qanTsInstance)(inst), topQueriesLimit, globalLabels)
}

func QANInstanceLabelsExport(inst *QANTsInstanceExport, globalLabels map[string]string) map[string]string {
	return qanInstanceLabels((*qanTsInstance)(inst), globalLabels)
}

// Test-only export seams for the collect* functions. They accept PgxQuerier so
// tests can drive them with pgxmock instead of a live *pgxpool.Pool.

func CollectPGBaseMetricsExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectPGBaseMetrics(ctx, q, labels, logger)
}

func CollectConnectionStatsExport(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectConnectionStats(ctx, q, labels)
}

func CollectDatabaseStatsExport(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectDatabaseStats(ctx, q, labels)
}

func CollectActivityStatsExport(ctx context.Context, q PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	return collectActivityStats(ctx, q, labels)
}

func CollectChunksExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectChunks(ctx, q, labels, logger)
}

func CollectCompressionExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectCompression(ctx, q, labels, logger)
}

func CollectContinuousAggregatesExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectContinuousAggregates(ctx, q, labels, logger)
}

func CollectDataNodesExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectDataNodes(ctx, q, labels, logger)
}

func CollectHypertablesExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectHypertables(ctx, q, labels, logger)
}

func CollectJobsExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectJobs(ctx, q, labels, logger)
}

func CollectRetentionExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectRetention(ctx, q, labels, logger)
}

func CollectTieringExport(ctx context.Context, q PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectTiering(ctx, q, labels, logger)
}

func SafeDivExport(num, denom float64) float64 { return safeDiv(num, denom) }

func ParseFloatExport(val interface{}) float64 { return parseFloat(val) }

func MakeMetricExport(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}

func ResolveEnvVarsExport(s string) string { return resolveEnvVars(s) }

func CopyLabelsExport(src map[string]string) map[string]string { return copyLabels(src) }

func NewConfigExport(cfg config.TimescaleDBCollectorConfig) Config { return NewConfig(cfg) }

func InstanceLabelsExport(inst *TsdbInstanceExport) map[string]string {
	return instanceLabels((*tsdbInstance)(inst))
}

type TsdbInstanceExport tsdbInstance

func NewTsdbInstanceExport(cfg config.TimescaleDBInstanceConfig, pgVersionS, tsdbVer string) *TsdbInstanceExport {
	return (*TsdbInstanceExport)(&tsdbInstance{
		config:     cfg,
		pgVersionS: pgVersionS,
		tsdbVer:    tsdbVer,
	})
}
