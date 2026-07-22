package cockroachdb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

type CRDBTestInstance struct {
	Config        config.CockroachDBInstanceConfig
	Version       string
	ClusterID     string
	NodeID        int
	PrevCounters  map[string]uint64
	PrevTimestamp time.Time
	TopStmtsLimit int
}

func (p *CRDBTestInstance) toInternal() *crdbInstance {
	return &crdbInstance{
		config:        p.Config,
		version:       p.Version,
		clusterID:     p.ClusterID,
		nodeID:        p.NodeID,
		prevCounters:  p.PrevCounters,
		prevTimestamp: p.PrevTimestamp,
		topStmtsLimit: p.TopStmtsLimit,
	}
}

func NewCRDBTestInstance(cfg config.CockroachDBInstanceConfig) *CRDBTestInstance {
	return &CRDBTestInstance{
		Config:       cfg,
		PrevCounters: make(map[string]uint64),
	}
}

func SafeDivExported(num, denom float64) float64 { return safeDiv(num, denom) }

func ParseFloatExported(s string) float64 { return parseFloat(s) }

func BoolToFloatExported(b bool) float64 { return boolToFloat(b) }

func MakeMetricExported(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}

func EmitCounterRateExported(name string, rate float64, labels map[string]string) collector.Metric {
	return emitCounterRate(name, rate, labels)
}

func InstanceLabelsExported(inst *CRDBTestInstance) map[string]string {
	return instanceLabels(inst.toInternal())
}

func BuildConnStringExported(cfg config.CockroachDBInstanceConfig) string {
	return buildConnString(cfg)
}

func ResolveEnvVarsExported(s string) string { return resolveEnvVars(s) }

func CopyLabelsExported(src map[string]string) map[string]string { return copyLabels(src) }

func NewConfigExported(cfg config.CockroachDBCollectorConfig) Config {
	return NewConfig(cfg)
}

func (e *OTLPEmitter) EmitMetricsForInstanceExported(ctx context.Context, metrics []collector.Metric, inst *CRDBTestInstance) error {
	return e.EmitMetricsForInstance(ctx, metrics, inst.toInternal())
}

// --- Query-scanning seams for pgxmock-based unit tests ---

func CollectNodeMetricsExported(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectNodeMetrics(ctx, pool, labels, logger)
}

func CollectSQLMetricsExported(ctx context.Context, pool PgxQuerier, inst *CRDBTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	internal := inst.toInternal()
	metrics, err := collectSQLMetrics(ctx, pool, internal, labels, logger)
	// Reflect mutated delta-tracking state back to the caller.
	inst.PrevCounters = internal.prevCounters
	inst.PrevTimestamp = internal.prevTimestamp
	return metrics, err
}

func CollectStoreMetricsExported(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectStoreMetrics(ctx, pool, labels, logger)
}

func CollectStatementStatsExported(ctx context.Context, pool PgxQuerier, inst *CRDBTestInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectStatementStats(ctx, pool, inst.toInternal(), labels, logger)
}

func CollectRangeMetricsExported(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	return collectRangeMetrics(ctx, pool, labels, logger)
}

// DetectVersionExported runs version detection against pool and reflects the
// discovered version/cluster/node identifiers back onto inst.
func DetectVersionExported(ctx context.Context, pool PgxQuerier, inst *CRDBTestInstance, logger *zap.Logger) error {
	internal := inst.toInternal()
	err := detectVersion(ctx, pool, internal, logger)
	inst.Version = internal.version
	inst.ClusterID = internal.clusterID
	inst.NodeID = internal.nodeID
	return err
}

// CollectInstanceRowsExported drives the QAN statement-statistics scanning path
// against pool, operating on the collector's first configured instance. Calling
// it twice with increasing counters exercises the delta-computation branch.
func (c *QANCockroachDBCollector) CollectInstanceRowsExported(ctx context.Context, pool PgxQuerier) ([]qan.QANMetricsBucket, error) {
	return c.collectInstanceRows(ctx, pool, c.instances[0])
}
