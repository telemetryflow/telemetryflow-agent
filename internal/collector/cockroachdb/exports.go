package cockroachdb

import (
	"context"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
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
