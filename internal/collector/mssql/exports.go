package mssql

import (
	"context"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

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

func NewMSSQLTestInstance(cfg config.MSSQLInstanceConfig) *MSSQLTestInstance {
	return &MSSQLTestInstance{
		Config:       cfg,
		PrevCounters: make(map[string]float64),
	}
}

func SafeDivExported(num, denom float64) float64 { return safeDiv(num, denom) }

func MakeMetricExported(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}

func EmitCounterRateExported(name string, rate float64, labels map[string]string) collector.Metric {
	return emitCounterRate(name, rate, labels)
}

func InstanceLabelsExported(inst *MSSQLTestInstance) map[string]string {
	return instanceLabels(inst.toInternal())
}

func BuildConnStringExported(cfg config.MSSQLInstanceConfig) string {
	return buildConnString(cfg)
}

func ResolveEnvVarsExported(s string) string { return resolveEnvVars(s) }

func CopyLabelsExported(src map[string]string) map[string]string { return copyLabels(src) }

func NewConfigExported(cfg config.MSSQLCollectorConfig) Config {
	return NewConfig(cfg)
}

func CategorizeWaitExported(waitType string) string { return categorizeWait(waitType) }

func HHMMSSToSecondsExported(hhmmss int) float64 { return hhmmssToSeconds(hhmmss) }

func (e *OTLPEmitter) EmitMetricsForInstanceExported(ctx interface{}, metrics []collector.Metric, inst *MSSQLTestInstance) error {
	return e.EmitMetricsForInstance(context.TODO(), metrics, inst.toInternal())
}
