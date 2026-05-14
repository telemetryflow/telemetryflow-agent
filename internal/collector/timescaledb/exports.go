package timescaledb

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

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
