package mssql

import (
	"fmt"
	"math"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func makeMetric(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	m := collector.Metric{
		Name:      name,
		Type:      mtype,
		Value:     value,
		Timestamp: time.Now(),
		Labels:    make(map[string]string, len(labels)),
	}
	for k, v := range labels {
		m.Labels[k] = v
	}
	return m
}

func safeDiv(num, denom float64) float64 {
	if denom == 0 {
		return 0
	}
	return num / denom
}

var _ = parseFloat

func parseFloat(val interface{}) float64 {
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case string:
		var f float64
		_, _ = fmt.Sscanf(v, "%f", &f)
		return f
	default:
		return 0
	}
}

func emitCounterRate(name string, rate float64, labels map[string]string) collector.Metric {
	if math.IsNaN(rate) || math.IsInf(rate, 0) {
		rate = 0
	}
	return makeMetric(name, rate, collector.MetricTypeGauge, labels)
}

func instanceLabels(inst *mssqlInstance) map[string]string {
	labels := map[string]string{
		"mssql_instance": inst.config.Name,
		"mssql_host":     inst.config.Host,
	}
	if inst.version != "" {
		labels["mssql_version"] = inst.version
	}
	if inst.config.InstanceName != "" {
		labels["mssql_instance_name"] = inst.config.InstanceName
	}
	for k, v := range inst.config.Tags {
		labels[k] = v
	}
	return labels
}

func copyLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
