package mongodb

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func makeMetric(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return collector.NewMetric(name, value, mtype).WithLabels(labels)
}

func gauge(name string, value float64, labels map[string]string) collector.Metric {
	return makeMetric(name, value, collector.MetricTypeGauge, labels)
}

func counter(name string, value float64, labels map[string]string) collector.Metric {
	return makeMetric(name, value, collector.MetricTypeCounter, labels)
}

func copyLabels(src map[string]string) map[string]string {
	if src == nil {
		return make(map[string]string)
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func safeDiv(num, denom float64) float64 {
	if denom == 0 {
		return 0
	}
	return num / denom
}

func instanceLabels(inst *mongoInstance) map[string]string {
	labels := map[string]string{
		"db.system":   "mongodb",
		"db.instance": inst.config.Name,
	}
	for k, v := range inst.config.Tags {
		labels[k] = v
	}
	return labels
}

// Exported wrappers for external tests.

func GaugeExported(name string, value float64, labels map[string]string) collector.Metric {
	return gauge(name, value, labels)
}

func CounterExported(name string, value float64, labels map[string]string) collector.Metric {
	return counter(name, value, labels)
}

func SafeDivExported(num, denom float64) float64 { return safeDiv(num, denom) }
