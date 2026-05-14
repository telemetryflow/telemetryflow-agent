package cockroachdb

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

func parseFloat(val string) float64 {
	var f float64
	_, _ = fmt.Sscanf(val, "%f", &f)
	return f
}

func emitCounterRate(name string, rate float64, labels map[string]string) collector.Metric {
	if math.IsNaN(rate) || math.IsInf(rate, 0) {
		rate = 0
	}
	return makeMetric(name, rate, collector.MetricTypeGauge, labels)
}

func instanceLabels(inst *crdbInstance) map[string]string {
	labels := map[string]string{
		"cockroachdb_instance": inst.config.Name,
		"cockroachdb_host":     inst.config.Host,
	}
	if inst.version != "" {
		labels["cockroachdb_version"] = inst.version
	}
	if inst.clusterID != "" {
		labels["cockroachdb_cluster_id"] = inst.clusterID
	}
	if inst.nodeID > 0 {
		labels["cockroachdb_node_id"] = fmt.Sprintf("%d", inst.nodeID)
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
