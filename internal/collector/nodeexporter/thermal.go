package nodeexporter

import (
	"github.com/shirou/gopsutil/v3/host"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectThermal collects hardware temperature metrics.
// Equivalent to node_exporter's hwmon/thermal_zone collector.
func (c *NodeExporterCollector) collectThermal() ([]collector.Metric, error) {
	temps, err := host.SensorsTemperatures()
	if err != nil {
		// Sensors not available on all platforms — return empty, not error
		return nil, nil
	}

	var metrics []collector.Metric
	for _, t := range temps {
		if t.Temperature == 0 {
			continue
		}
		metrics = append(metrics, collector.NewMetric(
			"node.thermal.temperature_celsius", t.Temperature, collector.MetricTypeGauge,
		).WithLabel("sensor", t.SensorKey).
			WithUnit("celsius").
			WithDescription("Hardware temperature in Celsius"))
	}

	return metrics, nil
}
