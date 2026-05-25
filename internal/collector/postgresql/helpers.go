// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

func instanceLabels(inst *pgInstance) map[string]string {
	labels := map[string]string{
		"postgresql_instance": inst.config.Name,
		"postgresql_host":     inst.config.Host,
	}
	if inst.flavor != "" {
		labels["postgresql_flavor"] = inst.flavor
	}
	if inst.versionStr != "" {
		labels["postgresql_version"] = inst.versionStr
	}
	for k, v := range inst.config.Tags {
		labels[k] = v
	}
	return labels
}
