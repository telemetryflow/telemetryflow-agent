// Package clickhouse — exported wrappers for unexported symbols used by external tests.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
package clickhouse

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// ToFloat64Exported exports toFloat64 for external tests.
func ToFloat64Exported(v interface{}) (float64, error) {
	return toFloat64(v)
}

// ToStringExported exports toString for external tests.
func ToStringExported(v interface{}) string {
	return toString(v)
}

// MergeLabelsExported exports mergeLabels for external tests.
func MergeLabelsExported(base, extra map[string]string) map[string]string {
	return mergeLabels(base, extra)
}

// MakeMetricExported exports makeMetric for external tests.
func MakeMetricExported(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}
