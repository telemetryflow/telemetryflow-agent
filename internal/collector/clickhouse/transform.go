// Package clickhouse — helpers to convert ClickHouse HTTP JSON rows into
// collector.Metric values.
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
	"fmt"
	"strconv"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// makeMetric creates a collector.Metric with the given parameters and a fresh timestamp.
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

// toFloat64 converts a value from the ClickHouse JSON response to float64.
// ClickHouse serialises numbers as JSON strings in JSONEachRow format.
func toFloat64(v interface{}) (float64, error) {
	if v == nil {
		return 0, nil
	}
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case uint64:
		return float64(val), nil
	case string:
		if val == "" {
			return 0, nil
		}
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, fmt.Errorf("toFloat64: cannot parse %q: %w", val, err)
		}
		return f, nil
	default:
		// Best-effort: stringify then parse
		s := fmt.Sprintf("%v", val)
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("toFloat64: unsupported type %T value %v", val, val)
		}
		return f, nil
	}
}

// toString returns the string representation of a ClickHouse JSON value.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	default:
		return fmt.Sprintf("%v", val)
	}
}

// mergeLabels returns a new map that is the union of base and extra.
// Keys in extra override base.
func mergeLabels(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
