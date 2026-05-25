// Package clickhouse — dictionary load status and memory usage metrics.
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
package clickhouse

import (
	"context"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectDictionaries gathers metrics from system.dictionaries.
func collectDictionaries(
	ctx context.Context,
	conn *connection,
	labels map[string]string,
	logger *zap.Logger,
) ([]collector.Metric, error) {
	rows, err := conn.Execute(ctx, `
		SELECT
			database,
			name,
			status,
			bytes_allocated,
			element_count,
			load_factor,
			loading_duration
		FROM system.dictionaries`)
	if err != nil {
		// system.dictionaries may not exist on very old ClickHouse versions.
		logger.Debug("system.dictionaries query failed", zap.Error(err))
		return nil, nil
	}

	var metrics []collector.Metric

	// Map dictionary status to a numeric code for alerting.
	statusCode := map[string]float64{
		"NOT_LOADED":           0,
		"LOADED":               1,
		"FAILED":               2,
		"LOADING":              3,
		"LOADED_AND_RELOADING": 4,
		"FAILED_AND_RELOADING": 5,
	}

	for _, row := range rows {
		db := toString(row["database"])
		name := toString(row["name"])
		if name == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{"db": db, "dict": name})

		// Status as numeric gauge
		status := toString(row["status"])
		code, ok := statusCode[status]
		if !ok {
			code = -1
		}
		metrics = append(metrics, makeMetric(
			"db.clickhouse.dictionary.status",
			code,
			collector.MetricTypeGauge,
			mergeLabels(lbl, map[string]string{"status": status}),
		))

		type dfield struct {
			key  string
			name string
			unit string
		}
		dfields := []dfield{
			{"bytes_allocated", "db.clickhouse.dictionary.bytes_allocated", "By"},
			{"element_count", "db.clickhouse.dictionary.element_count", ""},
			{"load_factor", "db.clickhouse.dictionary.load_factor", "1"},
			{"loading_duration", "db.clickhouse.dictionary.loading_duration", "s"},
		}
		for _, f := range dfields {
			val, err := toFloat64(row[f.key])
			if err != nil {
				continue
			}
			m := makeMetric(f.name, val, collector.MetricTypeGauge, lbl)
			if f.unit != "" {
				m.Unit = f.unit
			}
			metrics = append(metrics, m)
		}
	}

	return metrics, nil
}
