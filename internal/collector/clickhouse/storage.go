// Package clickhouse — disk and column-level storage metrics.
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
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectStorage gathers disk-level and per-table column storage metrics.
func collectStorage(
	ctx context.Context,
	conn *connection,
	labels map[string]string,
	logger *zap.Logger,
) ([]collector.Metric, error) {
	var metrics []collector.Metric

	// -----------------------------------------------------------------
	// system.disks — volume-level free / total / unreserved space
	// -----------------------------------------------------------------
	diskRows, err := conn.Execute(ctx, `
		SELECT name, free_space, total_space, unreserved_space, type
		FROM system.disks`)
	if err != nil {
		return nil, fmt.Errorf("system.disks query: %w", err)
	}

	for _, row := range diskRows {
		diskName := toString(row["name"])
		if diskName == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{
			"disk":      diskName,
			"disk_type": toString(row["type"]),
		})

		type dfield struct {
			key  string
			name string
		}
		dfields := []dfield{
			{"free_space", "db.clickhouse.disk.free_space"},
			{"total_space", "db.clickhouse.disk.total_space"},
			{"unreserved_space", "db.clickhouse.disk.unreserved_space"},
		}
		for _, f := range dfields {
			val, err := toFloat64(row[f.key])
			if err != nil {
				logger.Debug("system.disks: skip field",
					zap.String("disk", diskName), zap.String("field", f.key), zap.Error(err))
				continue
			}
			m := makeMetric(f.name, val, collector.MetricTypeGauge, lbl)
			m.Unit = "By"
			metrics = append(metrics, m)
		}

		// Derived used_space gauge
		freeVal, ferr := toFloat64(row["free_space"])
		totalVal, terr := toFloat64(row["total_space"])
		if ferr == nil && terr == nil && totalVal > 0 {
			usedPct := (totalVal - freeVal) / totalVal * 100
			m := makeMetric("db.clickhouse.disk.used_percent", usedPct, collector.MetricTypeGauge, lbl)
			m.Unit = "%"
			metrics = append(metrics, m)
		}
	}

	// -----------------------------------------------------------------
	// system.columns — per-table compressed / uncompressed column size
	// -----------------------------------------------------------------
	colQuery := `
		SELECT
			database,
			table,
			sum(data_compressed_bytes)   AS compressed_bytes,
			sum(data_uncompressed_bytes) AS uncompressed_bytes
		FROM system.columns
		GROUP BY database, table`

	colRows, err := conn.Execute(ctx, colQuery)
	if err != nil {
		logger.Debug("system.columns query failed", zap.Error(err))
		return metrics, nil
	}

	for _, row := range colRows {
		db := toString(row["database"])
		table := toString(row["table"])
		if db == "" || table == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{"db": db, "table": table})

		compressed, err := toFloat64(row["compressed_bytes"])
		if err == nil {
			m := makeMetric("db.clickhouse.columns.compressed_bytes", compressed, collector.MetricTypeGauge, lbl)
			m.Unit = "By"
			metrics = append(metrics, m)
		}
		uncompressed, err := toFloat64(row["uncompressed_bytes"])
		if err == nil {
			m := makeMetric("db.clickhouse.columns.uncompressed_bytes", uncompressed, collector.MetricTypeGauge, lbl)
			m.Unit = "By"
			metrics = append(metrics, m)
		}
	}

	return metrics, nil
}
