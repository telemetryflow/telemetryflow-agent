// Package clickhouse — MergeTree parts, merges, and mutations metrics.
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

// collectMergeTree gathers per-table part statistics and in-progress merge/mutation info.
func collectMergeTree(
	ctx context.Context,
	conn *connection,
	labels map[string]string,
	logger *zap.Logger,
) ([]collector.Metric, error) {
	var metrics []collector.Metric

	// -----------------------------------------------------------------
	// system.parts — active part counts and sizes per table
	// -----------------------------------------------------------------
	partsQuery := `
		SELECT
			database,
			table,
			count()                                AS parts_count,
			sum(rows)                              AS total_rows,
			sum(bytes_on_disk)                     AS bytes_on_disk,
			sum(data_compressed_bytes)             AS compressed_bytes,
			sum(data_uncompressed_bytes)           AS uncompressed_bytes,
			countDistinct(partition_id)            AS partition_count
		FROM system.parts
		WHERE active = 1
		GROUP BY database, table`

	partRows, err := conn.Execute(ctx, partsQuery)
	if err != nil {
		return nil, fmt.Errorf("system.parts query: %w", err)
	}

	for _, row := range partRows {
		db := toString(row["database"])
		table := toString(row["table"])
		if db == "" || table == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{"db": db, "table": table})

		type field struct {
			key  string
			name string
			unit string
		}
		fields := []field{
			{"parts_count", "db.clickhouse.mergetree.parts_count", ""},
			{"total_rows", "db.clickhouse.mergetree.rows", ""},
			{"bytes_on_disk", "db.clickhouse.mergetree.bytes_on_disk", "By"},
			{"compressed_bytes", "db.clickhouse.mergetree.compressed_bytes", "By"},
			{"uncompressed_bytes", "db.clickhouse.mergetree.uncompressed_bytes", "By"},
			{"partition_count", "db.clickhouse.mergetree.partition_count", ""},
		}
		for _, f := range fields {
			val, err := toFloat64(row[f.key])
			if err != nil {
				logger.Debug("system.parts: skip field", zap.String("field", f.key), zap.Error(err))
				continue
			}
			m := makeMetric(f.name, val, collector.MetricTypeGauge, lbl)
			if f.unit != "" {
				m.Unit = f.unit
			}
			metrics = append(metrics, m)
		}
	}

	// -----------------------------------------------------------------
	// system.merges — in-progress merges
	// -----------------------------------------------------------------
	mergeQuery := `
		SELECT
			database,
			table,
			elapsed,
			progress,
			num_parts,
			is_mutation,
			total_size_bytes_compressed,
			bytes_read_uncompressed,
			rows_read,
			rows_written,
			memory_usage
		FROM system.merges`

	mergeRows, err := conn.Execute(ctx, mergeQuery)
	if err != nil {
		// Non-fatal: merges may not be running
		logger.Debug("system.merges query failed", zap.Error(err))
		return metrics, nil
	}

	for _, row := range mergeRows {
		db := toString(row["database"])
		table := toString(row["table"])
		if db == "" || table == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{"db": db, "table": table})

		type mfield struct {
			key  string
			name string
			unit string
		}
		mfields := []mfield{
			{"elapsed", "db.clickhouse.merge.elapsed_seconds", "s"},
			{"progress", "db.clickhouse.merge.progress", "1"},
			{"num_parts", "db.clickhouse.merge.num_parts", ""},
			{"total_size_bytes_compressed", "db.clickhouse.merge.total_size_bytes_compressed", "By"},
			{"bytes_read_uncompressed", "db.clickhouse.merge.bytes_read_uncompressed", "By"},
			{"rows_read", "db.clickhouse.merge.rows_read", ""},
			{"rows_written", "db.clickhouse.merge.rows_written", ""},
			{"memory_usage", "db.clickhouse.merge.memory_usage", "By"},
		}
		for _, f := range mfields {
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

		// is_mutation as a 0/1 gauge
		if isMutation, err := toFloat64(row["is_mutation"]); err == nil {
			metrics = append(metrics, makeMetric(
				"db.clickhouse.merge.is_mutation",
				isMutation,
				collector.MetricTypeGauge,
				lbl,
			))
		}
	}

	// -----------------------------------------------------------------
	// system.mutations — pending / failed mutations
	// -----------------------------------------------------------------
	mutationQuery := `
		SELECT
			database,
			table,
			mutation_id,
			is_done,
			parts_to_do,
			latest_fail_reason
		FROM system.mutations`

	mutRows, err := conn.Execute(ctx, mutationQuery)
	if err != nil {
		logger.Debug("system.mutations query failed", zap.Error(err))
		return metrics, nil
	}

	for _, row := range mutRows {
		db := toString(row["database"])
		table := toString(row["table"])
		mutID := toString(row["mutation_id"])
		if db == "" || table == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{
			"db":          db,
			"table":       table,
			"mutation_id": mutID,
		})

		isDone, _ := toFloat64(row["is_done"])
		partsToDo, _ := toFloat64(row["parts_to_do"])
		hasFail := 0.0
		if reason := toString(row["latest_fail_reason"]); reason != "" {
			hasFail = 1.0
		}

		metrics = append(metrics,
			makeMetric("db.clickhouse.mutation.is_done", isDone, collector.MetricTypeGauge, lbl),
			makeMetric("db.clickhouse.mutation.parts_to_do", partsToDo, collector.MetricTypeGauge, lbl),
			makeMetric("db.clickhouse.mutation.has_failure", hasFail, collector.MetricTypeGauge, lbl),
		)
	}

	return metrics, nil
}
