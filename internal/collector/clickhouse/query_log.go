// Package clickhouse — query_log collector: duration, rows, bytes, errors by query kind.
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
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// queryLogRow holds a single parsed row from system.query_log.
type queryLogRow struct {
	queryKind       string
	eventTime       time.Time
	queryDurationMs float64
	readRows        float64
	readBytes       float64
	memoryUsage     float64
	isException     bool
	user            string
}

// collectQueryLog fetches recent rows from system.query_log since lastWatermark
// and emits per-query-kind summary metrics.  Returns the new watermark.
func collectQueryLog(
	ctx context.Context,
	conn *connection,
	labels map[string]string,
	lastWatermark time.Time,
	maxRows int,
	logger *zap.Logger,
) ([]collector.Metric, time.Time, error) {
	// Use Unix timestamp comparison to avoid timezone complications in the query.
	watermarkTS := lastWatermark.Unix()

	query := fmt.Sprintf(`
		SELECT
			query_kind,
			event_time,
			query_duration_ms,
			read_rows,
			read_bytes,
			memory_usage,
			type,
			user
		FROM system.query_log
		WHERE
			type IN ('QueryFinish', 'ExceptionWhileProcessing')
			AND toUnixTimestamp(event_time) > %d
		ORDER BY event_time ASC
		LIMIT %d`,
		watermarkTS, maxRows)

	rows, err := conn.Execute(ctx, query)
	if err != nil {
		// query_log may be disabled — treat as non-fatal.
		if strings.Contains(err.Error(), "query_log") || strings.Contains(err.Error(), "Unknown table") {
			logger.Debug("system.query_log not available", zap.Error(err))
			return nil, lastWatermark, nil
		}
		return nil, lastWatermark, fmt.Errorf("system.query_log query: %w", err)
	}

	if len(rows) == 0 {
		return nil, lastWatermark, nil
	}

	// Parse rows.
	parsed := make([]queryLogRow, 0, len(rows))
	newWatermark := lastWatermark

	for _, row := range rows {
		kind := toString(row["query_kind"])
		if kind == "" {
			kind = "Unknown"
		}

		// Parse event_time — ClickHouse returns it as a string like "2026-04-26 12:00:00"
		var evTime time.Time
		if evStr := toString(row["event_time"]); evStr != "" {
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", evStr, time.UTC); err == nil {
				evTime = t
			}
		}
		if evTime.IsZero() {
			evTime = time.Now()
		}
		if evTime.After(newWatermark) {
			newWatermark = evTime
		}

		durationMs, _ := toFloat64(row["query_duration_ms"])
		readRows, _ := toFloat64(row["read_rows"])
		readBytes, _ := toFloat64(row["read_bytes"])
		memUsage, _ := toFloat64(row["memory_usage"])
		isException := toString(row["type"]) == "ExceptionWhileProcessing"

		parsed = append(parsed, queryLogRow{
			queryKind:       kind,
			eventTime:       evTime,
			queryDurationMs: durationMs,
			readRows:        readRows,
			readBytes:       readBytes,
			memoryUsage:     memUsage,
			isException:     isException,
			user:            toString(row["user"]),
		})
	}

	// Aggregate per query_kind.
	type kindStats struct {
		count      float64
		totalDurMs float64
		maxDurMs   float64
		totalRows  float64
		totalBytes float64
		totalMem   float64
		errors     float64
	}
	byKind := make(map[string]*kindStats)

	for _, r := range parsed {
		s, ok := byKind[r.queryKind]
		if !ok {
			s = &kindStats{}
			byKind[r.queryKind] = s
		}
		s.count++
		s.totalDurMs += r.queryDurationMs
		if r.queryDurationMs > s.maxDurMs {
			s.maxDurMs = r.queryDurationMs
		}
		s.totalRows += r.readRows
		s.totalBytes += r.readBytes
		s.totalMem += r.memoryUsage
		if r.isException {
			s.errors++
		}
	}

	var metrics []collector.Metric
	now := time.Now()

	for kind, s := range byKind {
		lbl := mergeLabels(labels, map[string]string{"query_kind": kind})

		avgDurMs := 0.0
		if s.count > 0 {
			avgDurMs = s.totalDurMs / s.count
		}

		type qfield struct {
			name  string
			value float64
			unit  string
		}
		qfields := []qfield{
			{"db.clickhouse.query_log.count", s.count, ""},
			{"db.clickhouse.query_log.duration_ms_total", s.totalDurMs, "ms"},
			{"db.clickhouse.query_log.duration_ms_avg", avgDurMs, "ms"},
			{"db.clickhouse.query_log.duration_ms_max", s.maxDurMs, "ms"},
			{"db.clickhouse.query_log.read_rows_total", s.totalRows, ""},
			{"db.clickhouse.query_log.read_bytes_total", s.totalBytes, "By"},
			{"db.clickhouse.query_log.memory_usage_total", s.totalMem, "By"},
			{"db.clickhouse.query_log.errors", s.errors, ""},
		}
		for _, f := range qfields {
			m := collector.Metric{
				Name:      f.name,
				Type:      collector.MetricTypeCounter,
				Value:     f.value,
				Timestamp: now,
				Labels:    make(map[string]string, len(lbl)),
			}
			for k, v := range lbl {
				m.Labels[k] = v
			}
			if f.unit != "" {
				m.Unit = f.unit
			}
			metrics = append(metrics, m)
		}
	}

	return metrics, newWatermark, nil
}
