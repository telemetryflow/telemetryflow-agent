// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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

package mysql

import (
	"context"
	"database/sql"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectQueryAnalytics(ctx context.Context, db *sql.DB, inst *mysqlInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var enabled int
	if err := db.QueryRowContext(ctx2,
		"SELECT COUNT(*) FROM performance_schema.setup_instruments WHERE NAME LIKE 'statement/%' AND ENABLED = 'YES'",
	).Scan(&enabled); err != nil || enabled == 0 {
		logger.Debug("performance_schema not available or statement instruments disabled",
			zap.String("instance", inst.config.Name),
		)
		return nil, nil
	}

	query := `
		SELECT
			DIGEST,
			DIGEST_TEXT,
			SCHEMA_NAME,
			COUNT_STAR,
			SUM_TIMER_WAIT / 1000000 AS total_time_us,
			SUM_ROWS_SENT,
			SUM_ROWS_EXAMINED,
			SUM_ROWS_AFFECTED,
			SUM_CREATED_TMP_TABLES,
			SUM_CREATED_TMP_DISK_TABLES,
			SUM_NO_INDEX_USED,
			SUM_SORT_ROWS,
			FIRST_SEEN,
			LAST_SEEN
		FROM performance_schema.events_statements_summary_by_digest
		WHERE DIGEST IS NOT NULL
	`

	rows, err := db.QueryContext(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	type digestRow struct {
		digest       string
		digestText   string
		schemaName   string
		countStar    uint64
		totalTimeUs  uint64
		rowsSent     uint64
		rowsExamined uint64
		rowsAffected uint64
		tmpTables    uint64
		tmpDisk      uint64
		noIndexUsed  uint64
		sortRows     uint64
		firstSeen    string
		lastSeen     string
	}

	var current []digestRow
	for rows.Next() {
		var r digestRow
		if err := rows.Scan(
			&r.digest, &r.digestText, &r.schemaName,
			&r.countStar, &r.totalTimeUs,
			&r.rowsSent, &r.rowsExamined, &r.rowsAffected,
			&r.tmpTables, &r.tmpDisk, &r.noIndexUsed, &r.sortRows,
			&r.firstSeen, &r.lastSeen,
		); err != nil {
			continue
		}
		current = append(current, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var metrics []collector.Metric
	for _, r := range current {
		prev, hasPrev := inst.prevDigests[r.digest]
		if !hasPrev {
			continue
		}

		deltaCount := int64(r.countStar) - int64(prev.CountStar)
		deltaTime := int64(r.totalTimeUs) - int64(prev.SumTimerWait)
		deltaRowsSent := int64(r.rowsSent) - int64(prev.SumRowsSent)
		deltaRowsExam := int64(r.rowsExamined) - int64(prev.SumRowsExam)

		if deltaCount <= 0 {
			continue
		}

		digestLabels := make(map[string]string, len(labels)+2)
		for k, v := range labels {
			digestLabels[k] = v
		}
		digestLabels["digest"] = r.digest
		if r.schemaName != "" && r.schemaName != "NULL" {
			digestLabels["schema"] = r.schemaName
		}

		metrics = append(metrics,
			makeMetric("db.mysql.query.calls", float64(deltaCount), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.total_time_us", float64(deltaTime), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.avg_time_us", float64(deltaTime)/float64(deltaCount), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.rows_sent", float64(deltaRowsSent), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.rows_examined", float64(deltaRowsExam), collector.MetricTypeGauge, digestLabels),
		)
	}

	newDigests := make(map[string]*digestSnapshot, len(current))
	for _, r := range current {
		newDigests[r.digest] = &digestSnapshot{
			CountStar:    r.countStar,
			SumTimerWait: r.totalTimeUs,
			SumRowsSent:  r.rowsSent,
			SumRowsExam:  r.rowsExamined,
		}
	}
	inst.prevDigests = newDigests

	return metrics, nil
}
