// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
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

package mysql

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func collectSchema(ctx context.Context, db *sql.DB, cfg config.MySQLInstanceConfig, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			TABLE_SCHEMA,
			TABLE_NAME,
			ENGINE,
			TABLE_ROWS,
			DATA_LENGTH,
			INDEX_LENGTH,
			DATA_FREE,
			AUTO_INCREMENT
		FROM information_schema.TABLES
		WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
	`

	rows, err := db.QueryContext(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var metrics []collector.Metric
	for rows.Next() {
		var schema, table, engine sql.NullString
		var tableRows, dataLen, indexLen, dataFree sql.NullInt64
		var autoIncr sql.NullInt64

		if err := rows.Scan(&schema, &table, &engine, &tableRows, &dataLen, &indexLen, &dataFree, &autoIncr); err != nil {
			continue
		}

		if !schema.Valid || !table.Valid {
			continue
		}

		tblLabels := make(map[string]string, len(labels)+2)
		for k, v := range labels {
			tblLabels[k] = v
		}
		tblLabels["database"] = schema.String
		tblLabels["table"] = table.String
		if engine.Valid {
			tblLabels["engine"] = engine.String
		}

		if dataLen.Valid {
			metrics = append(metrics, makeMetric("db.mysql.schema.data_size", float64(dataLen.Int64), collector.MetricTypeGauge, tblLabels))
		}
		if indexLen.Valid {
			metrics = append(metrics, makeMetric("db.mysql.schema.index_size", float64(indexLen.Int64), collector.MetricTypeGauge, tblLabels))
		}
		if dataFree.Valid {
			metrics = append(metrics, makeMetric("db.mysql.schema.data_free", float64(dataFree.Int64), collector.MetricTypeGauge, tblLabels))
		}
		if tableRows.Valid {
			metrics = append(metrics, makeMetric("db.mysql.schema.rows", float64(tableRows.Int64), collector.MetricTypeGauge, tblLabels))
		}
		if autoIncr.Valid && autoIncr.Int64 > 0 {
			maxVal := getAutoIncrMax(engine.String)
			usage := safeDiv(float64(autoIncr.Int64), float64(maxVal))
			metrics = append(metrics, makeMetric("db.mysql.schema.auto_increment_usage", usage, collector.MetricTypeGauge, tblLabels))
		}
	}

	return metrics, rows.Err()
}

func getAutoIncrMax(engine string) int64 {
	if strings.EqualFold(engine, "InnoDB") {
		return 1<<63 - 1
	}
	return 1<<31 - 1
}
