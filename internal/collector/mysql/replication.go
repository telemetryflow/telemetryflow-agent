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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectReplicationStatus(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "SHOW SLAVE STATUS")
	if err != nil {
		rows, err = db.QueryContext(ctx2, "SHOW REPLICA STATUS")
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = rows.Close() }()

	var allMetrics []collector.Metric
	for rows.Next() {
		cols, err := rows.Columns()
		if err != nil {
			continue
		}
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}

		colMap := make(map[string]string)
		for i, col := range cols {
			colMap[col] = toStr(values[i])
		}

		channelLabels := make(map[string]string, len(labels))
		for k, v := range labels {
			channelLabels[k] = v
		}
		if ch, ok := colMap["Channel_Name"]; ok && ch != "" {
			channelLabels["replication_channel"] = ch
		}

		allMetrics = append(allMetrics, parseReplicationRow(colMap, channelLabels)...)
	}
	return allMetrics, rows.Err()
}

func parseReplicationRow(colMap map[string]string, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric

	if val, ok := colMap["Seconds_Behind_Master"]; ok {
		if f := parseFloat(val); f >= 0 {
			metrics = append(metrics, makeMetric("db.mysql.replication.lag_seconds", f, collector.MetricTypeGauge, labels))
		}
	}

	if val, ok := colMap["Slave_IO_Running"]; ok {
		v := 0.0
		if strings.EqualFold(val, "Yes") {
			v = 1
		}
		metrics = append(metrics, makeMetric("db.mysql.replication.io_running", v, collector.MetricTypeGauge, labels))
	}

	if val, ok := colMap["Slave_SQL_Running"]; ok {
		v := 0.0
		if strings.EqualFold(val, "Yes") {
			v = 1
		}
		metrics = append(metrics, makeMetric("db.mysql.replication.sql_running", v, collector.MetricTypeGauge, labels))
	}

	if val, ok := colMap["Relay_Log_Space"]; ok {
		if f := parseFloat(val); f >= 0 {
			metrics = append(metrics, makeMetric("db.mysql.replication.relay_log_space", f, collector.MetricTypeGauge, labels))
		}
	}

	if val, ok := colMap["Retried_Transactions"]; ok {
		if f := parseFloat(val); f >= 0 {
			metrics = append(metrics, makeMetric("db.mysql.replication.retried_transactions", f, collector.MetricTypeGauge, labels))
		}
	}

	if val, ok := colMap["Last_Error"]; ok && val != "" {
		ml := make(map[string]string, len(labels))
		for k, v := range labels {
			ml[k] = v
		}
		ml["replication_last_error"] = val
		metrics = append(metrics, makeMetric("db.mysql.replication.last_error", 1, collector.MetricTypeGauge, ml))
	}

	return metrics
}

func toStr(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	default:
		return ""
	}
}
