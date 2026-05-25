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
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectGaleraStatus(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var wsrepOn string
	if err := db.QueryRowContext(ctx2, "SHOW GLOBAL STATUS LIKE 'wsrep_on'").Scan(&nilStr{}, &wsrepOn); err != nil {
		return nil, err
	}
	if wsrepOn != "ON" {
		return nil, nil
	}

	galeraVars := map[string]string{
		"wsrep_cluster_size":         "db.mysql.galera.cluster_size",
		"wsrep_ready":                "db.mysql.galera.ready",
		"wsrep_flow_control_paused":  "db.mysql.galera.flow_control_paused",
		"wsrep_local_recv_queue_avg": "db.mysql.galera.recv_queue_avg",
		"wsrep_local_send_queue_avg": "db.mysql.galera.send_queue_avg",
		"wsrep_connected":            "db.mysql.galera.connected",
		"wsrep_local_state":          "db.mysql.galera.local_state",
	}

	var metrics []collector.Metric
	for statusName, metricName := range galeraVars {
		var val string
		if err := db.QueryRowContext(ctx2, "SHOW GLOBAL STATUS LIKE ?", statusName).Scan(&nilStr{}, &val); err != nil {
			continue
		}
		f := parseFloat(val)
		metrics = append(metrics, makeMetric(metricName, f, collector.MetricTypeGauge, labels))
	}

	var clusterStatus string
	if err := db.QueryRowContext(ctx2, "SHOW GLOBAL STATUS LIKE 'wsrep_cluster_status'").Scan(&nilStr{}, &clusterStatus); err == nil {
		if clusterStatus != "" {
			ml := make(map[string]string, len(labels))
			for k, v := range labels {
				ml[k] = v
			}
			ml["galera_cluster_status"] = clusterStatus
			metrics = append(metrics, makeMetric("db.mysql.galera.cluster_status", 1, collector.MetricTypeGauge, ml))
		}
	}

	return metrics, nil
}
