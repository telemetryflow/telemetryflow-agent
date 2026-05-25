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

func collectInnoDBStatus(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var statusStr sql.NullString
	if err := db.QueryRowContext(ctx2, "SHOW ENGINE INNODB STATUS").Scan(&nilStr{}, &nilStr{}, &statusStr); err != nil {
		return nil, err
	}

	if !statusStr.Valid {
		return nil, nil
	}

	var metrics []collector.Metric
	sections := parseInnoDBStatus(statusStr.String)

	if bp, ok := sections["BUFFER POOL"]; ok {
		metrics = append(metrics, parseBufferPoolSection(bp, labels)...)
	}
	if lo, ok := sections["ROW OPERATIONS"]; ok {
		metrics = append(metrics, parseRowOperationsSection(lo, labels)...)
	}

	return metrics, nil
}

func parseInnoDBStatus(status string) map[string]string {
	sections := make(map[string]string)
	var currentSection string
	var currentContent strings.Builder

	for _, line := range strings.Split(status, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "---") {
			continue
		}
		if strings.HasSuffix(trimmed, "===") {
			if currentSection != "" {
				sections[currentSection] = currentContent.String()
			}
			sectionName := strings.TrimRight(strings.TrimSpace(line), " =")
			sectionName = strings.TrimSpace(sectionName)
			currentSection = ""
			currentContent.Reset()
			if sectionName != "" {
				currentSection = sectionName
			}
			continue
		}
		if currentSection != "" {
			currentContent.WriteString(line)
			currentContent.WriteString("\n")
		}
	}
	if currentSection != "" {
		sections[currentSection] = currentContent.String()
	}
	return sections
}

func parseBufferPoolSection(content string, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for _, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "buffer pool size") && !strings.Contains(lower, "pages") {
			if val := extractNumber(line); val >= 0 {
				metrics = append(metrics, makeMetric("db.mysql.innodb.buffer_pool.pages.total", val, collector.MetricTypeGauge, labels))
			}
		}
		if strings.Contains(lower, "free buffers") {
			if val := extractNumber(line); val >= 0 {
				metrics = append(metrics, makeMetric("db.mysql.innodb.buffer_pool.pages.free", val, collector.MetricTypeGauge, labels))
			}
		}
		if strings.Contains(lower, "database pages") {
			if val := extractNumber(line); val >= 0 {
				metrics = append(metrics, makeMetric("db.mysql.innodb.buffer_pool.pages.data", val, collector.MetricTypeGauge, labels))
			}
		}
		if strings.Contains(lower, "modified db pages") || strings.Contains(lower, "old database pages") {
			if strings.Contains(lower, "modified") {
				if val := extractNumber(line); val >= 0 {
					metrics = append(metrics, makeMetric("db.mysql.innodb.buffer_pool.pages.modified", val, collector.MetricTypeGauge, labels))
				}
			}
		}
		if strings.Contains(lower, "read views") {
			if val := extractNumber(line); val >= 0 {
				metrics = append(metrics, makeMetric("db.mysql.innodb.read_views", val, collector.MetricTypeGauge, labels))
			}
		}
	}
	return metrics
}

func parseRowOperationsSection(content string, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for _, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "queries inside") {
			if val := extractNumber(line); val >= 0 {
				metrics = append(metrics, makeMetric("db.mysql.innodb.queries_inside_innodb", val, collector.MetricTypeGauge, labels))
			}
		}
		if strings.Contains(lower, "queries in queue") {
			if val := extractNumber(line); val >= 0 {
				metrics = append(metrics, makeMetric("db.mysql.innodb.queries_in_queue", val, collector.MetricTypeGauge, labels))
			}
		}
	}
	return metrics
}

func extractNumber(line string) float64 {
	parts := strings.Fields(line)
	for i := len(parts) - 1; i >= 0; i-- {
		if f := parseFloat(parts[i]); f > 0 {
			return f
		}
	}
	return -1
}
