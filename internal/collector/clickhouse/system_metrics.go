// Package clickhouse — system.metrics, system.events, system.asynchronous_metrics collector.
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
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectSystemMetrics gathers metrics from the three core system tables:
//   - system.metrics  → current gauges
//   - system.events   → monotonic counters (delta emitted)
//   - system.asynchronous_metrics → background gauges
func collectSystemMetrics(
	ctx context.Context,
	conn *connection,
	labels map[string]string,
	prevEvents map[string]float64,
	logger *zap.Logger,
) ([]collector.Metric, map[string]float64, error) {
	var metrics []collector.Metric

	// -----------------------------------------------------------------
	// system.metrics — instantaneous gauges
	// -----------------------------------------------------------------
	rows, err := conn.Execute(ctx, "SELECT metric, value FROM system.metrics")
	if err != nil {
		return nil, prevEvents, fmt.Errorf("system.metrics query: %w", err)
	}
	for _, row := range rows {
		name := toString(row["metric"])
		if name == "" {
			continue
		}
		val, err := toFloat64(row["value"])
		if err != nil {
			logger.Debug("system.metrics: skip unparseable value",
				zap.String("metric", name), zap.Error(err))
			continue
		}
		metrics = append(metrics, makeMetric(
			"db.clickhouse.system."+name,
			val,
			collector.MetricTypeGauge,
			labels,
		))
	}

	// -----------------------------------------------------------------
	// system.events — monotonic counters, emit deltas
	// -----------------------------------------------------------------
	eventRows, err := conn.Execute(ctx, "SELECT event, value FROM system.events")
	if err != nil {
		return metrics, prevEvents, fmt.Errorf("system.events query: %w", err)
	}

	newEvents := make(map[string]float64, len(eventRows))
	for _, row := range eventRows {
		name := toString(row["event"])
		if name == "" {
			continue
		}
		val, err := toFloat64(row["value"])
		if err != nil {
			logger.Debug("system.events: skip unparseable value",
				zap.String("event", name), zap.Error(err))
			continue
		}
		newEvents[name] = val

		delta := val
		if prev, ok := prevEvents[name]; ok {
			delta = val - prev
			if delta < 0 {
				// Counter reset (e.g. ClickHouse restart)
				delta = val
			}
		}
		metrics = append(metrics, makeMetric(
			"db.clickhouse.events."+name,
			delta,
			collector.MetricTypeCounter,
			labels,
		))
	}

	// -----------------------------------------------------------------
	// system.asynchronous_metrics — background gauges (large set)
	// -----------------------------------------------------------------
	asyncRows, err := conn.Execute(ctx, "SELECT metric, value FROM system.asynchronous_metrics")
	if err != nil {
		return metrics, newEvents, fmt.Errorf("system.asynchronous_metrics query: %w", err)
	}
	for _, row := range asyncRows {
		name := toString(row["metric"])
		if name == "" {
			continue
		}
		val, err := toFloat64(row["value"])
		if err != nil {
			logger.Debug("system.asynchronous_metrics: skip unparseable value",
				zap.String("metric", name), zap.Error(err))
			continue
		}
		metrics = append(metrics, makeMetric(
			"db.clickhouse.async."+name,
			val,
			collector.MetricTypeGauge,
			labels,
		))
	}

	return metrics, newEvents, nil
}
