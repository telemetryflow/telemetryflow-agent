// Package confluent_kafka exposes unexported symbols for external test packages.
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

package confluent_kafka

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// MetricQueryExported is a test-visible representation of the internal
// metricQuery. It mirrors the internal fields with exported names so that
// external test packages can construct queries without accessing unexported
// symbols.
type MetricQueryExported struct {
	Metric string
	Agg    string
	Suffix string
	Typ    collector.MetricType
	Unit   string
	Desc   string
}

func (q MetricQueryExported) toInternal() metricQuery {
	return metricQuery{
		metric: q.Metric,
		agg:    q.Agg,
		suffix: q.Suffix,
		typ:    q.Typ,
		unit:   q.Unit,
		desc:   q.Desc,
	}
}

// DataPointExported is a test-visible representation of the internal dataPoint.
type DataPointExported struct {
	Timestamp string
	Value     float64
	Metric    string
	Subject   map[string]string
}

func (p DataPointExported) toInternal() dataPoint {
	return dataPoint(p)
}

// BuildConfluentKafkaMetricsExported wraps BuildConfluentKafkaMetrics using the
// exported test-visible query and data-point types.
func BuildConfluentKafkaMetricsExported(labels map[string]string, queries []MetricQueryExported, points []DataPointExported) []collector.Metric {
	q := make([]metricQuery, len(queries))
	for i, item := range queries {
		q[i] = item.toInternal()
	}
	p := make([]dataPoint, len(points))
	for i, item := range points {
		p[i] = item.toInternal()
	}
	return BuildConfluentKafkaMetrics(labels, q, p)
}
