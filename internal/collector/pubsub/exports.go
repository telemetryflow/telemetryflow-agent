// Package pubsub exposes unexported symbols for external test packages.
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

package pubsub

import (
	"crypto/rsa"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// PubSubTestMetric is a test-visible representation of the internal
// pubsubMetric. It mirrors the internal fields with exported names so that
// external test packages can construct metric definitions.
type PubSubTestMetric struct {
	MetricType string
	Suffix     string
	Typ        collector.MetricType
}

func (m PubSubTestMetric) toInternal() pubsubMetric {
	return pubsubMetric{metricType: m.MetricType, suffix: m.Suffix, typ: m.Typ}
}

// PubSubTestPoint is a test-visible representation of a monitoringPoint.
type PubSubTestPoint struct {
	EndTime     time.Time
	Int64Value  *int64
	DoubleValue *float64
}

// PubSubTestSeries is a test-visible representation of a monitoringTimeSeries.
type PubSubTestSeries struct {
	Type           string
	SubscriptionID string
	ProjectID      string
	Points         []PubSubTestPoint
}

func (s PubSubTestSeries) toInternal() monitoringTimeSeries {
	var ts monitoringTimeSeries
	ts.Metric.Type = s.Type
	ts.Resource.Labels.SubscriptionID = s.SubscriptionID
	ts.Resource.Labels.ProjectID = s.ProjectID
	for _, p := range s.Points {
		var mp monitoringPoint
		mp.Interval.EndTime = p.EndTime
		mp.Value.Int64Value = p.Int64Value
		mp.Value.DoubleValue = p.DoubleValue
		ts.Points = append(ts.Points, mp)
	}
	return ts
}

// BuildPubSubMetricsExported wraps BuildPubSubMetrics for external test
// packages, converting exported test representations to internal types.
func BuildPubSubMetricsExported(labels map[string]string, metrics []PubSubTestMetric, series []PubSubTestSeries, subscriptionFilter string) ([]collector.Metric, error) {
	im := make([]pubsubMetric, 0, len(metrics))
	for _, m := range metrics {
		im = append(im, m.toInternal())
	}
	is := make([]monitoringTimeSeries, 0, len(series))
	for _, s := range series {
		is = append(is, s.toInternal())
	}
	return BuildPubSubMetrics(labels, im, is, subscriptionFilter)
}

// SignJWTExported wraps signJWT for external test packages.
func SignJWTExported(claims map[string]any, key *rsa.PrivateKey) (string, error) {
	return signJWT(claims, key)
}
