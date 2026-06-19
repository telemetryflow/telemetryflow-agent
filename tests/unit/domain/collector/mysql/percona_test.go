// Package mysql_test contains unit tests for the corresponding collector module.
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

package mysql_test

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	mysql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
)

func TestInitPerconaExtension(t *testing.T) {
	ext := mysql.InitPerconaExtensionExport()
	if ext == nil {
		t.Fatal("expected non-nil extension")
	}
	if ext.DetectedPlugins() == nil {
		t.Fatal("expected detectedPlugins map to be initialized")
	}
	if ext.QueryResponseTimeEnabled() {
		t.Error("expected queryResponseTimeEnabled to be false")
	}
}

func TestComputePercentilesFromBuckets_Empty(t *testing.T) {
	p50, p95, p99, pctBelow, pctAbove := mysql.ComputePercentilesFromBucketsExport(nil, 0)
	if p50 != 0 || p95 != 0 || p99 != 0 || pctBelow != 0 || pctAbove != 0 {
		t.Error("empty buckets should return all zeros")
	}
}

func TestComputePercentilesFromBuckets_SingleBucket(t *testing.T) {
	buckets := []mysql.QrtBucketExport{
		{TimeRange: "0.001s-0.01s", Count: 100, Total: 0.5},
	}
	p50, p95, p99, _, _ := mysql.ComputePercentilesFromBucketsExport(buckets, 100)
	if p50 <= 0 {
		t.Errorf("p50 should be > 0, got %f", p50)
	}
	if p95 <= 0 {
		t.Errorf("p95 should be > 0, got %f", p95)
	}
	if p99 <= 0 {
		t.Errorf("p99 should be > 0, got %f", p99)
	}
}

func TestParseBucketUpperMs(t *testing.T) {
	tests := []struct {
		input  string
		expect float64
	}{
		{"< 0.000001s", 0.001},
		{"0.000001s-0.000010s", 0.01},
		{"0.001s-0.01s", 10},
		{"0.01s-0.1s", 100},
		{"0.1s-1s", 1000},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := mysql.ParseBucketUpperMsExport(tc.input)
			if got != tc.expect {
				t.Errorf("parseBucketUpperMs(%q) = %f, want %f", tc.input, got, tc.expect)
			}
		})
	}
}

func TestCollectPerconaQRTFromBuckets(t *testing.T) {
	buckets := []mysql.QrtBucketExport{
		{TimeRange: "0-0.001s", Count: 500, Total: 0.25},
		{TimeRange: "0.001s-0.01s", Count: 300, Total: 1.5},
		{TimeRange: "0.01s-0.1s", Count: 150, Total: 7.5},
		{TimeRange: "0.1s-1s", Count: 50, Total: 25},
	}

	totalCount := 0.0
	for _, b := range buckets {
		totalCount += float64(b.Count)
	}

	p50, p95, p99, pctBelow1ms, pctAbove100ms := mysql.ComputePercentilesFromBucketsExport(buckets, totalCount)

	if p50 <= 0 {
		t.Errorf("p50 should be > 0, got %f", p50)
	}
	if p95 <= p50 {
		t.Errorf("p95 (%f) should be >= p50 (%f)", p95, p50)
	}
	if p99 <= p95 {
		t.Errorf("p99 (%f) should be >= p95 (%f)", p99, p95)
	}

	// All buckets under 1ms (first bucket: 0-0.001s = 1ms upper bound)
	if pctBelow1ms <= 0 {
		t.Errorf("pctBelow1ms should be > 0, got %f", pctBelow1ms)
	}
	// 0.1s-1s = 100ms upper bound, so pctAbove100ms should include that bucket
	if pctAbove100ms <= 0 {
		t.Errorf("pctAbove100ms should be > 0, got %f", pctAbove100ms)
	}
}

func TestCollectPerconaQRTFromStatus(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	buckets := []mysql.QrtBucketExport{
		{TimeRange: "0.000001s-0.000010s", Count: 800, Total: 0.004},
		{TimeRange: "0.000010s-0.000100s", Count: 150, Total: 0.0075},
		{TimeRange: "0.000100s-0.001000s", Count: 40, Total: 0.02},
		{TimeRange: "0.001000s-0.010000s", Count: 10, Total: 0.05},
	}
	totalCount := 0.0
	for _, b := range buckets {
		totalCount += float64(b.Count)
	}

	var metrics []collector.Metric
	for _, b := range buckets {
		bucketLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			bucketLabels[k] = v
		}
		bucketLabels["bucket"] = b.TimeRange
		metrics = append(metrics, mysql.MakeMetricExport("db.mysql.query_response_time.bucket_count", float64(b.Count), collector.MetricTypeGauge, bucketLabels))
		metrics = append(metrics, mysql.MakeMetricExport("db.mysql.query_response_time.bucket_total", b.Total, collector.MetricTypeGauge, bucketLabels))
	}

	if len(metrics) != 8 {
		t.Errorf("expected 8 bucket metrics, got %d", len(metrics))
	}

	first := findMetric(metrics, "db.mysql.query_response_time.bucket_count")
	if first == nil {
		t.Fatal("expected bucket_count metric")
	}
	if first.Value != 800 {
		t.Errorf("first bucket count = %f, want 800", first.Value)
	}
}

func TestComputePercentilesFromBuckets_AllInFirstBucket(t *testing.T) {
	buckets := []mysql.QrtBucketExport{
		{TimeRange: "0-0.001s", Count: 1000, Total: 0.5},
	}
	p50, p95, p99, pctBelow, pctAbove := mysql.ComputePercentilesFromBucketsExport(buckets, 1000)

	if p50 <= 0 {
		t.Errorf("p50 should be > 0, got %f", p50)
	}
	if p95 <= 0 {
		t.Errorf("p95 should be > 0, got %f", p95)
	}
	if p99 <= 0 {
		t.Errorf("p99 should be > 0, got %f", p99)
	}
	if pctBelow <= 0 {
		t.Errorf("pctBelow1ms should be > 0 when all in first bucket, got %f", pctBelow)
	}
	if pctAbove != 0 {
		t.Errorf("pctAbove100ms should be 0 when all under 1ms, got %f", pctAbove)
	}
}
