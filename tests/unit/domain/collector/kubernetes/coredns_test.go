// Package kubernetes_test contains unit tests for the Kubernetes collector
// covering nodes, pods, deployments, events, storage, network, HPAs, and PDBs.
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
package kubernetes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
)

func TestParseCoreDNSMetrics_Basic(t *testing.T) {
	body := `# HELP coredns_dns_requests_total Counter of DNS requests.
# TYPE coredns_dns_requests_total counter
coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 8000
coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="AAAA"} 2000
# HELP coredns_dns_responses_total Counter of DNS responses.
# TYPE coredns_dns_responses_total counter
coredns_dns_responses_total{server="dns://:53",zone=".",rcode="NOERROR"} 9500
coredns_dns_responses_total{server="dns://:53",zone=".",rcode="NXDOMAIN"} 300
coredns_dns_responses_total{server="dns://:53",zone=".",rcode="SERVFAIL"} 150
coredns_dns_responses_total{server="dns://:53",zone=".",rcode="REFUSED"} 50
# HELP coredns_dns_request_duration_seconds_sum
coredns_dns_request_duration_seconds_sum{server="dns://:53"} 5.0
coredns_dns_request_duration_seconds_count{server="dns://:53"} 10000
# HELP coredns_cache_hits_total
coredns_cache_hits_total{server="dns://:53",type="success"} 7000
# HELP coredns_cache_misses_total
coredns_cache_misses_total{server="dns://:53"} 3000
# HELP coredns_forward_requests_total
coredns_forward_requests_total{to="10.96.0.10:53"} 3000
# HELP process_cpu_seconds_total
process_cpu_seconds_total 45.678
# HELP process_resident_memory_bytes
process_resident_memory_bytes 134217728
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseCoreDNSMetricsExported(body, 2, logger)

	require.NotNil(t, metrics)
	assert.Equal(t, 1, metrics.HealthStatus)
	assert.Equal(t, 2, metrics.PodCount)

	// Total requests (snapshot count)
	assert.Equal(t, float64(10000), metrics.RequestsPerSec)

	// Responses by rcode
	assert.Equal(t, float64(9500), metrics.RequestsByRcode["NOERROR"])
	assert.Equal(t, float64(300), metrics.RequestsByRcode["NXDOMAIN"])
	assert.Equal(t, float64(150), metrics.RequestsByRcode["SERVFAIL"])
	assert.Equal(t, float64(50), metrics.RequestsByRcode["REFUSED"])

	// Cache hit rate: 7000 / (7000+3000) * 100 = 70%
	assert.InDelta(t, 70.0, metrics.CacheHitRatePercent, 0.01)

	// Avg duration: 5.0 * 1000 / 10000 = 0.5ms
	assert.InDelta(t, 0.5, metrics.AvgDurationMs, 0.01)

	// Error rate: (150+50) / 10000 * 100 = 2%
	assert.InDelta(t, 2.0, metrics.ErrorRate, 0.01)

	// Upstream
	assert.Equal(t, float64(3000), metrics.UpstreamRequestsPerSec)

	// Process metrics
	assert.Equal(t, 45.678, metrics.CPUUsage)
	assert.Equal(t, float64(134217728), metrics.MemoryUsage)
}

func TestParseCoreDNSMetrics_Empty(t *testing.T) {
	logger := zap.NewNop()
	metrics := k8scollector.ParseCoreDNSMetricsExported("", 0, logger)

	require.NotNil(t, metrics)
	assert.Equal(t, 1, metrics.HealthStatus)
	assert.Equal(t, 0, metrics.PodCount)
	assert.Equal(t, float64(0), metrics.RequestsPerSec)
	assert.Equal(t, float64(0), metrics.CacheHitRatePercent)
	assert.Equal(t, float64(0), metrics.AvgDurationMs)
	assert.Equal(t, float64(0), metrics.ErrorRate)
	assert.Empty(t, metrics.RequestsByRcode)
}

func TestParseCoreDNSMetrics_NoCacheData(t *testing.T) {
	body := `coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 500
coredns_dns_responses_total{server="dns://:53",zone=".",rcode="NOERROR"} 500
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseCoreDNSMetricsExported(body, 1, logger)

	require.NotNil(t, metrics)
	assert.Equal(t, float64(0), metrics.CacheHitRatePercent, "no cache data should yield 0% hit rate")
}

func TestParseCoreDNSMetrics_NoDurationData(t *testing.T) {
	body := `coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 100
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseCoreDNSMetricsExported(body, 1, logger)

	require.NotNil(t, metrics)
	assert.Equal(t, float64(0), metrics.AvgDurationMs, "no duration data should yield 0ms")
}

func TestParseCoreDNSMetrics_OnlyErrors(t *testing.T) {
	body := `coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 100
coredns_dns_responses_total{server="dns://:53",zone=".",rcode="SERVFAIL"} 100
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseCoreDNSMetricsExported(body, 1, logger)

	require.NotNil(t, metrics)
	// Error rate: 100 / 100 * 100 = 100%
	assert.InDelta(t, 100.0, metrics.ErrorRate, 0.01)
}

func TestParseCoreDNSMetrics_MergedMultiplePods(t *testing.T) {
	// Simulates concatenated output from 2 pods
	body := `coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 5000
coredns_cache_hits_total{server="dns://:53",type="success"} 3000
coredns_cache_misses_total{server="dns://:53"} 2000
coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 5000
coredns_cache_hits_total{server="dns://:53",type="success"} 4000
coredns_cache_misses_total{server="dns://:53"} 1000
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseCoreDNSMetricsExported(body, 2, logger)

	require.NotNil(t, metrics)
	assert.Equal(t, 2, metrics.PodCount)
	assert.Equal(t, float64(10000), metrics.RequestsPerSec)

	// Cache: (3000+4000) / (3000+4000+2000+1000) = 7000/10000 = 70%
	assert.InDelta(t, 70.0, metrics.CacheHitRatePercent, 0.01)
}
