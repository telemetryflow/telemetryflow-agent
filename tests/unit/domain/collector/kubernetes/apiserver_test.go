// Package kubernetes_test contains unit tests for the Kubernetes collector
// covering nodes, pods, deployments, events, storage, network, HPAs, and PDBs.
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
package kubernetes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
)

func TestParseApiServerMetrics_Basic(t *testing.T) {
	body := `# HELP apiserver_request_total Counter of API server requests broken out by verb, code, and resource.
# TYPE apiserver_request_total counter
apiserver_request_total{code="200",verb="GET",resource="pods"} 5000
apiserver_request_total{code="200",verb="POST",resource="pods"} 1000
apiserver_request_total{code="500",verb="GET",resource="pods"} 50
apiserver_request_total{code="201",verb="POST",resource="deployments"} 200
# HELP apiserver_request_duration_seconds_sum
# TYPE apiserver_request_duration_seconds_sum counter
apiserver_request_duration_seconds_sum{verb="GET"} 10.5
apiserver_request_duration_seconds_count{verb="GET"} 5000
apiserver_request_duration_seconds_sum{verb="POST"} 3.2
apiserver_request_duration_seconds_count{verb="POST"} 1200
# HELP process_cpu_seconds_total
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 123.456
# HELP process_resident_memory_bytes
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 536870912
# HELP workqueue_depth
# TYPE workqueue_depth gauge
workqueue_depth{name="crd_openapi_controller"} 3
workqueue_depth{name="namespace"} 2
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseApiServerMetricsExported(body, logger)

	require.NotNil(t, metrics)
	assert.Equal(t, 1, metrics.HealthStatus)

	// Requests by code (200: GET 5000 + POST 1000 = 6000)
	assert.Equal(t, float64(6000), metrics.RequestsByCode["200"])
	assert.Equal(t, float64(50), metrics.RequestsByCode["500"])
	assert.Equal(t, float64(200), metrics.RequestsByCode["201"])

	// Requests by verb (GET: 200+500 = 5050, POST: 200+201 = 1200)
	assert.Equal(t, float64(5050), metrics.RequestsByVerb["GET"])
	assert.Equal(t, float64(1200), metrics.RequestsByVerb["POST"])

	// Instances
	require.Len(t, metrics.Instances, 1)
	inst := metrics.Instances[0]
	assert.Equal(t, "apiserver", inst.Instance)
	assert.Equal(t, 123.456, inst.CPUUsage)
	assert.Equal(t, float64(536870912), inst.MemoryUsage)
	assert.Equal(t, float64(5), inst.WorkQueueDepth) // 3 + 2

	// Error rate: 50 / 6250 * 100 = 0.8%
	assert.InDelta(t, 0.8, inst.ErrorRate, 0.01)

	// Avg latency: (10.5+3.2)*1000 / (5000+1200) = 13700 / 6200 ≈ 2.21ms
	assert.InDelta(t, 2.21, inst.AvgLatencyMs, 0.1)
}

func TestParseApiServerMetrics_Empty(t *testing.T) {
	logger := zap.NewNop()
	metrics := k8scollector.ParseApiServerMetricsExported("", logger)

	require.NotNil(t, metrics)
	assert.Equal(t, 1, metrics.HealthStatus)
	assert.Empty(t, metrics.RequestsByCode)
	assert.Empty(t, metrics.RequestsByVerb)
	// Should still have a default "apiserver" instance
	require.Len(t, metrics.Instances, 1)
	assert.Equal(t, "apiserver", metrics.Instances[0].Instance)
	assert.Equal(t, float64(0), metrics.Instances[0].ErrorRate)
}

func TestParseApiServerMetrics_MultipleInstances(t *testing.T) {
	body := `process_cpu_seconds_total{instance="apiserver-0"} 100
process_cpu_seconds_total{instance="apiserver-1"} 200
process_resident_memory_bytes{instance="apiserver-0"} 1073741824
process_resident_memory_bytes{instance="apiserver-1"} 2147483648
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseApiServerMetricsExported(body, logger)

	require.NotNil(t, metrics)
	assert.Len(t, metrics.Instances, 2)

	instanceMap := make(map[string]k8scollector.ApiServerInstanceMetrics)
	for _, inst := range metrics.Instances {
		instanceMap[inst.Instance] = inst
	}

	assert.Equal(t, float64(100), instanceMap["apiserver-0"].CPUUsage)
	assert.Equal(t, float64(200), instanceMap["apiserver-1"].CPUUsage)
	assert.Equal(t, float64(1073741824), instanceMap["apiserver-0"].MemoryUsage)
	assert.Equal(t, float64(2147483648), instanceMap["apiserver-1"].MemoryUsage)
}

func TestParseApiServerMetrics_OnlyComments(t *testing.T) {
	body := `# HELP apiserver_request_total Counter of API server requests
# TYPE apiserver_request_total counter
# Some comment
`
	logger := zap.NewNop()
	metrics := k8scollector.ParseApiServerMetricsExported(body, logger)

	require.NotNil(t, metrics)
	assert.Empty(t, metrics.RequestsByCode)
	assert.Empty(t, metrics.RequestsByVerb)
}

func TestParsePromLine(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantLabels map[string]string
		wantValue  float64
	}{
		{
			name:       "with labels",
			line:       `apiserver_request_total{code="200",verb="GET"} 5000`,
			wantLabels: map[string]string{"code": "200", "verb": "GET"},
			wantValue:  5000,
		},
		{
			name:       "no labels",
			line:       `process_cpu_seconds_total 123.456`,
			wantLabels: map[string]string{},
			wantValue:  123.456,
		},
		{
			name:       "single label",
			line:       `workqueue_depth{name="crd_openapi_controller"} 3`,
			wantLabels: map[string]string{"name": "crd_openapi_controller"},
			wantValue:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, value := k8scollector.ParsePromLineExported(tt.line)
			assert.Equal(t, tt.wantLabels, labels)
			assert.InDelta(t, tt.wantValue, value, 0.001)
		})
	}
}
