// Package kubernetes_test contains unit tests for the Kubernetes collector
// covering nodes, pods, deployments, events, storage, network, HPAs, and PDBs.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
package kubernetes_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func newServiceCollector(t *testing.T, cfg config.KubernetesCollectorConfig) *k8scollector.KubernetesCollector {
	t.Helper()
	return k8scollector.NewKubernetesCollectorForTest(cfg, mocks.NewFakeClientset(), nil, zap.NewNop())
}

func TestCollectServicesMetricNames(t *testing.T) {
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["k8s.service.count"], "expected k8s.service.count")
	assert.True(t, metricNames["k8s.endpoint.count"], "expected k8s.endpoint.count")
	assert.True(t, metricNames["k8s.endpoint.total"], "expected k8s.endpoint.total")
}

func TestCollectServicesValues(t *testing.T) {
	// fakeService: app-svc in default, ClusterIP type
	// fakeEndpoints: app-svc with 2 ready addresses
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	// Check per-service endpoint count
	for _, m := range metrics {
		if m.Name == "k8s.endpoint.count" && m.Labels["service"] == "app-svc" {
			assert.Equal(t, float64(2), m.Value, "app-svc should have 2 ready endpoints")
			assert.Equal(t, "default", m.Labels["namespace"])
			return
		}
	}
	t.Fatal("k8s.endpoint.count metric for app-svc not found")
}

func TestCollectServicesCountByType(t *testing.T) {
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.service.count" && m.Labels["namespace"] == "default" {
			assert.Equal(t, "ClusterIP", m.Labels["type"])
			assert.Equal(t, "test-cluster", m.Labels["cluster"])
			assert.GreaterOrEqual(t, m.Value, float64(1))
			return
		}
	}
	t.Fatal("k8s.service.count metric for default namespace not found")
}

func TestCollectServicesClusterState(t *testing.T) {
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)

	// Services state
	require.NotEmpty(t, state.Services, "expected service states")
	svc := state.Services[0]
	assert.Equal(t, "app-svc", svc.Name)
	assert.Equal(t, "default", svc.Namespace)
	assert.Equal(t, "ClusterIP", svc.Type)
	assert.Equal(t, "10.0.0.1", svc.ClusterIP)
	assert.Equal(t, 2, svc.EndpointCount)

	// Endpoints state
	require.NotEmpty(t, state.Endpoints, "expected endpoint states")
	ep := state.Endpoints[0]
	assert.Equal(t, "app-svc", ep.Name)
	assert.Equal(t, "default", ep.Namespace)
	require.NotEmpty(t, ep.Subsets)
	assert.Len(t, ep.Subsets[0].Addresses, 2, "expected 2 ready addresses")
	assert.Len(t, ep.Subsets[0].NotReadyAddresses, 1, "expected 1 not-ready address")
	assert.Equal(t, "http", ep.Subsets[0].Ports[0].Name)
	assert.Equal(t, int32(8080), ep.Subsets[0].Ports[0].Port)
}

func TestCollectServicesEndpointAddressDetails(t *testing.T) {
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotEmpty(t, state.Endpoints)

	addr := state.Endpoints[0].Subsets[0].Addresses[0]
	assert.Equal(t, "10.0.1.1", addr.IP)
	assert.Equal(t, "worker-1", addr.NodeName)
	assert.Equal(t, "app-abc123", addr.TargetRef)
}

func TestCollectServicesNamespaceFilter(t *testing.T) {
	// Service is in "default"; filter to "monitoring" — should be excluded
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
		Namespaces:  []string{"monitoring"},
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.endpoint.count" {
			assert.NotEqual(t, "default", m.Labels["namespace"],
				"default namespace should be excluded when filter is monitoring")
		}
	}
}

func TestCollectServicesDisabled(t *testing.T) {
	collector := newServiceCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    false,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		assert.NotEqual(t, "k8s.service.count", m.Name, "expected no service metrics when Services=false")
		assert.NotEqual(t, "k8s.endpoint.count", m.Name, "expected no endpoint metrics when Services=false")
	}
}
