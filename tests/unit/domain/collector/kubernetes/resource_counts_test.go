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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func TestCollectResourceCounts(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:        true,
			ResourceCounts: true,
			ClusterName:    "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["k8s.secret.count"], "expected k8s.secret.count metric")
	assert.True(t, metricNames["k8s.configmap.count"], "expected k8s.configmap.count metric")
	assert.True(t, metricNames["k8s.ingress.count"], "expected k8s.ingress.count metric")
}

func TestCollectResourceCountsState(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:        true,
			ResourceCounts: true,
			ClusterName:    "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotNil(t, state.ResourceCounts)

	// Secrets: 2 in default + 1 in monitoring = 3 total
	assert.Equal(t, 2, state.ResourceCounts.Secrets["default"])
	assert.Equal(t, 1, state.ResourceCounts.Secrets["monitoring"])

	// ConfigMaps: 1 in default + 1 in monitoring
	assert.Equal(t, 1, state.ResourceCounts.ConfigMaps["default"])
	assert.Equal(t, 1, state.ResourceCounts.ConfigMaps["monitoring"])

	// Ingresses: 1 in default
	assert.Equal(t, 1, state.ResourceCounts.Ingresses["default"])
}

func TestCollectResourceCountsNamespaceFilter(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			ResourceCounts:    true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"monitoring"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if ns, ok := m.Labels["namespace"]; ok {
			assert.NotEqual(t, "monitoring", ns,
				"monitoring namespace should be excluded from %s", m.Name)
		}
	}

	state := collector.LastClusterState()
	require.NotNil(t, state.ResourceCounts)
	_, hasMonitoring := state.ResourceCounts.Secrets["monitoring"]
	assert.False(t, hasMonitoring, "monitoring namespace should be excluded from secrets count")
}

func TestCollectResourceCountsEmpty(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewEmptyClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:        true,
			ResourceCounts: true,
			ClusterName:    "empty-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics, "empty cluster should produce no resource count metrics")
}
