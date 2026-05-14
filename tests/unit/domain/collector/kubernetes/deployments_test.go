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

func TestCollectDeploymentMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Deployments: true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	replicaMetrics := 0
	for _, m := range metrics {
		if m.Name == "k8s.deployment.replicas" {
			replicaMetrics++
			assert.Contains(t, m.Labels, "deployment")
			assert.Contains(t, m.Labels, "namespace")
		}
	}
	// 2 deployments: "app" in default and "prometheus" in monitoring
	assert.Equal(t, 2, replicaMetrics, "expected 2 deployment replica metrics")
}

func TestCollectDeploymentReplicaCounts(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Deployments: true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.deployment.replicas" && m.Labels["deployment"] == "app" {
			assert.Equal(t, 3.0, m.Value, "app deployment should have 3 replicas")
		}
		if m.Name == "k8s.deployment.replicas.ready" && m.Labels["deployment"] == "app" {
			assert.Equal(t, 3.0, m.Value, "app deployment should have 3 ready replicas")
		}
		if m.Name == "k8s.deployment.replicas.unavailable" && m.Labels["deployment"] == "app" {
			assert.Equal(t, 0.0, m.Value, "app deployment should have 0 unavailable replicas")
		}
		if m.Name == "k8s.deployment.replicas.updated" && m.Labels["deployment"] == "app" {
			assert.Equal(t, 3.0, m.Value, "app deployment should have 3 updated replicas")
		}
	}
}

func TestCollectDeploymentExcludeNamespace(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			Deployments:       true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"monitoring"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	replicaMetrics := 0
	for _, m := range metrics {
		if m.Name == "k8s.deployment.replicas" {
			replicaMetrics++
			assert.NotEqual(t, "monitoring", m.Labels["namespace"])
		}
	}
	assert.Equal(t, 1, replicaMetrics, "only 1 deployment should remain after excluding monitoring")
}

func TestCollectDeploymentEnrichedFields(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Deployments: true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.Deployments)

	for _, dep := range state.Deployments {
		// Strategy
		require.NotNil(t, dep.Strategy, "deployment %s should have strategy", dep.Name)
		assert.Equal(t, "RollingUpdate", dep.Strategy.Type)
		assert.Equal(t, "25%", dep.Strategy.MaxUnavailable)
		assert.Equal(t, "25%", dep.Strategy.MaxSurge)

		// Containers
		require.NotEmpty(t, dep.Containers, "deployment %s should have containers", dep.Name)
		assert.Equal(t, "main", dep.Containers[0].Name)
		assert.Contains(t, dep.Containers[0].Image, ":latest")

		// Selector
		require.NotEmpty(t, dep.Selector, "deployment %s should have selector", dep.Name)
		assert.Contains(t, dep.Selector, "app")

		// Generation
		assert.Equal(t, int64(3), dep.Generation)
		assert.Equal(t, int64(3), dep.ObservedGeneration)

		// UpdatedReplicas
		assert.Equal(t, dep.Replicas, dep.UpdatedReplicas)
	}
}
