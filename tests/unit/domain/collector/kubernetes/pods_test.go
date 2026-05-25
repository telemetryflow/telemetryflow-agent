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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func TestCollectPodsMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			Pods:              true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"kube-system"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Count pod phase metrics (should exclude kube-system)
	phaseCount := 0
	for _, m := range metrics {
		if m.Name == "k8s.pod.phase" {
			phaseCount++
			assert.NotEqual(t, "kube-system", m.Labels["namespace"],
				"kube-system pods should be excluded")
		}
	}
	// 3 pods in default + monitoring (kube-system excluded)
	assert.Equal(t, 3, phaseCount, "expected 3 pod phase metrics")
}

func TestCollectPodsContainerMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			Pods:              true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"kube-system"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Check for container-level CPU request metrics
	cpuRequestFound := false
	for _, m := range metrics {
		if m.Name == "k8s.pod.container.cpu_request" {
			cpuRequestFound = true
			assert.Contains(t, m.Labels, "container",
				"container metric should have container label")
			assert.Equal(t, "cores", m.Unit)
		}
	}
	assert.True(t, cpuRequestFound, "expected container CPU request metrics")
}

func TestCollectPodsCounts(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			Pods:              true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"kube-system"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Check aggregate pod count metrics
	podCountFound := false
	for _, m := range metrics {
		if m.Name == "k8s.pod.count" {
			podCountFound = true
			assert.Contains(t, m.Labels, "phase")
			assert.Contains(t, m.Labels, "namespace")
		}
	}
	assert.True(t, podCountFound, "expected pod count aggregate metrics")
}

func TestCollectPodsNamespaceFilter(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	// Only collect from "monitoring" namespace
	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Pods:        true,
			ClusterName: "test-cluster",
			Namespaces:  []string{"monitoring"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if ns, ok := m.Labels["namespace"]; ok {
			assert.Equal(t, "monitoring", ns,
				"only monitoring namespace metrics should be collected")
		}
	}
}
