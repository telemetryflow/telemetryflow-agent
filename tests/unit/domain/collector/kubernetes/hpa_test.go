// Package kubernetes_test contains unit tests for the Kubernetes collector
// covering nodes, pods, deployments, events, storage, network, HPAs, and PDBs.
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

func newHPACollector(t *testing.T, cfg config.KubernetesCollectorConfig) *k8scollector.KubernetesCollector {
	t.Helper()
	return k8scollector.NewKubernetesCollectorForTest(cfg, mocks.NewFakeClientset(), nil, zap.NewNop())
}

func TestCollectHPAMetricNames(t *testing.T) {
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["k8s.hpa.replicas.min"], "expected k8s.hpa.replicas.min")
	assert.True(t, metricNames["k8s.hpa.replicas.max"], "expected k8s.hpa.replicas.max")
	assert.True(t, metricNames["k8s.hpa.replicas.current"], "expected k8s.hpa.replicas.current")
	assert.True(t, metricNames["k8s.hpa.replicas.desired"], "expected k8s.hpa.replicas.desired")
	assert.True(t, metricNames["k8s.hpa.condition"], "expected k8s.hpa.condition")
}

func TestCollectHPAValues(t *testing.T) {
	// fakeHPA: app-hpa in default, min=2, max=5, current=3, desired=3
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	vals := make(map[string]float64)
	for _, m := range metrics {
		if m.Labels["hpa"] == "app-hpa" && m.Labels["namespace"] == "default" {
			vals[m.Name] = m.Value
		}
	}

	require.NotEmpty(t, vals, "expected HPA app-hpa metrics")
	assert.Equal(t, float64(2), vals["k8s.hpa.replicas.min"])
	assert.Equal(t, float64(5), vals["k8s.hpa.replicas.max"])
	assert.Equal(t, float64(3), vals["k8s.hpa.replicas.current"])
	assert.Equal(t, float64(3), vals["k8s.hpa.replicas.desired"])
}

func TestCollectHPALabels(t *testing.T) {
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.hpa.replicas.min" {
			assert.Equal(t, "test-cluster", m.Labels["cluster"])
			assert.Equal(t, "default", m.Labels["namespace"])
			assert.Equal(t, "app-hpa", m.Labels["hpa"])
			assert.Equal(t, "Deployment", m.Labels["target_kind"])
			assert.Equal(t, "app", m.Labels["target_name"])
			return
		}
	}
	t.Fatal("k8s.hpa.replicas.min metric not found")
}

func TestCollectHPAConditionMetrics(t *testing.T) {
	// fakeHPA has AbleToScale=True, ScalingActive=True, ScalingLimited=False
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	conditions := make(map[string]float64)
	for _, m := range metrics {
		if m.Name == "k8s.hpa.condition" && m.Labels["hpa"] == "app-hpa" {
			conditions[m.Labels["condition"]] = m.Value
		}
	}

	require.NotEmpty(t, conditions, "expected HPA condition metrics")
	assert.Equal(t, float64(1), conditions["AbleToScale"], "AbleToScale should be 1")
	assert.Equal(t, float64(1), conditions["ScalingActive"], "ScalingActive should be 1")
	assert.Equal(t, float64(0), conditions["ScalingLimited"], "ScalingLimited should be 0")
}

func TestCollectHPANamespaceFilter(t *testing.T) {
	// HPA is in "default"; filter to "monitoring" — should be excluded
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         true,
		ClusterName: "test-cluster",
		Namespaces:  []string{"monitoring"},
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.hpa.replicas.min" {
			assert.NotEqual(t, "default", m.Labels["namespace"],
				"HPA in default namespace should be excluded when filter is monitoring")
		}
	}
}

func TestCollectHPAClusterState(t *testing.T) {
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         true,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.HPAs, "expected HPA state entries")

	hpa := state.HPAs[0]
	assert.Equal(t, "app-hpa", hpa.Name)
	assert.Equal(t, "default", hpa.Namespace)
	assert.Equal(t, "Deployment", hpa.ScaleTargetKind)
	assert.Equal(t, "app", hpa.ScaleTargetName)
	assert.Equal(t, int32(2), hpa.MinReplicas)
	assert.Equal(t, int32(5), hpa.MaxReplicas)
	assert.Equal(t, int32(3), hpa.CurrentReplicas)
	assert.Equal(t, int32(3), hpa.DesiredReplicas)
	assert.True(t, hpa.Conditions["AbleToScale"], "AbleToScale should be true")
	assert.True(t, hpa.Conditions["ScalingActive"], "ScalingActive should be true")
	assert.False(t, hpa.Conditions["ScalingLimited"], "ScalingLimited should be false")
}

func TestCollectHPADisabled(t *testing.T) {
	collector := newHPACollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		HPA:         false,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		assert.NotContains(t, m.Name, "k8s.hpa.", "expected no HPA metrics when HPA=false")
	}
}
