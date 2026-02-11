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
