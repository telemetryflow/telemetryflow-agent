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
