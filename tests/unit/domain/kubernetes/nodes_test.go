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

func TestCollectNodesMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	cfg := k8scollector.NewConfig(config.KubernetesCollectorConfig{
		Nodes:      true,
		MetricsAPI: false,
	})

	collector := k8scollector.NewKubernetesCollectorForTest(
		cfg.KubernetesCollectorConfig, cs, nil, logger,
	)

	// Only collect nodes
	cfgNodesOnly := config.KubernetesCollectorConfig{
		Enabled:     true,
		Interval:    1,
		Nodes:       true,
		ClusterName: "test-cluster",
	}
	collectorNodesOnly := k8scollector.NewKubernetesCollectorForTest(
		cfgNodesOnly, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collectorNodesOnly.Collect(ctx)
	require.NoError(t, err)

	// 3 nodes exist in the fake clientset
	nodeStatusCount := 0
	for _, m := range metrics {
		if m.Name == "k8s.node.status" {
			nodeStatusCount++
		}
	}
	assert.Equal(t, 3, nodeStatusCount, "expected 3 node status metrics (one per node)")

	// Verify node readiness values
	for _, m := range metrics {
		if m.Name == "k8s.node.status" {
			node := m.Labels["node"]
			if node == "worker-3" {
				assert.Equal(t, 0.0, m.Value, "worker-3 should be NotReady (0)")
			} else {
				assert.Equal(t, 1.0, m.Value, "%s should be Ready (1)", node)
			}
		}
	}

	_ = collector
}

func TestCollectNodesCPUCapacity(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.node.cpu.capacity" && m.Labels["node"] == "worker-1" {
			assert.Equal(t, 4.0, m.Value, "worker-1 should have 4 CPU cores")
			assert.Equal(t, "cores", m.Unit)
		}
		if m.Name == "k8s.node.cpu.capacity" && m.Labels["node"] == "worker-2" {
			assert.Equal(t, 8.0, m.Value, "worker-2 should have 8 CPU cores")
		}
	}
}

func TestCollectNodesClusterLabel(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			ClusterName: "production",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.node.status" {
			assert.Equal(t, "production", m.Labels["cluster"],
				"all metrics should have cluster=production label")
		}
	}
}

func TestCollectNodesEmpty(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewEmptyClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			ClusterName: "empty-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics, "empty cluster should produce no metrics")
}

func TestCollectNodesIPAddresses(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.Nodes)

	// All fake nodes have InternalIP=10.0.0.1 and ExternalIP=203.0.113.1
	for _, node := range state.Nodes {
		assert.Equal(t, "10.0.0.1", node.InternalIP,
			"node %s should have InternalIP", node.Name)
		assert.Equal(t, "203.0.113.1", node.ExternalIP,
			"node %s should have ExternalIP", node.Name)
	}
}
