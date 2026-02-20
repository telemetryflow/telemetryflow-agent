package kubernetes_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func testConfig() config.KubernetesCollectorConfig {
	return config.KubernetesCollectorConfig{
		Enabled:           true,
		Interval:          1 * time.Second,
		Nodes:             true,
		Pods:              true,
		Deployments:       true,
		NamespacesCollect: true,
		Storage:           true,
		Services:          true,
		Workloads:         true,
		Events:            true,
		ResourceCounts:    true,
		MetricsAPI:        false, // No metrics-server in tests
		SyncToBackend:     false,
		SyncInterval:      60 * time.Second,
		ClusterName:       "test-cluster",
		ClusterProvider:   "self-managed",
		ExcludeNamespaces: []string{"kube-system"},
	}
}

func TestKubernetesCollectorName(t *testing.T) {
	collector := newTestCollector(t)
	assert.Equal(t, "kubernetes", collector.Name())
}

func TestKubernetesCollectorStartStop(t *testing.T) {
	collector := newTestCollector(t)

	assert.False(t, collector.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- collector.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)
	assert.True(t, collector.IsRunning())

	cancel()
	err := <-errCh
	assert.NoError(t, err)
	assert.False(t, collector.IsRunning())
}

func TestKubernetesCollectorDoubleStart(t *testing.T) {
	collector := newTestCollector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = collector.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Second start should fail
	err := collector.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestKubernetesCollectorCollect(t *testing.T) {
	collector := newTestCollector(t)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Should have metrics from all enabled collectors
	assert.NotEmpty(t, metrics, "expected metrics from collection")

	// Check expected metric names exist
	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	// Node metrics
	assert.True(t, metricNames["k8s.node.status"], "expected k8s.node.status metric")
	assert.True(t, metricNames["k8s.node.cpu.capacity"], "expected k8s.node.cpu.capacity metric")

	// Pod metrics (kube-system excluded)
	assert.True(t, metricNames["k8s.pod.phase"], "expected k8s.pod.phase metric")

	// Deployment metrics
	assert.True(t, metricNames["k8s.deployment.replicas"], "expected k8s.deployment.replicas metric")
	assert.True(t, metricNames["k8s.deployment.replicas.updated"], "expected k8s.deployment.replicas.updated metric")

	// Namespace metrics
	assert.True(t, metricNames["k8s.namespace.phase"], "expected k8s.namespace.phase metric")

	// Namespace quota metrics
	assert.True(t, metricNames["k8s.namespace.quota.cpu.used"], "expected k8s.namespace.quota.cpu.used metric")
	assert.True(t, metricNames["k8s.namespace.quota.cpu.hard"], "expected k8s.namespace.quota.cpu.hard metric")
	assert.True(t, metricNames["k8s.namespace.quota.memory.used"], "expected k8s.namespace.quota.memory.used metric")
	assert.True(t, metricNames["k8s.namespace.quota.memory.hard"], "expected k8s.namespace.quota.memory.hard metric")
	assert.True(t, metricNames["k8s.namespace.quota.pods.used"], "expected k8s.namespace.quota.pods.used metric")
	assert.True(t, metricNames["k8s.namespace.quota.pods.hard"], "expected k8s.namespace.quota.pods.hard metric")

	// Storage metrics
	assert.True(t, metricNames["k8s.pv.capacity_bytes"], "expected k8s.pv.capacity_bytes metric")
	assert.True(t, metricNames["k8s.pvc.capacity_bytes"], "expected k8s.pvc.capacity_bytes metric")

	// Service metrics
	assert.True(t, metricNames["k8s.endpoint.count"], "expected k8s.endpoint.count metric")

	// Workload metrics
	assert.True(t, metricNames["k8s.statefulset.replicas"], "expected k8s.statefulset.replicas metric")
	assert.True(t, metricNames["k8s.daemonset.desired"], "expected k8s.daemonset.desired metric")

	// Event metrics
	assert.True(t, metricNames["k8s.event.count"], "expected k8s.event.count metric")

	// Resource count metrics
	assert.True(t, metricNames["k8s.secret.count"], "expected k8s.secret.count metric")
	assert.True(t, metricNames["k8s.configmap.count"], "expected k8s.configmap.count metric")
	assert.True(t, metricNames["k8s.ingress.count"], "expected k8s.ingress.count metric")
}

func TestKubernetesCollectorLastClusterState(t *testing.T) {
	collector := newTestCollector(t)

	// Before collection, state should be nil
	assert.Nil(t, collector.LastClusterState())

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	assert.Equal(t, "test-cluster", state.ClusterName)
	assert.Equal(t, "self-managed", state.ClusterProvider)
	assert.NotEmpty(t, state.Nodes)
	assert.NotEmpty(t, state.Pods)
	assert.NotEmpty(t, state.Deployments)
	assert.NotEmpty(t, state.Events)
	assert.NotNil(t, state.ResourceCounts)
	assert.NotEmpty(t, state.ResourceCounts.Secrets)
	assert.NotEmpty(t, state.ResourceCounts.ConfigMaps)
	assert.NotEmpty(t, state.ResourceCounts.Ingresses)
}

func TestKubernetesCollectorNamespaceExclusion(t *testing.T) {
	collector := newTestCollector(t)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Verify no metrics from kube-system
	for _, m := range metrics {
		if ns, ok := m.Labels["namespace"]; ok {
			assert.NotEqual(t, "kube-system", ns,
				"expected kube-system to be excluded, found metric %s with namespace=kube-system", m.Name)
		}
	}

	// Verify cluster state also excludes kube-system pods
	state := collector.LastClusterState()
	for _, pod := range state.Pods {
		assert.NotEqual(t, "kube-system", pod.Namespace)
	}
}

// newTestCollector creates a KubernetesCollector with a fake clientset for testing.
func newTestCollector(t *testing.T) *k8scollector.KubernetesCollector {
	t.Helper()
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	cfg := testConfig()
	collector := k8scollector.NewKubernetesCollectorForTest(cfg, cs, nil, logger)
	return collector
}
