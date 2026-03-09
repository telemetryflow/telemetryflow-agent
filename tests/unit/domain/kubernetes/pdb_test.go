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

func newPDBCollector(t *testing.T, cfg config.KubernetesCollectorConfig) *k8scollector.KubernetesCollector {
	t.Helper()
	return k8scollector.NewKubernetesCollectorForTest(cfg, mocks.NewFakeClientset(), nil, zap.NewNop())
}

func TestCollectPDBMetricNames(t *testing.T) {
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PDB:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["k8s.pdb.pods.current_healthy"], "expected k8s.pdb.pods.current_healthy")
	assert.True(t, metricNames["k8s.pdb.pods.desired_healthy"], "expected k8s.pdb.pods.desired_healthy")
	assert.True(t, metricNames["k8s.pdb.pods.expected"], "expected k8s.pdb.pods.expected")
	assert.True(t, metricNames["k8s.pdb.disruptions_allowed"], "expected k8s.pdb.disruptions_allowed")
}

func TestCollectPDBValues(t *testing.T) {
	// fakePDB: app-pdb in default, currentHealthy=3, desiredHealthy=3, disruptionsAllowed=1, expectedPods=3
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PDB:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	vals := make(map[string]float64)
	for _, m := range metrics {
		if m.Labels["pdb"] == "app-pdb" && m.Labels["namespace"] == "default" {
			vals[m.Name] = m.Value
		}
	}

	require.NotEmpty(t, vals, "expected PDB app-pdb metrics")
	assert.Equal(t, float64(3), vals["k8s.pdb.pods.current_healthy"])
	assert.Equal(t, float64(3), vals["k8s.pdb.pods.desired_healthy"])
	assert.Equal(t, float64(3), vals["k8s.pdb.pods.expected"])
	assert.Equal(t, float64(1), vals["k8s.pdb.disruptions_allowed"])
}

func TestCollectPDBLabels(t *testing.T) {
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PDB:         true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.pdb.pods.current_healthy" {
			assert.Equal(t, "test-cluster", m.Labels["cluster"])
			assert.Equal(t, "default", m.Labels["namespace"])
			assert.Equal(t, "app-pdb", m.Labels["pdb"])
			return
		}
	}
	t.Fatal("k8s.pdb.pods.current_healthy metric not found")
}

func TestCollectPDBNamespaceFilter(t *testing.T) {
	// PDB is in "default"; filter to "monitoring" — should be excluded
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PDB:         true,
		ClusterName: "test-cluster",
		Namespaces:  []string{"monitoring"},
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.pdb.pods.current_healthy" {
			t.Errorf("PDB in default namespace should be excluded, got namespace=%s", m.Labels["namespace"])
		}
	}
}

func TestCollectPDBExcludeNamespace(t *testing.T) {
	// ExcludeNamespaces should not affect default namespace (only kube-system)
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:           true,
		PDB:               true,
		ClusterName:       "test-cluster",
		ExcludeNamespaces: []string{"kube-system"},
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	found := false
	for _, m := range metrics {
		if m.Name == "k8s.pdb.pods.current_healthy" && m.Labels["namespace"] == "default" {
			found = true
		}
	}
	assert.True(t, found, "expected PDB in default namespace when only kube-system is excluded")
}

func TestCollectPDBClusterState(t *testing.T) {
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PDB:         true,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.PDBs, "expected PDB state entries")

	pdb := state.PDBs[0]
	assert.Equal(t, "app-pdb", pdb.Name)
	assert.Equal(t, "default", pdb.Namespace)
	assert.Equal(t, int32(3), pdb.CurrentHealthy)
	assert.Equal(t, int32(3), pdb.DesiredHealthy)
	assert.Equal(t, int32(1), pdb.DisruptionsAllowed)
	assert.Equal(t, int32(3), pdb.ExpectedPods)
}

func TestCollectPDBDisabled(t *testing.T) {
	collector := newPDBCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PDB:         false,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		assert.NotContains(t, m.Name, "k8s.pdb.", "expected no PDB metrics when PDB=false")
	}
}
