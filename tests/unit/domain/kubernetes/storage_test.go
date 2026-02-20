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

func TestCollectStorageMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Storage:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	pvFound := false
	pvcFound := false
	for _, m := range metrics {
		if m.Name == "k8s.pv.capacity_bytes" {
			pvFound = true
			assert.Equal(t, "bytes", m.Unit)
			assert.Contains(t, m.Labels, "pv")
			assert.Contains(t, m.Labels, "storage_class")
		}
		if m.Name == "k8s.pvc.capacity_bytes" {
			pvcFound = true
			assert.Equal(t, "bytes", m.Unit)
			assert.Contains(t, m.Labels, "pvc")
			assert.Contains(t, m.Labels, "namespace")
		}
	}
	assert.True(t, pvFound, "expected PV capacity metric")
	assert.True(t, pvcFound, "expected PVC capacity metric")
}

func TestCollectStoragePVCapacity(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Storage:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.pv.capacity_bytes" && m.Labels["pv"] == "pv-data-1" {
			// 10Gi = 10 * 1024 * 1024 * 1024 = 10737418240
			assert.Equal(t, float64(10737418240), m.Value, "PV should have 10Gi capacity")
			assert.Equal(t, "Bound", m.Labels["phase"])
			assert.Equal(t, "standard", m.Labels["storage_class"])
		}
	}
}

func TestCollectStorageEnrichedPVFields(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Storage:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.PVs)

	pv := state.PVs[0]
	assert.Equal(t, "pv-data-1", pv.Name)
	assert.Equal(t, []string{"ReadWriteOnce"}, pv.AccessModes)
	assert.Equal(t, "Retain", pv.ReclaimPolicy)
	assert.Equal(t, "Filesystem", pv.VolumeMode)
	require.NotNil(t, pv.ClaimRef)
	assert.Equal(t, "pvc-data-1", pv.ClaimRef.Name)
	assert.Equal(t, "default", pv.ClaimRef.Namespace)
}

func TestCollectStorageEnrichedPVCFields(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Storage:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.PVCs)

	pvc := state.PVCs[0]
	assert.Equal(t, "pvc-data-1", pvc.Name)
	assert.Equal(t, []string{"ReadWriteOnce"}, pvc.AccessModes)
	assert.Equal(t, "pv-data-1", pvc.VolumeName)
	assert.Equal(t, "Filesystem", pvc.VolumeMode)
	require.NotNil(t, pvc.Resources)
	assert.Contains(t, pvc.Resources.Requests, "storage")
}
