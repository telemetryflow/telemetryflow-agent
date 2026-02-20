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

func TestCollectEventsMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Events:      true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	eventMetrics := 0
	for _, m := range metrics {
		if m.Name == "k8s.event.count" {
			eventMetrics++
			assert.Contains(t, m.Labels, "namespace")
			assert.Contains(t, m.Labels, "type")
		}
	}
	// Events exist in default (Normal+Warning) and monitoring (Normal)
	assert.GreaterOrEqual(t, eventMetrics, 2, "expected at least 2 event count metrics")
}

func TestCollectEventsState(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Events:      true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.Events)

	// Verify event fields
	for _, ev := range state.Events {
		assert.NotEmpty(t, ev.Type, "event should have type")
		assert.NotEmpty(t, ev.Reason, "event should have reason")
		assert.NotEmpty(t, ev.InvolvedKind, "event should have involved kind")
		assert.NotEmpty(t, ev.InvolvedName, "event should have involved name")
		assert.NotEmpty(t, ev.Source, "event should have source")
	}

	// Verify we have both Normal and Warning events
	types := make(map[string]bool)
	for _, ev := range state.Events {
		types[ev.Type] = true
	}
	assert.True(t, types["Normal"], "expected Normal events")
	assert.True(t, types["Warning"], "expected Warning events")
}

func TestCollectEventsNamespaceFilter(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			Events:            true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"monitoring"},
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.event.count" {
			assert.NotEqual(t, "monitoring", m.Labels["namespace"],
				"monitoring namespace should be excluded")
		}
	}
}

func TestCollectEventsEmpty(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewEmptyClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Events:      true,
			ClusterName: "empty-cluster",
		}, cs, nil, logger,
	)

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics, "empty cluster should produce no event metrics")
}
