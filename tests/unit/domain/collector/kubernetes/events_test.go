// Package kubernetes_test contains unit tests for the Kubernetes collector
// covering nodes, pods, deployments, events, storage, network, HPAs, and PDBs.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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
