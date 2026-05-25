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

func newPodLogsCollector(t *testing.T, cfg config.KubernetesCollectorConfig) *k8scollector.KubernetesCollector {
	t.Helper()
	return k8scollector.NewKubernetesCollectorForTest(cfg, mocks.NewFakeClientset(), nil, zap.NewNop())
}

func TestCollectPodLogsDisabled(t *testing.T) {
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PodLogs:     false,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	assert.Empty(t, state.PodLogs, "expected no pod logs when PodLogs=false")
}

func TestCollectPodLogsEnabled(t *testing.T) {
	// The fake clientset does not support real log streaming, so PodLogs will be
	// empty — but the collection must complete without errors.
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:          true,
		PodLogs:          true,
		PodLogsTailLines: 50,
		ClusterName:      "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err, "collection should not fail when log streams are unavailable")

	state := collector.LastClusterState()
	require.NotNil(t, state)
	// PodLogs may be nil/empty; the key assertion is no error during collection.
	_ = state.PodLogs
}

func TestCollectPodLogsDefaultTailLines(t *testing.T) {
	// PodLogsTailLines=0 should default to 100 internally — no panic or error.
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:          true,
		PodLogs:          true,
		PodLogsTailLines: 0,
		ClusterName:      "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err, "zero PodLogsTailLines should not cause an error")
}

func TestCollectPodLogsNamespaceAllowlist(t *testing.T) {
	// Only "monitoring" namespace in the allowlist.
	// No real log streams available, but collection must not fail.
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:           true,
		PodLogs:           true,
		PodLogsTailLines:  100,
		PodLogsNamespaces: []string{"monitoring"},
		ClusterName:       "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err, "collection with PodLogsNamespaces allowlist should not fail")
}

func TestCollectPodLogsNamespaceExclusion(t *testing.T) {
	// When ExcludeNamespaces is set and PodLogsNamespaces is empty, pod log
	// collection falls back to the regular namespace filter (kube-system excluded).
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:           true,
		PodLogs:           true,
		ExcludeNamespaces: []string{"kube-system"},
		ClusterName:       "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err, "collection with ExcludeNamespaces should not fail")
}

func TestCollectPodLogsNamespaceAllowlistPrecedence(t *testing.T) {
	// When both PodLogsNamespaces and ExcludeNamespaces are set,
	// the allowlist takes precedence — only allowed namespaces are collected.
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:           true,
		PodLogs:           true,
		PodLogsNamespaces: []string{"monitoring"},
		ExcludeNamespaces: []string{"kube-system"},
		ClusterName:       "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err, "collection with allowlist + exclusion should not fail")
}

func TestCollectPodLogsStateNotNilAfterCollection(t *testing.T) {
	collector := newPodLogsCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		PodLogs:     true,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state, "cluster state must not be nil after collection")
}
