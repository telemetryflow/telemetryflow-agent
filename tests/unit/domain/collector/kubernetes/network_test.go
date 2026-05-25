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

// mockKubeletFetcher returns a KubeletProxyFunc backed by pre-built data.
func mockKubeletFetcher() k8scollector.KubeletProxyFunc {
	rx1 := uint64(1024000)
	tx1 := uint64(512000)
	rx2 := uint64(2048000)
	tx2 := uint64(1024000)
	rx3 := uint64(4096000)
	tx3 := uint64(2048000)
	rxErr := uint64(5)
	txErr := uint64(2)

	data := map[string]*k8scollector.KubeletSummary{
		"worker-1": {
			Node: k8scollector.KubeletNodeStats{NodeName: "worker-1"},
			Pods: []k8scollector.KubeletPodStats{
				{
					PodRef: k8scollector.KubeletPodRef{Name: "app-abc123", Namespace: "default"},
					Network: &k8scollector.KubeletNetworkStats{
						Interfaces: []k8scollector.KubeletInterfaceStats{
							{Name: "eth0", RxBytes: &rx1, TxBytes: &tx1, RxErrors: &rxErr, TxErrors: &txErr},
						},
					},
				},
				{
					PodRef: k8scollector.KubeletPodRef{Name: "prometheus-0", Namespace: "monitoring"},
					Network: &k8scollector.KubeletNetworkStats{
						Interfaces: []k8scollector.KubeletInterfaceStats{
							{Name: "eth0", RxBytes: &rx2, TxBytes: &tx2},
						},
					},
				},
			},
		},
		"worker-2": {
			Node: k8scollector.KubeletNodeStats{NodeName: "worker-2"},
			Pods: []k8scollector.KubeletPodStats{
				{
					PodRef: k8scollector.KubeletPodRef{Name: "app-def456", Namespace: "default"},
					Network: &k8scollector.KubeletNetworkStats{
						Interfaces: []k8scollector.KubeletInterfaceStats{
							{Name: "eth0", RxBytes: &rx3, TxBytes: &tx3},
						},
					},
				},
			},
		},
		"worker-3": {
			Node: k8scollector.KubeletNodeStats{NodeName: "worker-3"},
			Pods: []k8scollector.KubeletPodStats{},
		},
	}

	return func(_ context.Context, nodeName string) (*k8scollector.KubeletSummary, error) {
		if s, ok := data[nodeName]; ok {
			return s, nil
		}
		return &k8scollector.KubeletSummary{}, nil
	}
}

func TestCollectNetworkMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			Network:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)
	collector.SetKubeletFetcher(mockKubeletFetcher())

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	rxCount := 0
	txCount := 0
	for _, m := range metrics {
		if m.Name == "k8s.namespace.network.receive_bytes" {
			rxCount++
			assert.Contains(t, m.Labels, "namespace")
			assert.Contains(t, m.Labels, "cluster")
			assert.Equal(t, "bytes", m.Unit)
		}
		if m.Name == "k8s.namespace.network.transmit_bytes" {
			txCount++
		}
	}
	// 2 namespaces: default and monitoring
	assert.Equal(t, 2, rxCount, "expected 2 namespace receive metrics")
	assert.Equal(t, 2, txCount, "expected 2 namespace transmit metrics")
}

func TestCollectNetworkState(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			Network:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)
	collector.SetKubeletFetcher(mockKubeletFetcher())

	ctx := context.Background()
	_, err := collector.Collect(ctx)
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.NetworkStats)

	statsByNS := make(map[string]k8scollector.NamespaceNetworkStats)
	for _, ns := range state.NetworkStats {
		statsByNS[ns.Namespace] = ns
	}

	// default: app-abc123 (rx=1024000) + app-def456 (rx=4096000) = 5120000
	defStats := statsByNS["default"]
	assert.Equal(t, uint64(5120000), defStats.RxBytes)
	assert.Equal(t, uint64(2560000), defStats.TxBytes) // 512000 + 2048000
	assert.Equal(t, uint64(5), defStats.RxErrors)
	assert.Equal(t, uint64(2), defStats.TxErrors)

	// monitoring: prometheus-0 (rx=2048000)
	monStats := statsByNS["monitoring"]
	assert.Equal(t, uint64(2048000), monStats.RxBytes)
	assert.Equal(t, uint64(1024000), monStats.TxBytes)
}

func TestCollectNetworkNamespaceFilter(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			Nodes:             true,
			Network:           true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"monitoring"},
		}, cs, nil, logger,
	)
	collector.SetKubeletFetcher(mockKubeletFetcher())

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.namespace.network.receive_bytes" {
			assert.NotEqual(t, "monitoring", m.Labels["namespace"],
				"monitoring namespace should be excluded from network metrics")
		}
	}

	state := collector.LastClusterState()
	require.NotNil(t, state)
	for _, ns := range state.NetworkStats {
		assert.NotEqual(t, "monitoring", ns.Namespace,
			"monitoring namespace should be excluded from network state")
	}
}

func TestCollectNetworkEmpty(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewEmptyClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			Network:     true,
			ClusterName: "empty-cluster",
		}, cs, nil, logger,
	)
	// Empty fetcher — no nodes, no data
	collector.SetKubeletFetcher(func(_ context.Context, _ string) (*k8scollector.KubeletSummary, error) {
		return &k8scollector.KubeletSummary{}, nil
	})

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		assert.NotContains(t, m.Name, "network",
			"empty cluster should produce no network metrics")
	}
}

func TestCollectNetworkNilFetcher(t *testing.T) {
	logger := zap.NewNop()
	cs := mocks.NewFakeClientset()

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			Nodes:       true,
			Network:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)
	// Don't set a fetcher — should gracefully produce no network metrics

	ctx := context.Background()
	metrics, err := collector.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		assert.NotContains(t, m.Name, "network",
			"nil fetcher should produce no network metrics")
	}
}
