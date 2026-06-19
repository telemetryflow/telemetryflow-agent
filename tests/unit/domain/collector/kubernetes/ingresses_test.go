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

func newIngressCollector(t *testing.T, cfg config.KubernetesCollectorConfig) *k8scollector.KubernetesCollector {
	t.Helper()
	return k8scollector.NewKubernetesCollectorForTest(cfg, mocks.NewFakeClientset(), nil, zap.NewNop())
}

func TestCollectIngressMetricNames(t *testing.T) {
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true, // Ingresses collected alongside services
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["k8s.ingress.rule_count"], "expected k8s.ingress.rule_count")
	assert.True(t, metricNames["k8s.ingress.tls_enabled"], "expected k8s.ingress.tls_enabled")
	assert.True(t, metricNames["k8s.ingress.count"], "expected k8s.ingress.count")
}

func TestCollectIngressValues(t *testing.T) {
	// fakeIngress: app-ingress in default, 1 rule (example.com), TLS enabled
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	vals := make(map[string]float64)
	for _, m := range metrics {
		if m.Labels["ingress"] == "app-ingress" && m.Labels["namespace"] == "default" {
			vals[m.Name] = m.Value
		}
	}

	require.NotEmpty(t, vals, "expected ingress metrics for app-ingress")
	assert.Equal(t, float64(1), vals["k8s.ingress.rule_count"], "expected 1 rule")
	assert.Equal(t, float64(1), vals["k8s.ingress.tls_enabled"], "expected TLS enabled")
}

func TestCollectIngressLabels(t *testing.T) {
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.ingress.rule_count" {
			assert.Equal(t, "test-cluster", m.Labels["cluster"])
			assert.Equal(t, "default", m.Labels["namespace"])
			assert.Equal(t, "app-ingress", m.Labels["ingress"])
			return
		}
	}
	t.Fatal("k8s.ingress.rule_count metric not found")
}

func TestCollectIngressClusterState(t *testing.T) {
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	_, err := collector.Collect(context.Background())
	require.NoError(t, err)

	state := collector.LastClusterState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.Ingresses, "expected ingress states")

	ing := state.Ingresses[0]
	assert.Equal(t, "app-ingress", ing.Name)
	assert.Equal(t, "default", ing.Namespace)
	assert.Equal(t, "nginx", ing.IngressClass)

	// Rules
	require.Len(t, ing.Rules, 1)
	assert.Equal(t, "example.com", ing.Rules[0].Host)
	require.Len(t, ing.Rules[0].Paths, 1)
	assert.Equal(t, "/api", ing.Rules[0].Paths[0].Path)
	assert.Equal(t, "Prefix", ing.Rules[0].Paths[0].PathType)
	assert.Equal(t, "app-svc", ing.Rules[0].Paths[0].ServiceName)
	assert.Equal(t, "8080", ing.Rules[0].Paths[0].ServicePort)

	// TLS
	require.Len(t, ing.TLS, 1)
	assert.Equal(t, []string{"example.com"}, ing.TLS[0].Hosts)
	assert.Equal(t, "tls-secret", ing.TLS[0].SecretName)

	// Labels & annotations
	assert.Equal(t, "web", ing.Labels["app"])
	assert.Contains(t, ing.Annotations, "nginx.ingress.kubernetes.io/rewrite-target")
}

func TestCollectIngressCountPerNamespace(t *testing.T) {
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.ingress.count" && m.Labels["namespace"] == "default" {
			assert.Equal(t, float64(1), m.Value)
			assert.Equal(t, "test-cluster", m.Labels["cluster"])
			return
		}
	}
	t.Fatal("k8s.ingress.count metric for default namespace not found")
}

func TestCollectIngressNamespaceFilter(t *testing.T) {
	// Ingress is in "default"; filter to "monitoring" — should be excluded
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    true,
		ClusterName: "test-cluster",
		Namespaces:  []string{"monitoring"},
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "k8s.ingress.rule_count" || m.Name == "k8s.ingress.count" {
			assert.NotEqual(t, "default", m.Labels["namespace"],
				"default namespace ingresses should be excluded when filter is monitoring")
		}
	}
}

func TestCollectIngressDisabled(t *testing.T) {
	collector := newIngressCollector(t, config.KubernetesCollectorConfig{
		Enabled:     true,
		Services:    false,
		ClusterName: "test-cluster",
	})

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		assert.NotContains(t, m.Name, "k8s.ingress.", "expected no ingress metrics when Services=false")
	}
}
