// Package exporter_test contains unit tests for the Kubernetes state sync exporter.
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
package exporter_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

// fakeSyncClient implements exporter.KubernetesSyncClient.
type fakeSyncClient struct {
	calls int64
	err   error
	mu    sync.Mutex
	last  interface{}
}

func (c *fakeSyncClient) SyncKubernetesState(ctx context.Context, clusterID string, payload interface{}) error {
	atomic.AddInt64(&c.calls, 1)
	c.mu.Lock()
	c.last = payload
	c.mu.Unlock()
	return c.err
}

// collectorWithState returns a collector whose LastClusterState is populated.
func collectorWithState(t *testing.T) *k8scollector.KubernetesCollector {
	t.Helper()
	cfg := config.KubernetesCollectorConfig{
		Enabled:           true,
		Nodes:             true,
		Pods:              true,
		NamespacesCollect: true,
		ClusterName:       "test-cluster",
	}
	col := k8scollector.NewKubernetesCollectorForTest(cfg, mocks.NewFakeClientset(), nil, zap.NewNop())
	_, err := col.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, col.LastClusterState())
	return col
}

func TestKubernetesSync_Defaults(t *testing.T) {
	ks := exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{})
	require.NotNil(t, ks)
	assert.False(t, ks.IsRunning())
	stats := ks.Stats()
	assert.False(t, stats.Running)
	assert.Zero(t, stats.SuccessCount)
	// Stop when not running is a no-op.
	require.NoError(t, ks.Stop())
}

func TestKubernetesSync_DisabledWithoutClusterID(t *testing.T) {
	ks := exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
		Client: &fakeSyncClient{},
		Logger: zap.NewNop(),
	})
	require.NoError(t, ks.Start(context.Background()))
	assert.False(t, ks.IsRunning())
}

func TestKubernetesSync_SyncsSuccessfully(t *testing.T) {
	client := &fakeSyncClient{}
	ks := exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
		ClusterID: "cluster-uuid",
		Interval:  15 * time.Millisecond,
		Timeout:   time.Second,
		Collector: collectorWithState(t),
		Client:    client,
		Logger:    zap.NewNop(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = ks.Start(ctx) }()

	require.Eventually(t, func() bool { return ks.IsRunning() }, time.Second, 5*time.Millisecond)
	// Starting again while running is a no-op.
	require.NoError(t, ks.Start(ctx))

	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&client.calls) >= 1
	}, 2*time.Second, 5*time.Millisecond)

	stats := ks.Stats()
	assert.GreaterOrEqual(t, stats.SuccessCount, 1)
	assert.Nil(t, stats.LastError)

	require.NoError(t, ks.Stop())
	assert.False(t, ks.IsRunning())
	cancel()
}

func TestKubernetesSync_SyncError(t *testing.T) {
	client := &fakeSyncClient{err: errors.New("backend down")}
	ks := exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
		ClusterID: "cluster-uuid",
		Interval:  15 * time.Millisecond,
		Collector: collectorWithState(t),
		Client:    client,
		Logger:    zap.NewNop(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ks.Start(ctx) }()

	require.Eventually(t, func() bool {
		return ks.Stats().ErrorCount >= 1
	}, 2*time.Second, 5*time.Millisecond)

	stats := ks.Stats()
	assert.Error(t, stats.LastError)
	require.NoError(t, ks.Stop())
}

func TestKubernetesSync_NoStateSkips(t *testing.T) {
	client := &fakeSyncClient{}
	// Collector without any Collect call -> LastClusterState() is nil.
	col := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{ClusterName: "test"},
		mocks.NewFakeClientset(), nil, zap.NewNop(),
	)
	require.Nil(t, col.LastClusterState())

	ks := exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
		ClusterID: "cluster-uuid",
		Interval:  15 * time.Millisecond,
		Collector: col,
		Client:    client,
		Logger:    zap.NewNop(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = ks.Start(ctx) }()
	require.Eventually(t, func() bool { return ks.IsRunning() }, time.Second, 5*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	// No state -> sendSync returns nil without calling the client.
	assert.Zero(t, atomic.LoadInt64(&client.calls))
	assert.GreaterOrEqual(t, ks.Stats().SuccessCount, 1)

	cancel()
	time.Sleep(20 * time.Millisecond)
	_ = ks.Stop()
}

func TestKubernetesSync_ContextCancelStops(t *testing.T) {
	ks := exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
		ClusterID: "cluster-uuid",
		Interval:  time.Hour,
		Collector: collectorWithState(t),
		Client:    &fakeSyncClient{},
		Logger:    zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ks.Start(ctx) }()
	require.Eventually(t, func() bool { return ks.IsRunning() }, time.Second, 5*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}
