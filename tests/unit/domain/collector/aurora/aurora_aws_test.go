// Package aurora_test contains unit tests for the Aurora collector module.
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

package aurora_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// newDrivenCollector builds a collector whose AWS clients are initialised
// against the mock server via the AWS_ENDPOINT_URL override.
func newDrivenCollector(t *testing.T, mode mockMode) (*aurora.AuroraCollector, context.Context) {
	t.Helper()
	srv := newMockAWSServer(t, mode)
	setAWSTestEnv(t, srv.URL)

	cfg := baseCollectorConfig()
	cfg.CollectionInterval = 60 * time.Second
	cfg.PIInterval = 60 * time.Second
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx := context.Background()
	require.NoError(t, c.InitAWSClientsFirst(ctx))
	return c, ctx
}

func TestInitAWSClients_WithRoleARN(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)

	cfg := baseCollectorConfig()
	cfg.Clusters[0].RoleARN = "arn:aws:iam::123456789012:role/monitoring"
	cfg.Clusters[0].SessionToken = "token"
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
}

func TestDiscoverTopology_Success(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)

	// First discovery: new topology -> changed.
	changed, err := c.DiscoverTopologyFirst(ctx)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, 2, c.NumInstances())
	assert.Equal(t, "aurora-postgresql", c.ClusterEngine())
	assert.True(t, c.FirstInstancePIEnabled())

	// Second discovery with identical data -> unchanged.
	changed2, err := c.DiscoverTopologyFirst(ctx)
	require.NoError(t, err)
	assert.False(t, changed2)
}

func TestDiscoverTopology_NoClient(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	_, err := c.DiscoverTopologyFirst(context.Background())
	require.Error(t, err)
}

func TestDiscoverTopology_Error(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockError)
	_, err := c.DiscoverTopologyFirst(ctx)
	require.Error(t, err)
}

func TestDescribeDBCluster_And_Instances(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	require.NoError(t, c.DescribeDBClusterFirst(ctx, "test-cluster"))

	n, err := c.DescribeDBInstancesFirst(ctx, "test-cluster")
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestCollectCloudWatchMetrics_Success(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "arn:aws:rds:us-east-1:123456789012:db:inst-writer", true)

	metrics, err := c.CollectCloudWatchFirst(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, metrics)

	m := metrics[0]
	assert.Contains(t, m.Name, "aurora.")
	assert.Equal(t, "test-cluster", m.Labels["aurora_cluster"])
}

func TestCollectCloudWatchMetrics_NoClient(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "", true)
	c.ClearFirstClients()

	_, err := c.CollectCloudWatchFirst(ctx)
	require.Error(t, err)
}

func TestCollectCluster_Success(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	// Populate topology so collectCluster has instances.
	_, err := c.DiscoverTopologyFirst(ctx)
	require.NoError(t, err)

	metrics, err := c.CollectClusterFirst(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestCollectCluster_NoTopology(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	// No topology discovered -> returns nil, nil.
	metrics, err := c.CollectClusterFirst(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectPerformanceInsights_Success(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "arn:aws:rds:us-east-1:123456789012:db:inst-writer", true)

	metrics, err := c.CollectPIFirst(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
	for _, m := range metrics {
		assert.Contains(t, m.Name, "aurora.pi.")
	}
}

func TestCollectPerformanceInsights_NoClient(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	c.SetSyntheticInstance("inst-writer", "", true)
	c.ClearFirstClients()
	_, err := c.CollectPIFirst(context.Background())
	require.Error(t, err)
}

func TestCollectPerformanceInsights_PIDisabledInstance(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "", false) // PI disabled
	metrics, err := c.CollectPIFirst(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectAllPI(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "arn:aws:rds:us-east-1:123456789012:db:inst-writer", true)
	metrics, err := c.CollectAllPIExported(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestCollectQANInstance(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "arn:aws:rds:us-east-1:123456789012:db:inst-writer", true)
	n, err := c.CollectQANInstanceFirst(ctx)
	require.NoError(t, err)
	assert.Greater(t, n, 0)
}

func TestCollectQAN_TopLevel(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	c.SetSyntheticInstance("inst-writer", "arn:aws:rds:us-east-1:123456789012:db:inst-writer", true)
	buckets, err := c.CollectQAN(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, buckets)
}

func TestCollectQAN_Disabled(t *testing.T) {
	cfg := baseCollectorConfig()
	cfg.EnablePI = false
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Nil(t, buckets)
}

func TestCollect_TopLevel_Success(t *testing.T) {
	c, ctx := newDrivenCollector(t, mockSuccess)
	_, err := c.DiscoverTopologyFirst(ctx)
	require.NoError(t, err)

	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestCollect_NoStates(t *testing.T) {
	c := aurora.NewAuroraCollector(config.AuroraCollectorConfig{}, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics)
}

func TestCollect_MultiCluster(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)

	cfg := baseCollectorConfig()
	cfg.Clusters = append(cfg.Clusters, config.AuroraClusterConfig{
		ClusterID:       "test-cluster-2",
		Region:          "us-east-1",
		AccessKeyID:     "AKIA",
		SecretAccessKey: "secret",
	})
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())
	require.Equal(t, 2, c.NumStates())

	// Collect with lazy init (rdsClient nil -> initAWSClients inside collectCluster).
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	// No topology discovered yet -> empty but no error.
	assert.Empty(t, metrics)
}

func TestQANStandaloneLazyInit(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	// piClient is nil; CollectQAN should lazily init and then find no instances.
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Empty(t, buckets)
}
