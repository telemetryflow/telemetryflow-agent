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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// initClientsAgainst builds a collector with clients pointed at endpoint.
func initClientsAgainst(t *testing.T, endpoint string, cfg config.AuroraCollectorConfig) *aurora.AuroraCollector {
	t.Helper()
	setAWSTestEnv(t, endpoint)
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	return c
}

func TestDescribeDBCluster_ThrottleThenSucceed(t *testing.T) {
	srv := newThrottleThenOKServer(t, 1, false)
	c := initClientsAgainst(t, srv.URL, baseCollectorConfig())
	// First attempt throttled (1s backoff), second succeeds.
	require.NoError(t, c.DescribeDBClusterFirst(context.Background(), "test-cluster"))
}

func TestDescribeDBInstances_ThrottleThenSucceed(t *testing.T) {
	srv := newThrottleThenOKServer(t, 1, false)
	c := initClientsAgainst(t, srv.URL, baseCollectorConfig())
	n, err := c.DescribeDBInstancesFirst(context.Background(), "test-cluster")
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestCloudWatch_ThrottleThenSucceed(t *testing.T) {
	srv := newThrottleThenOKServer(t, 1, false)
	c := initClientsAgainst(t, srv.URL, baseCollectorConfig())
	c.SetSyntheticInstance("inst-writer", "arn:x", true)
	metrics, err := c.CollectCloudWatchFirst(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestPI_ThrottleThenSucceed(t *testing.T) {
	srv := newThrottleThenOKServer(t, 1, false)
	c := initClientsAgainst(t, srv.URL, baseCollectorConfig())
	c.SetSyntheticInstance("inst-writer", "arn:x", true)
	metrics, err := c.CollectPIFirst(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestQAN_ThrottleThenSucceed(t *testing.T) {
	srv := newThrottleThenOKServer(t, 1, false)
	c := initClientsAgainst(t, srv.URL, baseCollectorConfig())
	c.SetSyntheticInstance("inst-writer", "arn:x", true)
	n, err := c.CollectQANInstanceFirst(context.Background())
	require.NoError(t, err)
	assert.Greater(t, n, 0)
}

func TestCloudWatch_NonThrottlingError(t *testing.T) {
	srv := newMockAWSServer(t, mockError)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)
	// Batch error is swallowed; returns empty with no error.
	metrics, err := c.CollectCloudWatchFirst(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestQAN_MultiStatement_RankAndTruncate(t *testing.T) {
	srv := newMultiStmtServer(t)
	cfg := baseCollectorConfig()
	cfg.TopQueriesLimit = 1 // force ranking + truncation
	c := initClientsAgainst(t, srv.URL, cfg)
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	n, err := c.CollectQANInstanceFirst(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n) // truncated to the configured limit
}

func TestQANTopLimit_Fallback(t *testing.T) {
	// A negative limit is preserved by NewConfig, exercising the fallback path.
	cfg := config.AuroraCollectorConfig{
		TopQueriesLimit: -1,
		Clusters:        []config.AuroraClusterConfig{{ClusterID: "c1"}},
	}
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())
	assert.Equal(t, 200, c.QanTopLimitExported())
}

func TestExportedAccessors(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	assert.Equal(t, 60_000_000_000, int(c.ResolvedConfig().CollectionInterval))
	assert.Equal(t, "", c.FirstInstanceID())

	c.SetSyntheticInstance("inst-writer", "arn:x", true)
	assert.Equal(t, "inst-writer", c.FirstInstanceID())
	assert.Equal(t, 1, c.NumInstances())
}
