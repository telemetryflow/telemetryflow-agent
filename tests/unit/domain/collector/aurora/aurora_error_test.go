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

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
)

// cancelledBackoffCtx returns a context that expires quickly so the throttling
// backoff loop hits its ctx.Done() branch instead of sleeping through retries.
func shortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestGetMetricData_ThrottlingBackoffCancelled(t *testing.T) {
	srv := newMockAWSServer(t, mockThrottling)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	// collectCloudWatchMetrics swallows batch errors and returns nil error,
	// but the underlying throttling path is exercised.
	_, err := c.CollectCloudWatchFirst(shortCtx(t))
	require.NoError(t, err)
}

func TestDescribeDBCluster_Throttling(t *testing.T) {
	srv := newMockAWSServer(t, mockThrottling)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))

	err := c.DescribeDBClusterFirst(shortCtx(t), "test-cluster")
	require.Error(t, err)
}

func TestDescribeDBInstances_Throttling(t *testing.T) {
	srv := newMockAWSServer(t, mockThrottling)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))

	_, err := c.DescribeDBInstancesFirst(shortCtx(t), "test-cluster")
	require.Error(t, err)
}

func TestPI_Throttling(t *testing.T) {
	srv := newMockAWSServer(t, mockThrottling)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	// collectPerformanceInsights logs and continues per-metric errors.
	metrics, err := c.CollectPIFirst(shortCtx(t))
	require.NoError(t, err)
	require.Empty(t, metrics)
}

func TestPI_Error(t *testing.T) {
	srv := newMockAWSServer(t, mockError)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	metrics, err := c.CollectPIFirst(context.Background())
	require.NoError(t, err)
	require.Empty(t, metrics)
}

func TestQANInstance_Error(t *testing.T) {
	srv := newMockAWSServer(t, mockError)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	_, err := c.CollectQANInstanceFirst(context.Background())
	require.Error(t, err)
}

func TestDescribeDBCluster_NotFound(t *testing.T) {
	// Empty cluster list -> "not found" error.
	srv := newEmptyClusterServer(t)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))

	err := c.DescribeDBClusterFirst(context.Background(), "missing-cluster")
	require.Error(t, err)
}
