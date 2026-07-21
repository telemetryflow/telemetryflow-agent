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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
)

// newSelectiveServer serves success for RDS and (optionally) succeeds or errors
// for CloudWatch and PI independently.
func newSelectiveServer(t *testing.T, cwOK, piOK bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		target := r.Header.Get("X-Amz-Target")

		if strings.Contains(target, "GetResourceMetrics") {
			if !piOK {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"__type":"InternalServiceError","message":"boom"}`))
				return
			}
			writePIResponse(w, bodyBytes, false)
			return
		}
		if strings.Contains(r.URL.Path, "GetMetricData") {
			if !cwOK {
				w.Header().Set("smithy-protocol", "rpc-v2-cbor")
				w.Header().Set("X-Amzn-Errortype", "InternalServiceError")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/cbor")
			w.Header().Set("smithy-protocol", "rpc-v2-cbor")
			_, _ = w.Write(getMetricDataCBOR())
			return
		}
		writeSuccess(w, r, target, body, bodyBytes, false)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newPaginatedInstancesServer returns a Marker on the first DescribeDBInstances
// call to exercise the pagination loop.
func newPaginatedInstancesServer(t *testing.T) *httptest.Server {
	t.Helper()
	var instCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		if strings.Contains(body, "Action=DescribeDBInstances") {
			w.Header().Set("Content-Type", "text/xml")
			if atomic.AddInt32(&instCalls, 1) == 1 {
				// First page: one instance + a marker.
				_, _ = w.Write([]byte(`<DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">` +
					`<DescribeDBInstancesResult><Marker>next</Marker><DBInstances>` +
					`<DBInstance><DBInstanceIdentifier>inst-writer</DBInstanceIdentifier>` +
					`<DBInstanceStatus>available</DBInstanceStatus>` +
					`<PerformanceInsightsEnabled>true</PerformanceInsightsEnabled></DBInstance>` +
					`</DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
				return
			}
			// Second page: no marker, terminates the loop.
			_, _ = w.Write([]byte(describeDBInstancesXML))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(describeDBClustersXML))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newInstancesErrorServer serves a valid cluster but errors on DescribeDBInstances.
func newInstancesErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		if strings.Contains(body, "Action=DescribeDBInstances") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidParameterValue</Code><Message>bad</Message></Error></ErrorResponse>`))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(describeDBClustersXML))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverTopology_InstancesError(t *testing.T) {
	srv := newInstancesErrorServer(t)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	// Cluster describe succeeds, instances describe errors (non-throttling).
	_, err := c.DiscoverTopologyFirst(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DescribeDBInstances")
}

func TestDescribeDBInstances_Pagination(t *testing.T) {
	srv := newPaginatedInstancesServer(t)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))

	n, err := c.DescribeDBInstancesFirst(context.Background(), "test-cluster")
	require.NoError(t, err)
	// 1 from first page + 2 from second page.
	assert.Equal(t, 3, n)
}

func TestCollectCluster_CloudWatchError(t *testing.T) {
	srv := newSelectiveServer(t, false /*cwOK*/, true)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	_, err := c.DiscoverTopologyFirst(context.Background())
	require.NoError(t, err)

	// CloudWatch errors are logged and skipped -> no metrics, no error.
	metrics, err := c.CollectClusterFirst(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectAllPI_InstanceError(t *testing.T) {
	srv := newSelectiveServer(t, true, false /*piOK*/)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	// PI per-metric errors are swallowed; collectAllPI returns empty, no error.
	metrics, err := c.CollectAllPIExported(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectQAN_InstanceError(t *testing.T) {
	srv := newSelectiveServer(t, true, false /*piOK*/)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	// collectQANInstance errors -> warn + continue -> empty buckets, no error.
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestCollect_SingleClusterWithPI(t *testing.T) {
	srv := newSelectiveServer(t, true, true)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	_, err := c.DiscoverTopologyFirst(context.Background())
	require.NoError(t, err)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

// newTopologyChangeServer returns a different instance status on the second
// DescribeDBInstances call (same instance count) to exercise the change-detection
// branch.
func newTopologyChangeServer(t *testing.T) *httptest.Server {
	t.Helper()
	var instCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		if strings.Contains(body, "Action=DescribeDBInstances") {
			w.Header().Set("Content-Type", "text/xml")
			status := "available"
			if atomic.AddInt32(&instCalls, 1) > 1 {
				status = "modifying"
			}
			_, _ = w.Write([]byte(`<DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">` +
				`<DescribeDBInstancesResult><DBInstances>` +
				`<DBInstance><DBInstanceIdentifier>inst-writer</DBInstanceIdentifier>` +
				`<DBInstanceStatus>` + status + `</DBInstanceStatus>` +
				`<PerformanceInsightsEnabled>true</PerformanceInsightsEnabled></DBInstance>` +
				`</DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(describeDBClustersXML))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverTopology_StatusChangeDetected(t *testing.T) {
	srv := newTopologyChangeServer(t)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))

	changed1, err := c.DiscoverTopologyFirst(context.Background())
	require.NoError(t, err)
	assert.True(t, changed1)

	// Same instance count but status flips -> change detected again.
	changed2, err := c.DiscoverTopologyFirst(context.Background())
	require.NoError(t, err)
	assert.True(t, changed2)
}

func TestInitAWSClients_ConfigLoadError(t *testing.T) {
	setBadAWSConfig(t)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	err := c.InitAWSClientsFirst(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws config load failed")
}

func TestCollect_ClusterInitError(t *testing.T) {
	setBadAWSConfig(t)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	// rdsClient is nil -> collectCluster calls initAWSClients which fails; the
	// per-cluster error is logged and swallowed by Collect.
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectCluster_InitErrorPropagates(t *testing.T) {
	setBadAWSConfig(t)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	_, err := c.CollectClusterFirst(context.Background())
	require.Error(t, err)
}

func TestCollectQAN_LazyInitFailure(t *testing.T) {
	setBadAWSConfig(t)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	// piClient nil -> CollectQAN tries initAWSClients, which fails, and the
	// cluster is skipped.
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestCollectQAN_PIDisabledInstance(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", false) // PI disabled -> skipped

	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestCollectAllPI_NilClient(t *testing.T) {
	// A collector whose AWS clients were never initialised: piClient is nil,
	// so collectAllPI skips the state.
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	metrics, err := c.CollectAllPIExported(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectCloudWatch_SubMinutePeriod(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)
	cfg := baseCollectorConfig()
	cfg.CollectionInterval = 30 * time.Second // < 60s -> period clamped to 60
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	metrics, err := c.CollectCloudWatchFirst(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

// newQANEdgeServer returns PI SQL data with a zero-execution digest, a
// dimension-less entry, and a digest missing from the latency series.
func newQANEdgeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		target := r.Header.Get("X-Amz-Target")
		if !strings.Contains(target, "GetResourceMetrics") {
			body := string(bodyBytes)
			writeSuccess(w, r, target, body, bodyBytes, false)
			return
		}
		metric := "db.load.avg"
		if i := strings.Index(string(bodyBytes), `"Metric":"`); i >= 0 {
			rest := string(bodyBytes)[i+len(`"Metric":"`):]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				metric = rest[:j]
			}
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if strings.Contains(metric, "executions") {
			// s1 (10 execs), a dimension-less entry (dropped), s2 (8 execs but no
			// latency series) and s3 (0 execs, skipped).
			_, _ = w.Write([]byte(`{"MetricList":[` +
				`{"Key":{"Metric":"db.sql.executions","Dimensions":{"db.sql.statement":"s1"}},"DataPoints":[{"Timestamp":1704067200.0,"Value":10}]},` +
				`{"Key":{"Metric":"db.sql.executions"},"DataPoints":[{"Timestamp":1704067200.0,"Value":5}]},` +
				`{"Key":{"Metric":"db.sql.executions","Dimensions":{"db.sql.statement":"s2"}},"DataPoints":[{"Timestamp":1704067200.0,"Value":8}]},` +
				`{"Key":{"Metric":"db.sql.executions","Dimensions":{"db.sql.statement":"s3"}},"DataPoints":[{"Timestamp":1704067200.0,"Value":0}]}` +
				`]}`))
			return
		}
		// avg_latency: only s1 is present, so s2 has no latency entry.
		_, _ = w.Write([]byte(`{"MetricList":[` +
			`{"Key":{"Metric":"db.sql.avg_latency","Dimensions":{"db.sql.statement":"s1"}},"DataPoints":[{"Timestamp":1704067200.0,"Value":5}]}` +
			`]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCollectQANInstance_DigestEdgeCases(t *testing.T) {
	srv := newQANEdgeServer(t)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	// s1 and s2 yield buckets (s2 has no latency series); the dimension-less
	// entry is dropped and s3 has zero executions.
	n, err := c.CollectQANInstanceFirst(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

// newEmptyExecServer returns an empty PI SQL result so QAN produces no buckets.
func newEmptyExecServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		target := r.Header.Get("X-Amz-Target")
		if strings.Contains(target, "GetResourceMetrics") {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write([]byte(`{"MetricList":[]}`))
			return
		}
		writeSuccess(w, r, target, string(bodyBytes), bodyBytes, false)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCollectQANInstance_EmptyResultAndFallbacks(t *testing.T) {
	srv := newEmptyExecServer(t)
	setAWSTestEnv(t, srv.URL)
	cfg := baseCollectorConfig()
	cfg.PIInterval = 500 * time.Millisecond // sub-second -> periodSec clamps to 60
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	// Empty ARN exercises the identifier fallback.
	c.SetSyntheticInstance("inst-writer", "", true)

	n, err := c.CollectQANInstanceFirst(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestStart_TopologyChangeDuringTicks(t *testing.T) {
	srv := newTopologyChangeServer(t)
	setAWSTestEnv(t, srv.URL)
	cfg := baseCollectorConfig()
	cfg.TopologyInterval = 8 * time.Millisecond
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	assert.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)
	time.Sleep(60 * time.Millisecond) // allow several ticks (status flips -> change)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestPICallWithRetry_ExhaustThrottling(t *testing.T) {
	// Throttle every request; the QAN retry loop exhausts all attempts.
	srv := newThrottleThenOKServer(t, 1000, false)
	setAWSTestEnv(t, srv.URL)
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.InitAWSClientsFirst(context.Background()))
	c.SetSyntheticInstance("inst-writer", "arn:x", true)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.CollectQANInstanceFirst(ctx)
	require.Error(t, err)
}
