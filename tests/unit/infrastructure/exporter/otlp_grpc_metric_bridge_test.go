// Package exporter_test contains unit tests for the OTLP gRPC metric bridge.
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
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	collectormetricsv1 "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// stubMetricsServer captures Export calls so the test can assert the bridge
// encoded and delivered the ResourceMetrics payload.
type stubMetricsServer struct {
	collectormetricsv1.UnimplementedMetricsServiceServer

	mu       sync.Mutex
	hits     int64
	requests []*collectormetricsv1.ExportMetricsServiceRequest
}

func (s *stubMetricsServer) Export(ctx context.Context, req *collectormetricsv1.ExportMetricsServiceRequest) (*collectormetricsv1.ExportMetricsServiceResponse, error) {
	atomic.AddInt64(&s.hits, 1)
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
	return &collectormetricsv1.ExportMetricsServiceResponse{}, nil
}

func (s *stubMetricsServer) snapshot() []*collectormetricsv1.ExportMetricsServiceRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*collectormetricsv1.ExportMetricsServiceRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// startStubCollector spins up a gRPC server implementing the OTLP metrics
// service on a random localhost port and returns its address + a cleanup fn.
func startStubCollector(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	collectormetricsv1.RegisterMetricsServiceServer(srv, &stubMetricsServer{})

	go func() { _ = srv.Serve(lis) }()

	cleanup := func() {
		srv.GracefulStop()
		_ = lis.Close()
	}
	return lis.Addr().String(), cleanup
}

func grpcBridgeMetrics() []collector.Metric {
	now := time.Now()
	return []collector.Metric{
		{Name: "db_connections", Description: "conns", Unit: "1", Type: collector.MetricTypeGauge, Value: 5, Timestamp: now, Labels: map[string]string{"db": "pg"}},
		{Name: "db_queries_total", Description: "queries", Unit: "1", Type: collector.MetricTypeCounter, Value: 42, Timestamp: now, Labels: map[string]string{"db": "pg"}},
	}
}

func TestOTLPMetricGRPCBridge_ConstructAndShutdown(t *testing.T) {
	addr, cleanup := startStubCollector(t)
	defer cleanup()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricGRPCBridge(ctx, exporter.OTLPMetricGRPCBridgeConfig{
		Endpoint: addr,
		Headers:  map[string]string{"X-Test": "1"},
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	require.NotNil(t, b)

	// Empty batch is a no-op.
	require.NoError(t, b.Export(ctx, nil, nil))

	require.NoError(t, b.Shutdown(ctx))
}

// TestOTLPMetricGRPCBridge_ExportRecordsRequest uses a dedicated recorder so
// we can verify the ResourceMetrics payload arrived intact.
func TestOTLPMetricGRPCBridge_ExportRecordsRequest(t *testing.T) {
	rec := &stubMetricsServer{}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	collectormetricsv1.RegisterMetricsServiceServer(srv, rec)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.GracefulStop(); _ = lis.Close() })

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricGRPCBridge(ctx, exporter.OTLPMetricGRPCBridgeConfig{
		Endpoint: lis.Addr().String(),
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Shutdown(ctx) })

	require.NoError(t, b.Export(ctx, grpcBridgeMetrics(), map[string]string{"db.system": "postgresql"}))

	require.Eventually(t, func() bool { return atomic.LoadInt64(&rec.hits) >= 1 }, 2*time.Second, 5*time.Millisecond)

	snap := rec.snapshot()
	require.Len(t, snap, 1)
	rm := snap[0].GetResourceMetrics()
	require.Len(t, rm, 1)
	// Resource attrs: base (service.name, service.version) + db.system.
	rattrs := rm[0].GetResource().GetAttributes()
	var sawSystem bool
	for _, kv := range rattrs {
		if kv.GetKey() == "db.system" && kv.Value.GetStringValue() == "postgresql" {
			sawSystem = true
		}
	}
	assert.True(t, sawSystem, "resource attribute db.system=postgresql should be encoded")

	// Two metric names: db_connections + db_queries_total.
	scopeMetrics := rm[0].GetScopeMetrics()
	require.Len(t, scopeMetrics, 1)
	names := map[string]struct{}{}
	for _, m := range scopeMetrics[0].GetMetrics() {
		names[m.GetName()] = struct{}{}
	}
	assert.Contains(t, names, "db_connections")
	assert.Contains(t, names, "db_queries_total")
}

func TestOTLPMetricGRPCBridge_TLSConfig(t *testing.T) {
	// TLS-enabled path builds a TLS dial option without a live connection.
	ctx := context.Background()
	b, err := exporter.NewOTLPMetricGRPCBridge(ctx, exporter.OTLPMetricGRPCBridgeConfig{
		Endpoint:      "127.0.0.1:4317",
		TLSEnabled:    true,
		TLSSkipVerify: true,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Shutdown(ctx))
}

func TestOTLPMetricGRPCBridge_CompressionAndTimeout(t *testing.T) {
	addr, cleanup := startStubCollector(t)
	defer cleanup()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricGRPCBridge(ctx, exporter.OTLPMetricGRPCBridgeConfig{
		Endpoint:    addr,
		Compression: "gzip",
		Timeout:     2 * time.Second,
		Logger:      zap.NewNop(),
	})
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Shutdown(ctx))
}

func TestOTLPMetricGRPCBridge_ExportAfterShutdown(t *testing.T) {
	addr, cleanup := startStubCollector(t)
	defer cleanup()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricGRPCBridge(ctx, exporter.OTLPMetricGRPCBridgeConfig{
		Endpoint: addr,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, b.Shutdown(ctx))

	// After shutdown the exporter must reject further exports.
	err = b.Export(ctx, grpcBridgeMetrics(), nil)
	assert.Error(t, err)
}

// Verify the insecure dial path is selected by default (no TLS).
func TestOTLPMetricGRPCBridge_InsecureDefault(t *testing.T) {
	addr, cleanup := startStubCollector(t)
	defer cleanup()

	// Dial the stub directly to prove the in-memory/loopback path is reachable
	// without TLS — sanity-checks the test harness before the bridge uses it.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricGRPCBridge(ctx, exporter.OTLPMetricGRPCBridgeConfig{
		Endpoint: addr,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, b.Shutdown(ctx))
}
