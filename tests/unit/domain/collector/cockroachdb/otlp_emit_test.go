// Package cockroachdb_test contains unit tests for the CockroachDB collector.
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
package cockroachdb_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func sampleMetric() collector.Metric {
	return collector.Metric{
		Name:  "db.cockroachdb.node.is_live",
		Type:  collector.MetricTypeGauge,
		Value: 1,
		Labels: map[string]string{
			"cockroachdb_instance":   "crdb-1",
			"cockroachdb_host":       "localhost",
			"cockroachdb_version":    "23.1",
			"cockroachdb_cluster_id": "cid-1",
		},
	}
}

func TestNewOTLPEmitter(t *testing.T) {
	e := cockroachdb.NewOTLPEmitter(nil, zap.NewNop())
	require.NotNil(t, e)
}

func TestOTLPEmitter_NilBridge(t *testing.T) {
	e := cockroachdb.NewOTLPEmitter(nil, zap.NewNop())
	ctx := context.Background()

	// Nil bridge + non-empty metrics => no-op, no error.
	require.NoError(t, e.EmitMetrics(ctx, []collector.Metric{sampleMetric()}))

	// Empty metrics => no-op.
	require.NoError(t, e.EmitMetrics(ctx, nil))

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "x"})
	require.NoError(t, e.EmitMetricsForInstanceExported(ctx, []collector.Metric{sampleMetric()}, inst))
	require.NoError(t, e.EmitMetricsForInstanceExported(ctx, nil, inst))

	// Shutdown with nil bridge => no error.
	require.NoError(t, e.Shutdown(ctx))
}

func newBridge(t *testing.T, endpoint string) *exporter.OTLPMetricBridge {
	t.Helper()
	b, err := exporter.NewOTLPMetricBridge(context.Background(), exporter.OTLPMetricBridgeConfig{
		Endpoint: endpoint,
		Path:     "/v1/metrics",
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	return b
}

func TestOTLPEmitter_RealBridge(t *testing.T) {
	// Bad endpoint so Export returns an error (covers the error-wrap branch).
	// Uses a reserved TEST-NET address that will not connect.
	bridge := newBridge(t, "192.0.2.1:4317")
	e := cockroachdb.NewOTLPEmitter(bridge, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled context forces a fast export failure

	err := e.EmitMetrics(ctx, []collector.Metric{sampleMetric()})
	assert.Error(t, err)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "crdb-1", Host: "localhost", SQLPort: 26257, Database: "system"})
	inst.Version = "23.1"
	inst.ClusterID = "cid-1"
	err = e.EmitMetricsForInstanceExported(ctx, []collector.Metric{sampleMetric()}, inst)
	assert.Error(t, err)

	_ = e.Shutdown(context.Background())
}

func TestOTLPEmitter_ExportSuccess(t *testing.T) {
	// Minimal OTLP/HTTP receiver that returns 200 with an empty (valid) body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	endpoint := strings.TrimPrefix(srv.URL, "http://") // host:port

	bridge, err := exporter.NewOTLPMetricBridge(context.Background(), exporter.OTLPMetricBridgeConfig{
		Endpoint: endpoint,
		Path:     "/v1/metrics",
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	e := cockroachdb.NewOTLPEmitter(bridge, zap.NewNop())
	ctx := context.Background()

	require.NoError(t, e.EmitMetrics(ctx, []collector.Metric{sampleMetric()}))

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{
		Name: "crdb-1", Host: "localhost", SQLPort: 26257, Database: "system",
	})
	inst.Version = "23.1"
	inst.ClusterID = "cid-1"
	require.NoError(t, e.EmitMetricsForInstanceExported(ctx, []collector.Metric{sampleMetric()}, inst))

	require.NoError(t, e.Shutdown(ctx))
}
