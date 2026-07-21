// Package exporter_test contains unit tests for the OTLP metric bridge and
// the exported conversion helpers.
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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func endpointHost(t *testing.T, url string) string {
	t.Helper()
	return strings.TrimPrefix(url, "http://")
}

func bridgeMetrics() []collector.Metric {
	now := time.Now()
	return []collector.Metric{
		{Name: "db_connections", Description: "conns", Unit: "1", Type: collector.MetricTypeGauge, Value: 5, Timestamp: now, Labels: map[string]string{"db": "pg"}},
		{Name: "db_queries_total", Description: "queries", Unit: "1", Type: collector.MetricTypeCounter, Value: 42, Timestamp: now, Labels: map[string]string{"db": "pg"}},
		{Name: "db_connections", Type: collector.MetricTypeGauge, Value: 7, Timestamp: now, Labels: map[string]string{"db": "pg2"}},
	}
}

func TestOTLPMetricBridge_ExportAndShutdown(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/metrics", r.URL.Path)
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricBridge(ctx, exporter.OTLPMetricBridgeConfig{
		Endpoint: endpointHost(t, srv.URL),
		Path:     "/v1/metrics",
		Headers:  map[string]string{"X-Test": "1"},
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	require.NotNil(t, b)

	// Empty batch is a no-op.
	require.NoError(t, b.Export(ctx, nil, nil))

	err = b.Export(ctx, bridgeMetrics(), map[string]string{"db.system": "postgresql"})
	require.NoError(t, err)
	assert.Eventually(t, func() bool { return atomic.LoadInt64(&hits) >= 1 }, time.Second, 5*time.Millisecond)

	require.NoError(t, b.Shutdown(ctx))
	// Shutdown is idempotent enough to be called after exporter close.
}

func TestOTLPMetricBridge_DefaultLoggerAndNoPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricBridge(ctx, exporter.OTLPMetricBridgeConfig{
		Endpoint: endpointHost(t, srv.URL),
		// No Path, no Logger -> default logger, default path.
	})
	require.NoError(t, err)
	require.NoError(t, b.Export(ctx, bridgeMetrics(), nil))
	require.NoError(t, b.Shutdown(ctx))
}

func TestOTLPMetricBridge_ExportError(t *testing.T) {
	// Server returns a permanent error; exporter surfaces it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	ctx := context.Background()
	b, err := exporter.NewOTLPMetricBridge(ctx, exporter.OTLPMetricBridgeConfig{
		Endpoint: endpointHost(t, srv.URL),
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	err = b.Export(ctx, bridgeMetrics(), nil)
	assert.Error(t, err)
	_ = b.Shutdown(ctx)
}

func TestOTLPMetricBridge_TLSConfig(t *testing.T) {
	// TLS enabled path builds a TLS client config (no live connection needed).
	ctx := context.Background()
	b, err := exporter.NewOTLPMetricBridge(ctx, exporter.OTLPMetricBridgeConfig{
		Endpoint:      "127.0.0.1:4318",
		TLSEnabled:    true,
		TLSSkipVerify: true,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NoError(t, b.Shutdown(ctx))
}

func TestExportedConversionHelpers(t *testing.T) {
	// labelsToAttributeSet: empty and populated.
	empty := exporter.LabelsToAttributeSetExported(nil)
	assert.Equal(t, 0, empty.Len())
	set := exporter.LabelsToAttributeSetExported(map[string]string{"a": "1", "b": "2"})
	assert.Equal(t, 2, set.Len())

	// baseResourceAttrs contains service.name/version.
	base := exporter.BaseResourceAttrsExported()
	assert.Len(t, base, 2)

	// groupMetricsByName groups by name.
	groups := exporter.GroupMetricsByNameExported(bridgeMetrics())
	assert.Len(t, groups["db_connections"], 2)
	assert.Len(t, groups["db_queries_total"], 1)

	// buildAggregation: counter -> Sum, gauge -> Gauge, empty -> Gauge.
	counterAgg := exporter.BuildAggregationExported(groups["db_queries_total"])
	assert.NotNil(t, counterAgg)
	gaugeAgg := exporter.BuildAggregationExported(groups["db_connections"])
	assert.NotNil(t, gaugeAgg)
	emptyAgg := exporter.BuildAggregationExported(nil)
	assert.NotNil(t, emptyAgg)
}
