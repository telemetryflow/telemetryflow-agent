// Package integrations_test contains additional coverage tests for the
// OpenObserve exporter focusing on Health checks and error-path handling.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package integrations_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

func openobserveSampleData() *integrations.TelemetryData {
	return &integrations.TelemetryData{
		Metrics: []integrations.Metric{{Name: "m", Value: 1, Type: integrations.MetricTypeGauge, Timestamp: time.Now()}},
		Traces:  []integrations.Trace{{TraceID: "t", SpanID: "s", OperationName: "op", ServiceName: "svc", StartTime: time.Now(), Duration: time.Millisecond, Status: integrations.TraceStatusOK}},
		Logs:    []integrations.LogEntry{{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "msg", Source: "src"}},
	}
}

func TestOpenObserveHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/healthz", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.OpenObserveConfig{Enabled: true, Endpoint: server.URL, Username: "u", Password: "p"}
	exporter := integrations.NewOpenObserveExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestOpenObserveHealthNon200(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := integrations.OpenObserveConfig{Enabled: true, Endpoint: server.URL, Username: "u", Password: "p"}
	exporter := integrations.NewOpenObserveExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
}

func TestOpenObserveHealthConnectionFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	config := integrations.OpenObserveConfig{Enabled: true, Endpoint: url, Username: "u", Password: "p"}
	exporter := integrations.NewOpenObserveExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
}

func TestOpenObserveExportServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := integrations.OpenObserveConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
		Username:        "u",
		Password:        "p",
		Headers:         map[string]string{"X-Extra": "v"},
	}
	exporter := integrations.NewOpenObserveExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	_, err := exporter.ExportMetrics(ctx, openobserveSampleData().Metrics)
	assert.Error(t, err)
	_, err = exporter.ExportTraces(ctx, openobserveSampleData().Traces)
	assert.Error(t, err)
	_, err = exporter.ExportLogs(ctx, openobserveSampleData().Logs)
	assert.Error(t, err)

	result, err := exporter.Export(ctx, openobserveSampleData())
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}
