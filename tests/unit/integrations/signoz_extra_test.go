// Package integrations_test contains additional coverage tests for the SigNoz
// exporter focusing on Health checks and error-path handling.
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

func signozSampleData() *integrations.TelemetryData {
	return &integrations.TelemetryData{
		Metrics: []integrations.Metric{{Name: "m", Value: 1, Type: integrations.MetricTypeGauge, Timestamp: time.Now()}},
		Traces:  []integrations.Trace{{TraceID: "t", SpanID: "s", OperationName: "op", ServiceName: "svc", StartTime: time.Now(), Duration: time.Millisecond, Status: integrations.TraceStatusOK}},
		Logs:    []integrations.LogEntry{{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "msg", Source: "src"}},
	}
}

func TestSigNozHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/health", r.URL.Path)
		assert.Equal(t, "tok-1", r.Header.Get("SIGNOZ-ACCESS-TOKEN"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.SigNozConfig{Enabled: true, Endpoint: server.URL, AccessToken: "tok-1"}
	exporter := integrations.NewSigNozExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestSigNozHealthNon200(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := integrations.SigNozConfig{Enabled: true, Endpoint: server.URL}
	exporter := integrations.NewSigNozExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
}

func TestSigNozHealthConnectionFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	config := integrations.SigNozConfig{Enabled: true, Endpoint: url}
	exporter := integrations.NewSigNozExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
}

func TestSigNozExportServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := integrations.SigNozConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
		AccessToken:     "tok",
		Headers:         map[string]string{"X-Extra": "v"},
	}
	exporter := integrations.NewSigNozExporter(config, logger)
	require.NoError(t, exporter.Init(ctx))

	_, err := exporter.ExportMetrics(ctx, signozSampleData().Metrics)
	assert.Error(t, err)
	_, err = exporter.ExportTraces(ctx, signozSampleData().Traces)
	assert.Error(t, err)
	_, err = exporter.ExportLogs(ctx, signozSampleData().Logs)
	assert.Error(t, err)

	result, err := exporter.Export(ctx, signozSampleData())
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}
