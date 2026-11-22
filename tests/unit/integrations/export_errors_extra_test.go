// Package integrations_test — additional coverage for the Export / ExportMetrics
// / ExportTraces / ExportLogs / sendRequest error paths of the exporters. A
// local httptest server answers GET (health probes) with 200 and POST/PUT
// (data sends) with 500, so Init succeeds but every data send exercises the
// error-handling branch deterministically, without real network egress.
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
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// serverErrOnSend returns 200 for GET (health probes) and 500 for data sends.
func serverErrOnSend() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
}

func exportErrSampleData() *integrations.TelemetryData {
	now := time.Now()
	return &integrations.TelemetryData{
		Metrics: []integrations.Metric{{Name: "m", Value: 1, Type: integrations.MetricTypeGauge, Timestamp: now}},
		Traces:  []integrations.Trace{{TraceID: "t", SpanID: "s", OperationName: "op", ServiceName: "svc", StartTime: now, Duration: time.Millisecond, Status: integrations.TraceStatusOK}},
		Logs:    []integrations.LogEntry{{Timestamp: now, Level: integrations.LogLevelInfo, Message: "msg", Source: "src"}},
	}
}

// assertExportFailed accepts either a returned error or a non-nil result whose
// Success is false — both signal the error path was taken.
func assertExportFailed(t *testing.T, res *integrations.ExportResult, err error) {
	t.Helper()
	if err != nil {
		assert.Error(t, err)
		return
	}
	if assert.NotNil(t, res) {
		assert.False(t, res.Success)
	}
}

func TestLokiExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewLokiExporter(integrations.LokiConfig{Enabled: true, Endpoint: srv.URL, BearerToken: "tok"}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestInfluxDBExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewInfluxDBExporter(integrations.InfluxDBConfig{
		Enabled: true, URL: srv.URL, Token: "tok", Organization: "org", Bucket: "b", Database: "db",
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestDynatraceExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewDynatraceExporter(integrations.DynatraceConfig{
		Enabled: true, APIToken: "tok", EnvironmentURL: srv.URL,
		MetricsEndpoint: srv.URL, LogsEndpoint: srv.URL, TracesEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestManageEngineExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewManageEngineExporter(integrations.ManageEngineConfig{
		Enabled: true, APIKey: "key", BaseURL: srv.URL,
		MetricsEndpoint: srv.URL, AlertsEndpoint: srv.URL, LogsEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestOpenObserveExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewOpenObserveExporter(integrations.OpenObserveConfig{
		Enabled: true, Endpoint: srv.URL, Organization: "org", Username: "u", Password: "p",
		MetricsEndpoint: srv.URL, TracesEndpoint: srv.URL, LogsEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestDatadogExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewDatadogExporter(integrations.DatadogConfig{
		Enabled: true, APIKey: "0123456789abcdef0123456789abcdef",
		MetricsEndpoint: srv.URL, LogsEndpoint: srv.URL, TracesEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}
