// Package integrations_test — second batch of Export error-path coverage for
// the remaining HTTP-based exporters, using the shared serverErrOnSend helper
// (200 on GET health probes, 500 on data sends) so every data send hits the
// error branch deterministically and offline.
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
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

func TestZipkinExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewZipkinExporter(integrations.ZipkinConfig{Enabled: true, Endpoint: srv.URL}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestSigNozExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewSigNozExporter(integrations.SigNozConfig{
		Enabled: true, Endpoint: srv.URL, AccessToken: "tok",
		MetricsEndpoint: srv.URL, TracesEndpoint: srv.URL, LogsEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestNetdataExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewNetdataExporter(integrations.NetdataConfig{
		Enabled: true, Endpoint: srv.URL, APIToken: "tok", MetricsEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestPrometheusExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewPrometheusExporter(integrations.PrometheusConfig{Enabled: true, Endpoint: srv.URL}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestInstanaExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewInstanaExporter(integrations.InstanaConfig{
		Enabled: true, AgentKey: "key", EndpointURL: srv.URL,
		MetricsEndpoint: srv.URL, TracesEndpoint: srv.URL, EventsEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestSplunkExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewSplunkExporter(integrations.SplunkConfig{
		Enabled: true, HECEndpoint: srv.URL, HECToken: "tok", Index: "main",
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}

func TestAzureExportServerErrorBatch(t *testing.T) {
	srv := serverErrOnSend()
	defer srv.Close()
	ctx := context.Background()
	ex := integrations.NewAzureExporter(integrations.AzureConfig{
		Enabled: true, WorkspaceKey: "dGVzdGtleQ==", InstrumentationKey: "ik",
		CustomMetricsEndpoint: srv.URL, LogAnalyticsEndpoint: srv.URL, ApplicationInsightsEndpoint: srv.URL,
	}, zap.NewNop())
	_ = ex.Init(ctx)
	res, err := ex.Export(ctx, exportErrSampleData())
	assertExportFailed(t, res, err)
}
