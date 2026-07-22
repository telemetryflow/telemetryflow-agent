// Package integrations_test contains additional coverage tests for the eBPF
// exporter's metric collectors. These exercise the pure in-memory collector
// functions that are otherwise gated behind a Linux-only Init path, by
// enabling all collectors and marking the exporter initialized directly.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

func ebpfAllCollectorsConfig() integrations.EBPFConfig {
	return integrations.EBPFConfig{
		Enabled:          true,
		CollectSyscalls:  true,
		CollectNetwork:   true,
		CollectFileIO:    true,
		CollectScheduler: true,
		CollectMemory:    true,
		CollectTCPEvents: true,
		Labels:           map[string]string{"env": "test"},
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			KubernetesEnabled: true,
			CollectFlows:      true,
			CollectL7Flows:    true,
			CollectDrops:      true,
			CollectPolicies:   true,
			CollectServices:   true,
		},
	}
}

func TestEBPFCollectMetricsAllCollectors(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	exporter := integrations.NewEBPFExporter(ebpfAllCollectorsConfig(), logger)
	// Bypass the Linux-only Init gate to exercise the pure collector functions.
	exporter.SetInitialized(true)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, metrics)

	// Verify base tags are applied and metric names are populated.
	for _, m := range metrics {
		assert.NotEmpty(t, m.Name)
		assert.NotEmpty(t, m.Tags["collector"])
	}
}

func TestEBPFExportCollectsMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	exporter := integrations.NewEBPFExporter(ebpfAllCollectorsConfig(), logger)
	exporter.SetInitialized(true)

	data := &integrations.TelemetryData{}
	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Greater(t, result.ItemsExported, 0)
	assert.Equal(t, result.ItemsExported, len(data.Metrics))
}

func TestEBPFCollectMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	exporter := integrations.NewEBPFExporter(ebpfAllCollectorsConfig(), logger)
	_, err := exporter.CollectMetrics(ctx)
	assert.ErrorIs(t, err, integrations.ErrNotInitialized)
}

func TestEBPFCollectMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	exporter := integrations.NewEBPFExporter(integrations.EBPFConfig{Enabled: false}, logger)
	_, err := exporter.CollectMetrics(ctx)
	assert.ErrorIs(t, err, integrations.ErrNotEnabled)
}

func TestEBPFExportDataSourceMethods(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	exporter := integrations.NewEBPFExporter(ebpfAllCollectorsConfig(), logger)

	_, err := exporter.ExportMetrics(ctx, nil)
	assert.Error(t, err)
	_, err = exporter.ExportTraces(ctx, nil)
	assert.Error(t, err)
	_, err = exporter.ExportLogs(ctx, nil)
	assert.Error(t, err)
}
