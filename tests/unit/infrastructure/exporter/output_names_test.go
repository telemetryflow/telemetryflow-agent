// Package exporter_test — small coverage top-ups for plugin.Output.Name on
// the Datadog + Prometheus remote-write outputs, plus the remote-write
// Connect probe success/error branches (driven against httptest servers).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package exporter_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func TestDatadog_Name(t *testing.T) {
	srv, _ := newDatadogCapturingServer(t)
	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{})
	assert.Equal(t, "datadog", out.Name())
	require.NoError(t, out.Close())
}

func TestPromRemoteWrite_NameAndConnectProbe(t *testing.T) {
	t.Run("name + connect success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)

		out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
			Endpoint: srv.URL, Timeout: 2 * time.Second, Logger: zap.NewNop(),
		})
		require.NoError(t, err)
		assert.Equal(t, "prometheus_remote_write", out.Name())
		require.NoError(t, out.Connect())
		require.NoError(t, out.Close())
	})

	t.Run("connect probe non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
			Endpoint: srv.URL, Timeout: 2 * time.Second, Logger: zap.NewNop(),
		})
		require.NoError(t, err)
		err = out.Connect()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "probe returned")
		require.NoError(t, out.Close())
	})

	t.Run("connect probe unreachable", func(t *testing.T) {
		// Port 1 refuses immediately (connection refused) — deterministic,
		// no real network egress.
		out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
			Endpoint: "http://127.0.0.1:1/write", Timeout: 500 * time.Millisecond, Logger: zap.NewNop(),
		})
		require.NoError(t, err)
		require.Error(t, out.Connect())
		require.NoError(t, out.Close())
	})
}
