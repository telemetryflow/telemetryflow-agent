// Package exporter_test contains unit tests for the Datadog output (Metrics
// v2 intake over plain HTTP). Tests drive the output against an httptest
// server; no traffic leaves the loopback interface.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// datadogCapture records the last request received by the test intake.
type datadogCapture struct {
	mu       sync.Mutex
	method   string
	path     string
	headers  http.Header
	body     []byte
	statuses chan int
}

func newDatadogCapturingServer(t *testing.T) (*httptest.Server, *datadogCapture) {
	t.Helper()
	cap := &datadogCapture{statuses: make(chan int, 16)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cap.mu.Lock()
		cap.method = r.Method
		cap.path = r.URL.Path
		cap.headers = r.Header.Clone()
		cap.body = body
		cap.mu.Unlock()

		select {
		case code := <-cap.statuses:
			w.WriteHeader(code)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func (c *datadogCapture) snapshot() (string, string, http.Header, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.method, c.path, c.headers, append([]byte(nil), c.body...)
}

// newDatadogOutputWithServer wires up an output pointing at srv. The cfg's
// Site/endpoint defaults are overridden via constructing first, then
// hot-swapping the endpoint through a fresh client bound to srv.
func newDatadogOutputWithServer(t *testing.T, srv *httptest.Server, cfg exporter.DatadogOutputConfig) *exporter.DatadogOutput {
	t.Helper()
	if cfg.APIKey == "" {
		cfg.APIKey = "test-key-123"
	}
	cfg.Logger = zap.NewNop()

	out, err := exporter.NewDatadogOutput(cfg)
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	// Redirect at the output level onto the test server. We keep the
	// /api/v2/series path so the test server sees the same request shape
	// the real intake would.
	out.SetEndpointForTest(srv.URL + "/api/v2/series")
	return out
}

func TestDatadog_Write_ThreeMetricsThreeSeries(t *testing.T) {
	srv, cap := newDatadogCapturingServer(t)
	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{})
	t.Cleanup(func() { require.NoError(t, out.Close()) })

	now := time.Unix(1_700_000_000, 0).UTC()
	metrics := []plugin.Metric{
		{Name: "system.cpu.usage", Type: plugin.MetricTypeGauge, Value: 42.5, Timestamp: now, Labels: map[string]string{"host": "node-1", "region": "us-east"}},
		{Name: "system.mem.used", Type: plugin.MetricTypeGauge, Value: 1024, Timestamp: now, Labels: map[string]string{"host": "node-1"}},
		{Name: "http.requests.total", Type: plugin.MetricTypeCounter, Value: 7, Timestamp: now, Labels: map[string]string{"host": "node-1", "code": "200"}},
	}
	require.NoError(t, out.Write(metrics))

	method, path, headers, body := cap.snapshot()
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "/api/v2/series", path)
	assert.Equal(t, "test-key-123", headers.Get("DD-API-KEY"))
	assert.Equal(t, "application/json", headers.Get("Content-Type"))
	assert.Contains(t, headers.Get("User-Agent"), "tfo-agent/")

	var payload struct {
		Series []struct {
			Metric string `json:"metric"`
			Points []struct {
				Timestamp int64   `json:"timestamp"`
				Value     float64 `json:"value"`
			} `json:"points"`
			Tags []string `json:"tags"`
			Type int32    `json:"type"`
		} `json:"series"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	require.Len(t, payload.Series, 3)

	byName := make(map[string]int, len(payload.Series))
	for i, s := range payload.Series {
		byName[s.Metric] = i
	}

	cpu := payload.Series[byName["system.cpu.usage"]]
	assert.Equal(t, int32(3), cpu.Type, "gauges use type 3")
	require.Len(t, cpu.Points, 1)
	assert.InDelta(t, 42.5, cpu.Points[0].Value, 1e-9)
	assert.Equal(t, now.Unix(), cpu.Points[0].Timestamp)
	assert.Equal(t, []string{"host:node-1", "region:us-east"}, cpu.Tags, "tags must be key:value and sorted")

	reqs := payload.Series[byName["http.requests.total"]]
	assert.Equal(t, int32(1), reqs.Type, "counters use type 1")
	assert.Equal(t, []string{"code:200", "host:node-1"}, reqs.Tags)
}

func TestDatadog_TagsAreSortedKeyColonValue(t *testing.T) {
	srv, cap := newDatadogCapturingServer(t)
	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{})
	t.Cleanup(func() { require.NoError(t, out.Close()) })

	require.NoError(t, out.Write([]plugin.Metric{
		{
			Name:      "tag.order",
			Value:     1,
			Timestamp: time.Now().UTC(),
			Labels: map[string]string{
				"zebra":  "z",
				"alpha":  "a",
				"middle": "m",
			},
		},
	}))
	_, _, _, body := cap.snapshot()

	var payload struct {
		Series []struct {
			Tags []string `json:"tags"`
		} `json:"series"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	require.Len(t, payload.Series, 1)
	assert.Equal(t, []string{"alpha:a", "middle:m", "zebra:z"}, payload.Series[0].Tags)
}

func TestDatadog_EUSiteUsesDifferentURL(t *testing.T) {
	// Construct an output pointed at the EU site and check the endpoint it
	// would use. We don't actually send traffic; we just inspect the
	// endpoint that the constructor computed.
	out, err := exporter.NewDatadogOutput(exporter.DatadogOutputConfig{
		APIKey: "k",
		Site:   "datadoghq.eu",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	assert.Equal(t, "https://api.datadoghq.eu/api/v2/series", out.EndpointForTest())
	require.NoError(t, out.Close())

	out2, err := exporter.NewDatadogOutput(exporter.DatadogOutputConfig{
		APIKey: "k",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	assert.Equal(t, "https://api.datadoghq.com/api/v2/series", out2.EndpointForTest(), "default site is US1")
	require.NoError(t, out2.Close())
}

func TestDatadog_APIKeyHeader(t *testing.T) {
	srv, cap := newDatadogCapturingServer(t)
	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{
		APIKey: "hunter2",
	})
	t.Cleanup(func() { require.NoError(t, out.Close()) })

	require.NoError(t, out.Write([]plugin.Metric{
		{Name: "k.test", Value: 1, Timestamp: time.Now().UTC()},
	}))
	_, _, headers, _ := cap.snapshot()
	assert.Equal(t, "hunter2", headers.Get("DD-API-KEY"), "API key goes in the DD-API-KEY header (hyphenated)")
}

func TestDatadog_4xxResponseReturnsError(t *testing.T) {
	srv, cap := newDatadogCapturingServer(t)
	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{})
	t.Cleanup(func() { require.NoError(t, out.Close()) })

	cap.statuses <- http.StatusUnauthorized

	err := out.Write([]plugin.Metric{
		{Name: "denied.metric", Value: 1, Timestamp: time.Now().UTC()},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestDatadog_EmptyBatchIsNoop(t *testing.T) {
	srv, cap := newDatadogCapturingServer(t)
	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{})
	t.Cleanup(func() { require.NoError(t, out.Close()) })

	require.NoError(t, out.Write(nil))
	method, _, _, body := cap.snapshot()
	assert.Empty(t, method, "no POST for an empty batch")
	assert.Nil(t, body)
}

func TestDatadog_NewRequiresAPIKey(t *testing.T) {
	_, err := exporter.NewDatadogOutput(exporter.DatadogOutputConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestDatadog_BatchingRespectsBatchSize(t *testing.T) {
	var count int
	mu := sync.Mutex{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	out := newDatadogOutputWithServer(t, srv, exporter.DatadogOutputConfig{BatchSize: 2})
	t.Cleanup(func() { require.NoError(t, out.Close()) })

	metrics := make([]plugin.Metric, 5)
	for i := range metrics {
		metrics[i] = plugin.Metric{
			Name:      "batch.test",
			Value:     float64(i),
			Timestamp: time.Now().UTC(),
		}
	}
	require.NoError(t, out.Write(metrics))
	assert.Equal(t, 3, count, "5 metrics / BatchSize 2 -> 3 POSTs")
}
