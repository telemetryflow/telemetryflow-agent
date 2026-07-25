// Package exporter_test contains unit tests for the Prometheus remote-write
// output (prompb + snappy block encoding).
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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// rwCapture records the last HTTP request received by the test server.
type rwCapture struct {
	mu       sync.Mutex
	method   string
	path     string
	headers  http.Header
	body     []byte
	statuses chan int // per-request status code override (default 204)
}

func newRemoteWriteCapturingServer(t *testing.T) (*httptest.Server, *rwCapture) {
	t.Helper()
	cap := &rwCapture{statuses: make(chan int, 16)}
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
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func (c *rwCapture) snapshot() (string, string, http.Header, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.method, c.path, c.headers, append([]byte(nil), c.body...)
}

func TestPromRemoteWrite_Write_Encoding(t *testing.T) {
	srv, cap := newRemoteWriteCapturingServer(t)

	out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
		Endpoint:  srv.URL,
		AuthType:  "none",
		Headers:   map[string]string{"X-Scope-OrgID": "tenant-42"},
		Timeout:   5 * time.Second,
		BatchSize: 100,
		Logger:    zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	now := time.UnixMilli(1_700_000_000_000).UTC()
	metrics := []plugin.Metric{
		{
			Name:      "system.cpu.usage",
			Type:      plugin.MetricTypeGauge,
			Value:     0.42,
			Timestamp: now,
			Labels:    map[string]string{"host": "node-1", "cpu": "0"},
		},
		{
			Name:      "http.requests_total",
			Type:      plugin.MetricTypeCounter,
			Value:     7,
			Timestamp: now,
			Labels:    map[string]string{"code": "200", "method": "GET"},
		},
	}

	require.NoError(t, out.Write(metrics))

	method, path, headers, body := cap.snapshot()
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "/", path)
	assert.Equal(t, "snappy", headers.Get("Content-Encoding"))
	assert.Equal(t, "application/x-protobuf", headers.Get("Content-Type"))
	assert.Equal(t, "0.1.0", headers.Get("X-Prometheus-Remote-Write-Version"))
	assert.Contains(t, headers.Get("User-Agent"), "tfo-agent/")
	assert.Equal(t, "tenant-42", headers.Get("X-Scope-OrgID"))
	assert.NotEmpty(t, body)

	// Decode snappy block, then unmarshal protobuf.
	raw, err := snappy.Decode(nil, body)
	require.NoError(t, err, "body should be valid snappy block format")

	var wr prompb.WriteRequest
	require.NoError(t, wr.Unmarshal(raw), "decoded body should be a valid prompb.WriteRequest")
	require.Len(t, wr.Timeseries, 2)

	tsByName := make(map[string]prompb.TimeSeries, len(wr.Timeseries))
	for _, ts := range wr.Timeseries {
		tsByName[rwLabelValue(ts.Labels, "__name__")] = ts
	}

	cpu := tsByName["system.cpu.usage"]
	require.NotNil(t, cpu.Labels)
	assert.Equal(t, []prompb.Label{
		{Name: "__name__", Value: "system.cpu.usage"},
		{Name: "cpu", Value: "0"},
		{Name: "host", Value: "node-1"},
	}, cpu.Labels, "labels must be sorted alphabetically")
	require.Len(t, cpu.Samples, 1)
	assert.InDelta(t, 0.42, cpu.Samples[0].Value, 1e-9)
	assert.Equal(t, int64(1_700_000_000_000), cpu.Samples[0].Timestamp)

	reqs := tsByName["http.requests_total"]
	assert.Equal(t, []prompb.Label{
		{Name: "__name__", Value: "http.requests_total"},
		{Name: "code", Value: "200"},
		{Name: "method", Value: "GET"},
	}, reqs.Labels)
	require.Len(t, reqs.Samples, 1)
	assert.InDelta(t, 7.0, reqs.Samples[0].Value, 1e-9)

	require.NoError(t, out.Close())
}

func TestPromRemoteWrite_BasicAuthAndBearer(t *testing.T) {
	cases := []struct {
		name    string
		cfg     exporter.PromRemoteWriteConfig
		wantHdr string
		wantVal string
	}{
		{
			name: "basic auth",
			cfg: exporter.PromRemoteWriteConfig{
				AuthType:  "basic",
				Username:  "alice",
				Password:  "s3cret",
				BatchSize: 10,
			},
			wantHdr: "Authorization",
			wantVal: "Basic YWxpY2U6czNjcmV0", // base64("alice:s3cret")
		},
		{
			name: "bearer token",
			cfg: exporter.PromRemoteWriteConfig{
				AuthType:  "bearer",
				Token:     "abc123",
				BatchSize: 10,
			},
			wantHdr: "Authorization",
			wantVal: "Bearer abc123",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cap := newRemoteWriteCapturingServer(t)
			tc.cfg.Endpoint = srv.URL
			tc.cfg.Timeout = 2 * time.Second
			tc.cfg.Logger = zap.NewNop()

			out, err := exporter.NewPromRemoteWriteOutput(tc.cfg)
			require.NoError(t, err)
			require.NoError(t, out.Write([]plugin.Metric{
				{Name: "tfo_test_metric", Type: plugin.MetricTypeGauge, Value: 1, Timestamp: time.Now()},
			}))

			_, _, headers, _ := cap.snapshot()
			assert.Equal(t, tc.wantVal, headers.Get(tc.wantHdr))
			require.NoError(t, out.Close())
		})
	}
}

func TestPromRemoteWrite_BatchingChunksByBatchSize(t *testing.T) {
	var requestCount int32
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(counting.Close)

	out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
		Endpoint:  counting.URL,
		AuthType:  "none",
		BatchSize: 2,
		Timeout:   2 * time.Second,
		Logger:    zap.NewNop(),
	})
	require.NoError(t, err)

	metrics := make([]plugin.Metric, 5)
	for i := range metrics {
		metrics[i] = plugin.Metric{
			Name:      "batch.test",
			Value:     float64(i),
			Timestamp: time.Now(),
			Labels:    map[string]string{"i": string(rune('a' + i))},
		}
	}
	require.NoError(t, out.Write(metrics))

	// 5 metrics / BatchSize=2 -> ceil(5/2) = 3 pushes.
	assert.Equal(t, int32(3), atomic.LoadInt32(&requestCount), "expected writes to be chunked by BatchSize")
	require.NoError(t, out.Close())
}

func TestPromRemoteWrite_RejectsReceiverError(t *testing.T) {
	srv, cap := newRemoteWriteCapturingServer(t)
	// Pre-seed the next response with 400.
	cap.statuses <- http.StatusBadRequest

	out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
		Endpoint:  srv.URL,
		AuthType:  "none",
		BatchSize: 100,
		Timeout:   2 * time.Second,
		Logger:    zap.NewNop(),
	})
	require.NoError(t, err)

	err = out.Write([]plugin.Metric{
		{Name: "err.metric", Value: 1, Timestamp: time.Now()},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	require.NoError(t, out.Close())
}

func TestPromRemoteWrite_LegacyExportAdapter(t *testing.T) {
	srv, cap := newRemoteWriteCapturingServer(t)

	out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
		Endpoint:  srv.URL,
		AuthType:  "none",
		BatchSize: 100,
		Timeout:   2 * time.Second,
		Logger:    zap.NewNop(),
	})
	require.NoError(t, err)

	legacy := []collector.Metric{
		{
			Name:      "legacy.gauge",
			Type:      collector.MetricTypeGauge,
			Value:     9.5,
			Timestamp: time.UnixMilli(1_700_000_000_001).UTC(),
			Labels:    map[string]string{"k": "v"},
		},
	}
	require.NoError(t, out.Export(context.Background(), legacy, nil))

	_, _, headers, body := cap.snapshot()
	assert.Equal(t, "snappy", headers.Get("Content-Encoding"))

	raw, err := snappy.Decode(nil, body)
	require.NoError(t, err)
	var wr prompb.WriteRequest
	require.NoError(t, wr.Unmarshal(raw))
	require.Len(t, wr.Timeseries, 1)
	ts := wr.Timeseries[0]
	assert.Equal(t, []prompb.Label{
		{Name: "__name__", Value: "legacy.gauge"},
		{Name: "k", Value: "v"},
	}, ts.Labels)
	require.Len(t, ts.Samples, 1)
	assert.InDelta(t, 9.5, ts.Samples[0].Value, 1e-9)
	assert.Equal(t, int64(1_700_000_000_001), ts.Samples[0].Timestamp)
	require.NoError(t, out.Close())
}

func TestPromRemoteWrite_EmptyBatchIsNoop(t *testing.T) {
	srv, cap := newRemoteWriteCapturingServer(t)
	out, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{
		Endpoint: srv.URL,
		AuthType: "none",
		Timeout:  2 * time.Second,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Write(nil))

	method, _, _, body := cap.snapshot()
	assert.Empty(t, method, "no HTTP request should be issued for an empty batch")
	assert.Nil(t, body)
	require.NoError(t, out.Close())
}

func TestPromRemoteWrite_NewRequiresEndpoint(t *testing.T) {
	_, err := exporter.NewPromRemoteWriteOutput(exporter.PromRemoteWriteConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint")
}

// rwLabelValue returns the value of the named label or "" if absent.
func rwLabelValue(labels []prompb.Label, name string) string {
	for _, l := range labels {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}
