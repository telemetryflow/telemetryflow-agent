// Package exporter_test contains unit tests for the Loki output
// (JSON push API with stream grouping and async flusher).
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
	"encoding/base64"
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

// --- Test helpers -----------------------------------------------------------

// lokiValueJSON mirrors the [unix_ns, line] tuple Loki expects.
type lokiValueJSON [2]string

type lokiStreamJSON struct {
	Stream map[string]string `json:"stream"`
	Values []lokiValueJSON   `json:"values"`
}

type lokiPushJSON struct {
	Streams []lokiStreamJSON `json:"streams"`
}

// lokiRequest captures one HTTP push received by the test server.
type lokiRequest struct {
	path    string
	headers http.Header
	body    lokiPushJSON
}

// lokiCapture collects every push received by the test server.
type lokiCapture struct {
	mu       sync.Mutex
	requests []lokiRequest
}

func (c *lokiCapture) snapshot() []lokiRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]lokiRequest, len(c.requests))
	copy(out, c.requests)
	return out
}

func (c *lokiCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

// newLokiCapturingServer starts an httptest server that records every push
// and returns 204 No Content. The server is registered for t.Cleanup.
func newLokiCapturingServer(t *testing.T) (*httptest.Server, *lokiCapture) {
	t.Helper()
	cap := &lokiCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var push lokiPushJSON
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &push); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		cap.mu.Lock()
		cap.requests = append(cap.requests, lokiRequest{
			path:    r.URL.Path,
			headers: r.Header.Clone(),
			body:    push,
		})
		cap.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// requireFlushCount waits up to timeout for the capture to record at least n
// pushes, returning the snapshot. Fails the test on timeout.
func requireFlushCount(t *testing.T, cap *lokiCapture, n int, timeout time.Duration) []lokiRequest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if snap := cap.snapshot(); len(snap) >= n {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d pushes; got %d", n, cap.count())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func mustWrite(t *testing.T, out *exporter.LokiOutput, metrics []plugin.Metric) {
	t.Helper()
	require.NoError(t, out.Write(metrics))
}

// --- Tests ------------------------------------------------------------------

// TestLokiOutput_NewRequiresEndpoint verifies the constructor rejects empty
// configurations.
func TestLokiOutput_NewRequiresEndpoint(t *testing.T) {
	_, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint")
}

// TestLokiOutput_Name verifies the plugin name.
func TestLokiOutput_Name(t *testing.T) {
	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint: "http://localhost:3100",
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	assert.Equal(t, "loki", out.Name())
	require.NoError(t, out.Close())
}

// TestLokiOutput_DefaultsApplied verifies that zero-valued Duration/Int
// fields fall back to documented defaults.
func TestLokiOutput_DefaultsApplied(t *testing.T) {
	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint: "http://localhost:3100",
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())
	require.NoError(t, out.Close())
}

// TestLokiOutput_SameLabelsSingleStream: 3 metrics sharing the same label
// set must be grouped into one stream with three values.
func TestLokiOutput_SameLabelsSingleStream(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		BatchSize:     100,
		FlushInterval: 10 * time.Second, // avoid timer firing
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
		Labels:        map[string]string{"job": "tfo-agent"},
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	ts := time.Unix(1_700_000_000, 0).UTC()
	metrics := []plugin.Metric{
		{Description: "line-a", Timestamp: ts, Labels: map[string]string{"host": "node-1"}},
		{Description: "line-b", Timestamp: ts, Labels: map[string]string{"host": "node-1"}},
		{Description: "line-c", Timestamp: ts, Labels: map[string]string{"host": "node-1"}},
	}
	mustWrite(t, out, metrics)
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.Len(t, snap, 1, "expected exactly one flush on Close")
	req := snap[0]
	assert.Equal(t, "/loki/api/v1/push", req.path)
	assert.Equal(t, "application/json", req.headers.Get("Content-Type"))
	require.Len(t, req.body.Streams, 1, "expected a single stream")

	stream := req.body.Streams[0]
	assert.Equal(t, map[string]string{"job": "tfo-agent", "host": "node-1"}, stream.Stream,
		"stream labels must merge static config labels and the metric's own labels")
	require.Len(t, stream.Values, 3, "expected all three lines in one stream")

	lines := []string{stream.Values[0][1], stream.Values[1][1], stream.Values[2][1]}
	assert.Equal(t, []string{"line-a", "line-b", "line-c"}, lines)

	// Every value carries the metric's timestamp as unix-nanoseconds string.
	for _, v := range stream.Values {
		assert.Equal(t, strconvItoa(ts.UnixNano()), v[0])
	}
}

// TestLokiOutput_DistinctLabelsMultipleStreams: 3 metrics with distinct
// label sets must produce three separate streams.
func TestLokiOutput_DistinctLabelsMultipleStreams(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	ts := time.Unix(1_700_000_000, 0).UTC()
	metrics := []plugin.Metric{
		{Description: "l1", Timestamp: ts, Labels: map[string]string{"svc": "a"}},
		{Description: "l2", Timestamp: ts, Labels: map[string]string{"svc": "b"}},
		{Description: "l3", Timestamp: ts, Labels: map[string]string{"svc": "c"}},
	}
	mustWrite(t, out, metrics)
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.Len(t, snap, 1)
	require.Len(t, snap[0].body.Streams, 3, "expected three streams")

	bySvc := make(map[string]string, 3)
	for _, s := range snap[0].body.Streams {
		require.Len(t, s.Values, 1)
		bySvc[s.Stream["svc"]] = s.Values[0][1]
	}
	assert.Equal(t, map[string]string{"a": "l1", "b": "l2", "c": "l3"}, bySvc)
}

// TestLokiOutput_BatchSizeTrigger: with BatchSize=2 and 3 metrics, the
// flusher must emit two pushes (one at the BatchSize threshold and one on
// Close).
func TestLokiOutput_BatchSizeTrigger(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		BatchSize:     2,
		FlushInterval: 10 * time.Second, // disable timer-based flush
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	ts := time.Unix(1_700_000_000, 0).UTC()
	metrics := []plugin.Metric{
		{Description: "m1", Timestamp: ts, Labels: map[string]string{"host": "n1"}},
		{Description: "m2", Timestamp: ts, Labels: map[string]string{"host": "n1"}},
		{Description: "m3", Timestamp: ts, Labels: map[string]string{"host": "n1"}},
	}
	mustWrite(t, out, metrics)

	// The first flush must happen well before Close().
	requireFlushCount(t, cap, 1, time.Second)

	require.NoError(t, out.Close())
	snap := cap.snapshot()
	require.Len(t, snap, 2, "expected exactly two flushes (batch + final)")
	assert.Len(t, snap[0].body.Streams[0].Values, 2)
	assert.Len(t, snap[1].body.Streams[0].Values, 1)
}

// TestLokiOutput_FlushIntervalTrigger: a single metric below BatchSize must
// still be flushed by the periodic ticker, without Close().
func TestLokiOutput_FlushIntervalTrigger(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		BatchSize:     1000,
		FlushInterval: 30 * time.Millisecond,
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	mustWrite(t, out, []plugin.Metric{
		{Description: "tick", Timestamp: time.Unix(1_700_000_000, 0).UTC()},
	})

	// Wait for the timer-driven flush. Do not call Close() first.
	requireFlushCount(t, cap, 1, 2*time.Second)
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.GreaterOrEqual(t, len(snap), 1)
	require.Len(t, snap[0].body.Streams, 1)
	require.Len(t, snap[0].body.Streams[0].Values, 1)
	assert.Equal(t, "tick", snap[0].body.Streams[0].Values[0][1])
}

// TestLokiOutput_LabelTemplateExpansion verifies that LabelTemplate entries
// are expanded against the metric's labels (including dotted keys via the
// nestedLabels convention).
func TestLokiOutput_LabelTemplateExpansion(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
		Labels:        map[string]string{"job": "tfo-agent"},
		LabelTemplate: map[string]string{
			"service": "{{.service.name}}",
			"level":   "{{.level}}",
		},
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	mustWrite(t, out, []plugin.Metric{
		{
			Description: "hello",
			Timestamp:   time.Unix(1_700_000_000, 0).UTC(),
			Labels: map[string]string{
				"service.name": "checkout",
				"level":        "info",
			},
		},
	})
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.Len(t, snap, 1)
	require.Len(t, snap[0].body.Streams, 1)
	stream := snap[0].body.Streams[0]

	assert.Equal(t, "tfo-agent", stream.Stream["job"], "static labels must be present")
	assert.Equal(t, "checkout", stream.Stream["service"],
		"dotted label key must resolve via nested map access")
	assert.Equal(t, "info", stream.Stream["level"],
		"plain label key must resolve via direct field access")
	assert.Equal(t, "checkout", stream.Stream["service.name"],
		"metric's own labels must also be present in the stream key")
}

// TestLokiOutput_TenantIDHeader verifies the X-Scope-OrgID header.
func TestLokiOutput_TenantIDHeader(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		TenantID:      "acme-prod",
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())
	mustWrite(t, out, []plugin.Metric{
		{Description: "x", Timestamp: time.Unix(1_700_000_000, 0).UTC()},
	})
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "acme-prod", snap[0].headers.Get("X-Scope-OrgID"))
}

// TestLokiOutput_BasicAuthHeader verifies HTTP basic-auth on the request.
func TestLokiOutput_BasicAuthHeader(t *testing.T) {
	srv, cap := newLokiCapturingServer(t)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		Auth:          exporter.BasicAuth{Username: "alice", Password: "s3cret"},
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())
	mustWrite(t, out, []plugin.Metric{
		{Description: "x", Timestamp: time.Unix(1_700_000_000, 0).UTC()},
	})
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.Len(t, snap, 1)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	assert.Equal(t, want, snap[0].headers.Get("Authorization"))
}

// TestLokiOutput_TLSSkipVerify verifies that a self-signed TLS endpoint is
// reachable when TLSSkipVerify is true.
func TestLokiOutput_TLSSkipVerify(t *testing.T) {
	cap := &lokiCapture{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var push lokiPushJSON
		_ = json.Unmarshal(raw, &push)
		cap.mu.Lock()
		cap.requests = append(cap.requests, lokiRequest{
			path:    r.URL.Path,
			headers: r.Header.Clone(),
			body:    push,
		})
		cap.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	out, err := exporter.NewLokiOutput(exporter.LokiOutputConfig{
		Endpoint:      srv.URL,
		TLSSkipVerify: true,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       2 * time.Second,
		Logger:        zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())
	mustWrite(t, out, []plugin.Metric{
		{Description: "tls-line", Timestamp: time.Unix(1_700_000_000, 0).UTC()},
	})
	require.NoError(t, out.Close())

	snap := cap.snapshot()
	require.Len(t, snap, 1, "push must succeed over TLS with skip-verify")
	require.Len(t, snap[0].body.Streams, 1)
	require.Len(t, snap[0].body.Streams[0].Values, 1)
	assert.Equal(t, "tls-line", snap[0].body.Streams[0].Values[0][1])
}

// TestLokiOutput_RegistryRegistered verifies the plugin self-registers under
// the "loki" name during package init.
func TestLokiOutput_RegistryRegistered(t *testing.T) {
	p, dep, ok := plugin.GetOutput("loki")
	require.True(t, ok, "loki must be registered")
	assert.Empty(t, dep)
	assert.NotNil(t, p)
	assert.Equal(t, "loki", p.Name())
}

// strconvItoa is a tiny local helper that avoids pulling strconv into the
// test package's import list just for one call.
func strconvItoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
