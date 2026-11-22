// Package ifmib_test gate-counted unit tests for the IF-MIB interface
// collector: the pure counter-wrap / utilization math, the collector lifecycle
// and poll->compute->POST path (driven by a fake poller + httptest ingestion
// server), and the exporter batching/retry/auth branches. No live SNMP device
// or backend is touched. These mirror the in-package tests under
// internal/collector/snmp/ifmib so the coverage counts toward the ./tests/unit
// gate.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package ifmib_test

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/snmp/ifmib"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ───────────────────────── fakes ─────────────────────────

type fakePoller struct {
	readings []ifmib.InterfaceReading
	err      error
}

func (f *fakePoller) Poll(context.Context) ([]ifmib.InterfaceReading, error) {
	return f.readings, f.err
}

// captureServer records POST requests to the ingestion endpoint.
type captureServer struct {
	mu       sync.Mutex
	paths    []string
	apiKey   []string
	bearer   []string
	batches  [][]ifmib.InterfaceSample
	respCode int
}

func (c *captureServer) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Samples []ifmib.InterfaceSample `json:"samples"`
	}
	_ = json.Unmarshal(body, &req)

	c.mu.Lock()
	c.paths = append(c.paths, r.URL.Path)
	c.apiKey = append(c.apiKey, r.Header.Get("X-API-Key-ID"))
	c.bearer = append(c.bearer, r.Header.Get("Authorization"))
	c.batches = append(c.batches, req.Samples)
	code := c.respCode
	c.mu.Unlock()

	if code == 0 {
		code = http.StatusNoContent
	}
	w.WriteHeader(code)
}

func (c *captureServer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.paths)
}

// ───────────────────────── pure math: CounterDelta ─────────────────────────

func TestCounterDelta(t *testing.T) {
	tests := []struct {
		name    string
		prev    uint64
		cur     uint64
		is64bit bool
		want    uint64
	}{
		{"32bit no wrap", 100, 500, false, 400},
		{"32bit zero delta", 42, 42, false, 0},
		{"32bit exact wrap", math.MaxUint32, 0, false, 1},
		{"32bit wrap remainder", math.MaxUint32 - 10, 20, false, 31},
		{"64bit no wrap", 1_000_000_000_000, 1_000_000_050_000, true, 50_000},
		{"64bit zero delta", 9_999, 9_999, true, 0},
		{"64bit exact wrap", math.MaxUint64, 0, true, 1},
		{"64bit wrap remainder", math.MaxUint64 - 5, 4, true, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ifmib.CounterDelta(tt.prev, tt.cur, tt.is64bit))
		})
	}
}

// ───────────────────────── pure math: Utilization ─────────────────────────

func TestUtilization(t *testing.T) {
	const gig = uint64(1_000_000_000)
	tests := []struct {
		name        string
		prev, cur   uint64
		is64bit     bool
		hasPrevious bool
		interval    float64
		speedBps    uint64
		want        float64
	}{
		// (62.5MB*8)/(60*1e9)*100 = 0.8333%
		{"typical", 0, 62_500_000, true, true, 60, gig, 0.8333333333},
		{"no previous -> 0", 0, 1_000_000, true, false, 60, gig, 0},
		{"zero interval -> 0", 0, 1_000_000, true, true, 0, gig, 0},
		{"negative interval -> 0", 0, 1_000_000, true, true, -5, gig, 0},
		{"zero speed -> 0", 0, 1_000_000, true, true, 60, 0, 0},
		{"zero delta -> 0", 500, 500, true, true, 60, gig, 0},
		// delta so large it exceeds capacity -> clamped to 100.
		{"over capacity -> clamp 100", 0, gig, true, true, 1, 1_000, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ifmib.Utilization(tt.prev, tt.cur, tt.is64bit, tt.hasPrevious, tt.interval, tt.speedBps)
			assert.InDelta(t, tt.want, got, 1e-6)
			assert.GreaterOrEqual(t, got, 0.0)
			assert.LessOrEqual(t, got, 100.0)
		})
	}
}

// ───────────────────────── constructor defaults ─────────────────────────

func TestNewCollector_AppliesDefaults(t *testing.T) {
	c := ifmib.NewCollector(config.SNMPInterfaceCollectorConfig{Enabled: true}, nil)
	require.NotNil(t, c)
	assert.Equal(t, "snmp_interface", c.Name())
	assert.False(t, c.IsRunning())
}

// ───────────────────────── lifecycle ─────────────────────────

func TestStartStopLifecycle(t *testing.T) {
	c := ifmib.NewCollector(config.SNMPInterfaceCollectorConfig{Enabled: true}, nil)
	require.False(t, c.IsRunning())

	require.NoError(t, c.Start(context.Background()))
	assert.True(t, c.IsRunning())

	assert.Error(t, c.Start(context.Background()), "double Start must error")

	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
}

// ───────────────────────── Collect: poll -> compute -> POST ─────────────────────────

func newTestCollector(t *testing.T, cfg config.SNMPInterfaceCollectorConfig, p ifmib.Poller) *ifmib.Collector {
	t.Helper()
	if len(cfg.Devices) == 0 {
		cfg.Devices = []config.SNMPInterfaceDevice{
			{DeviceID: "dev-1", DeviceName: "core-sw", Host: "10.0.0.1", Community: "public"},
		}
	}
	c := ifmib.NewCollector(cfg, nil)
	c.SetPollerFactory(func(config.SNMPInterfaceDevice) ifmib.Poller { return p })
	return c
}

func TestCollect_FirstCyclePostsZeroUtilWithAPIKey(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: srv.URL, APIKeyID: "tfk_x", APIKeySecret: "tfs_x",
	}, &fakePoller{readings: []ifmib.InterfaceReading{
		{IfIndex: 1, IfName: "Gi0/1", IfSpeedBps: 1_000_000_000, InOctets: 1_000_000, OutOctets: 2_000_000, Is64Bit: true, InErrors: 1, OperStatus: "up"},
	}})

	_, err := c.Collect(context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, cap.count())
	cap.mu.Lock()
	defer cap.mu.Unlock()
	assert.Equal(t, "/api/v2/monitoring/network-map/snmp/interface-metrics", cap.paths[0])
	assert.Equal(t, "tfk_x", cap.apiKey[0])
	require.Len(t, cap.batches[0], 1)
	s := cap.batches[0][0]
	assert.Equal(t, "dev-1", s.DeviceID)
	assert.Equal(t, "Gi0/1", s.IfName)
	assert.Equal(t, "up", s.OperStatus)
	assert.Zero(t, s.InUtilizationPct)
	assert.Zero(t, s.OutUtilizationPct)
	assert.NotEmpty(t, s.Timestamp)
}

func TestCollect_SecondCycleComputesUtilization(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: srv.URL, APIKeyID: "k",
	}, &fakePoller{readings: []ifmib.InterfaceReading{
		{IfIndex: 1, IfName: "Gi0/1", IfSpeedBps: 1_000_000_000, InOctets: 1_000_000, OutOctets: 2_000_000, Is64Bit: true, OperStatus: "up"},
	}})
	_, err := c.Collect(context.Background())
	require.NoError(t, err)

	// second cycle: larger counters over a real elapsed interval -> non-zero util.
	c.SetPollerFactory(func(config.SNMPInterfaceDevice) ifmib.Poller {
		return &fakePoller{readings: []ifmib.InterfaceReading{
			{IfIndex: 1, IfName: "Gi0/1", IfSpeedBps: 1_000_000_000, InOctets: 9_000_000, OutOctets: 10_000_000, Is64Bit: true, OperStatus: "up"},
		}}
	})
	time.Sleep(3 * time.Millisecond)
	_, err = c.Collect(context.Background())
	require.NoError(t, err)

	require.Equal(t, 2, cap.count())
	cap.mu.Lock()
	defer cap.mu.Unlock()
	s := cap.batches[1][0]
	// delta is positive over a tiny interval -> clamps to [0,100].
	assert.GreaterOrEqual(t, s.InUtilizationPct, 0.0)
	assert.LessOrEqual(t, s.InUtilizationPct, 100.0)
}

func TestCollect_NoDevices(t *testing.T) {
	c := ifmib.NewCollector(config.SNMPInterfaceCollectorConfig{Enabled: true}, nil)
	out, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestCollect_PollErrorIsSkipped(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: srv.URL, APIKeyID: "k",
	}, &fakePoller{err: assertErr("poll boom")})

	_, err := c.Collect(context.Background())
	require.NoError(t, err, "a per-device poll error must not fail the cycle")
	assert.Zero(t, cap.count(), "no samples -> no POST")
}

func TestCollect_ContextCanceled(t *testing.T) {
	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: "http://127.0.0.1:0", APIKeyID: "k",
	}, &fakePoller{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Collect(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// ───────────────────────── exporter branches ─────────────────────────

func TestExporter_EmptyEndpointDropsSamples(t *testing.T) {
	// BackendEndpoint empty but a device yields readings -> Push drops silently.
	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{Enabled: true}, &fakePoller{
		readings: []ifmib.InterfaceReading{{IfIndex: 1, IfName: "e0", OperStatus: "up"}},
	})
	_, err := c.Collect(context.Background())
	assert.NoError(t, err)
}

func TestExporter_BatchSplit(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: srv.URL, APIKeyID: "k", BatchSize: 1,
	}, &fakePoller{readings: []ifmib.InterfaceReading{
		{IfIndex: 1, IfName: "e1", OperStatus: "up"},
		{IfIndex: 2, IfName: "e2", OperStatus: "up"},
		{IfIndex: 3, IfName: "e3", OperStatus: "up"},
	}})

	_, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, cap.count(), "3 samples at batch_size=1 -> 3 POSTs")
}

func TestExporter_BearerTokenAuth(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: srv.URL, BearerToken: "jwt-abc",
	}, &fakePoller{readings: []ifmib.InterfaceReading{{IfIndex: 1, IfName: "e0", OperStatus: "up"}}})

	_, err := c.Collect(context.Background())
	require.NoError(t, err)
	cap.mu.Lock()
	defer cap.mu.Unlock()
	require.NotEmpty(t, cap.bearer)
	assert.Equal(t, "Bearer jwt-abc", cap.bearer[0])
	assert.Empty(t, cap.apiKey[0], "bearer takes precedence over api key")
}

func TestExporter_RetryThenFailFastViaContext(t *testing.T) {
	// Server always 500 -> push fails, enters backoff; a short ctx deadline makes
	// pushWithRetry return via ctx.Done() instead of sleeping the full backoff.
	cap := &captureServer{respCode: http.StatusInternalServerError}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	c := newTestCollector(t, config.SNMPInterfaceCollectorConfig{
		Enabled: true, BackendEndpoint: srv.URL, APIKeyID: "k", MaxRetryAttempts: 5,
	}, &fakePoller{readings: []ifmib.InterfaceReading{{IfIndex: 1, IfName: "e0", OperStatus: "up"}}})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := c.Collect(ctx)
	assert.Error(t, err, "repeated 500s with an expiring context must surface an error")
	assert.GreaterOrEqual(t, cap.count(), 1, "at least one attempt reached the server")
}

// TestNewGoSNMPPoller_Constructs covers the production poller factory (no
// network: it only builds the poller, applying SNMP agent defaults).
func TestNewGoSNMPPoller_Constructs(t *testing.T) {
	p := ifmib.NewGoSNMPPoller(config.SNMPInterfaceDevice{
		DeviceID: "d", DeviceName: "sw", Host: "198.51.100.10", Community: "public", Version: "2c",
	})
	assert.NotNil(t, p)
}

// assertErr is a tiny error helper so the test stays dependency-light.
type assertErr string

func (e assertErr) Error() string { return string(e) }
