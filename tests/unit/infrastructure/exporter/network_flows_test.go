// Package exporter_test contains unit tests for the network flow exporter.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package exporter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func sampleFlow() exporter.NetworkFlowRecord {
	return exporter.NetworkFlowRecord{
		Timestamp:       time.Now().Format(time.RFC3339),
		SourceNamespace: "default",
		SourcePod:       "pod-a",
		TargetNamespace: "default",
		TargetPod:       "pod-b",
		Protocol:        "TCP",
		Verdict:         "FORWARDED",
	}
}

func TestNetworkFlowExporter_Defaults(t *testing.T) {
	e := exporter.NewNetworkFlowExporter(exporter.NetworkFlowExporterConfig{})
	require.NotNil(t, e)
	// RecordMany with nothing is a no-op.
	e.RecordMany(nil)
}

func TestNetworkFlowExporter_FlushOnStop(t *testing.T) {
	var count int64
	var lastBatch exporter.NetworkFlowBatch
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2/monitoring/network-map/k8s/flows", r.URL.Path)
		assert.Equal(t, "keyid", r.Header.Get("X-TelemetryFlow-Key-ID"))
		assert.Equal(t, "secret", r.Header.Get("X-TelemetryFlow-Key-Secret"))
		var b exporter.NetworkFlowBatch
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		lastBatch = b
		mu.Unlock()
		atomic.AddInt64(&count, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := exporter.NewNetworkFlowExporter(exporter.NetworkFlowExporterConfig{
		ClusterID:     "cluster-1",
		Endpoint:      srv.URL,
		APIKeyID:      "keyid",
		APIKeySecret:  "secret",
		FlushInterval: 20 * time.Millisecond,
		MaxBatchSize:  100,
		Logger:        zap.NewNop(),
	})

	e.Start()
	// Starting again is a no-op.
	e.Start()
	e.Record(sampleFlow())
	e.RecordMany([]exporter.NetworkFlowRecord{sampleFlow(), sampleFlow()})

	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&count) >= 1
	}, time.Second, 5*time.Millisecond)

	e.Stop()
	// Stopping again is a no-op.
	e.Stop()

	mu.Lock()
	assert.Equal(t, "cluster-1", lastBatch.ClusterID)
	mu.Unlock()
}

func TestNetworkFlowExporter_FlushOnBatchSize(t *testing.T) {
	var count int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := exporter.NewNetworkFlowExporter(exporter.NetworkFlowExporterConfig{
		ClusterID:    "cluster-1",
		Endpoint:     srv.URL,
		MaxBatchSize: 2,
		Logger:       zap.NewNop(),
	})
	// Record triggers async flush once buffer >= MaxBatchSize.
	e.Record(sampleFlow())
	e.Record(sampleFlow())
	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&count) >= 1
	}, time.Second, 5*time.Millisecond)

	// RecordMany also triggers flush when it fills the batch.
	e.RecordMany([]exporter.NetworkFlowRecord{sampleFlow(), sampleFlow()})
	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&count) >= 2
	}, time.Second, 5*time.Millisecond)
}

func TestNetworkFlowExporter_NonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := exporter.NewNetworkFlowExporter(exporter.NetworkFlowExporterConfig{
		ClusterID:    "cluster-1",
		Endpoint:     srv.URL,
		MaxBatchSize: 100,
		Logger:       zap.NewNop(),
	})
	e.Record(sampleFlow())
	e.Stop() // final flush hits the 500 branch
}

func TestNetworkFlowExporter_RequestError(t *testing.T) {
	// Point at an unreachable endpoint so client.Do fails.
	e := exporter.NewNetworkFlowExporter(exporter.NetworkFlowExporterConfig{
		ClusterID:    "cluster-1",
		Endpoint:     "http://127.0.0.1:1", // connection refused
		MaxBatchSize: 100,
		Logger:       zap.NewNop(),
	})
	e.Record(sampleFlow())
	e.Stop() // final flush hits the request-error branch
}

func TestNetworkFlowExporter_DisabledWithoutClusterID(t *testing.T) {
	e := exporter.NewNetworkFlowExporter(exporter.NetworkFlowExporterConfig{
		Endpoint: "http://example.com",
		Logger:   zap.NewNop(),
	})
	e.Start() // logs warning and returns without starting loop
	// No flow recorded -> Stop's final flush is a no-op (empty buffer).
	e.Stop()
}
