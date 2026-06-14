// Package qan_test contains unit tests for the QAN exporter.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

package qan_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// ---------------------------------------------------------------------------
// Tests: QANExporter
// ---------------------------------------------------------------------------

func TestQANExporter_CollectAndFlush(t *testing.T) {
	var receivedBuckets int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/qan/collect" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		var req qan.CollectRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("failed to unmarshal: %v", err)
		}
		atomic.AddInt32(&receivedBuckets, int32(len(req.Buckets)))

		resp := qan.CollectResponse{Accepted: len(req.Buckets), Rejected: 0}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := qan.QANConfig{
		Enabled:          true,
		Endpoint:         server.URL,
		BatchSize:        10,
		FlushInterval:    100 * time.Millisecond,
		Timeout:          5 * time.Second,
		MaxRetryAttempts: 1,
	}

	exp := qan.NewQANExporter(cfg, "test-agent-id", zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = exp.Start(ctx)
	defer func() { _ = exp.Stop() }()

	buckets := []qan.QANMetricsBucket{
		{QueryID: "q1", AgentType: qan.AgentTypePostgreSQLPgStatements, NumQueries: 10},
		{QueryID: "q2", AgentType: qan.AgentTypePostgreSQLPgStatements, NumQueries: 5},
	}

	if err := exp.Collect(ctx, buckets); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Manual flush
	if err := exp.Flush(ctx); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if got := atomic.LoadInt32(&receivedBuckets); got != 2 {
		t.Fatalf("expected 2 received buckets, got %d", got)
	}
}

func TestQANExporter_BatchSizeAutoFlush(t *testing.T) {
	var flushes int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&flushes, 1)
		resp := qan.CollectResponse{Accepted: 5}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := qan.QANConfig{
		Enabled:          true,
		Endpoint:         server.URL,
		BatchSize:        5,
		FlushInterval:    10 * time.Second, // long interval — only auto-flush triggers
		Timeout:          5 * time.Second,
		MaxRetryAttempts: 1,
	}

	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = exp.Start(ctx)
	defer func() { _ = exp.Stop() }()

	buckets := make([]qan.QANMetricsBucket, 5)
	for i := range buckets {
		buckets[i] = qan.QANMetricsBucket{QueryID: "q"}
	}

	// This should trigger an auto-flush because len(buckets) >= BatchSize
	if err := exp.Collect(ctx, buckets); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if got := atomic.LoadInt32(&flushes); got != 1 {
		t.Fatalf("expected 1 auto-flush, got %d", got)
	}
}

func TestQANExporter_EmptyCollect(t *testing.T) {
	exp := qan.NewQANExporter(qan.QANConfig{
		Enabled:   true,
		Endpoint:  "http://localhost:9999",
		BatchSize: 10,
	}, "agent-1", zap.NewNop())

	if err := exp.Collect(context.Background(), nil); err != nil {
		t.Fatalf("Collect with nil should not error: %v", err)
	}
	if err := exp.Collect(context.Background(), []qan.QANMetricsBucket{}); err != nil {
		t.Fatalf("Collect with empty slice should not error: %v", err)
	}
}

func TestQANExporter_FlushEmptyBuffer(t *testing.T) {
	exp := qan.NewQANExporter(qan.QANConfig{
		Enabled:   true,
		Endpoint:  "http://localhost:9999",
		BatchSize: 10,
	}, "agent-1", zap.NewNop())

	if err := exp.Flush(context.Background()); err != nil {
		t.Fatalf("Flush with empty buffer should not error: %v", err)
	}
}

func TestQANExporter_NoEndpointDropsBatch(t *testing.T) {
	cfg := qan.QANConfig{
		Enabled:   true,
		Endpoint:  "", // no endpoint
		BatchSize: 10,
	}
	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	buckets := []qan.QANMetricsBucket{{QueryID: "q1"}}
	if err := exp.Collect(context.Background(), buckets); err != nil {
		t.Fatalf("Collect should not error even without endpoint: %v", err)
	}

	// Flush should silently drop
	if err := exp.Flush(context.Background()); err != nil {
		t.Fatalf("Flush should not error without endpoint: %v", err)
	}
}

func TestQANExporter_RetryOnFailure(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp := qan.CollectResponse{Accepted: 1}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := qan.QANConfig{
		Enabled:          true,
		Endpoint:         server.URL,
		BatchSize:        10,
		FlushInterval:    10 * time.Second,
		Timeout:          5 * time.Second,
		MaxRetryAttempts: 5,
	}

	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	buckets := []qan.QANMetricsBucket{{QueryID: "q1"}}
	if err := exp.Collect(context.Background(), buckets); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if err := exp.Flush(context.Background()); err != nil {
		t.Fatalf("Flush should eventually succeed via retry: %v", err)
	}

	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestQANExporter_RetryExhausted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := qan.QANConfig{
		Enabled:          true,
		Endpoint:         server.URL,
		BatchSize:        10,
		FlushInterval:    10 * time.Second,
		Timeout:          5 * time.Second,
		MaxRetryAttempts: 2,
	}

	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	buckets := []qan.QANMetricsBucket{{QueryID: "q1"}}
	_ = exp.Collect(context.Background(), buckets)

	err := exp.Flush(context.Background())
	if err == nil {
		t.Fatal("Flush should error when retries exhausted")
	}
}

func TestQANExporter_AuthHeaders(t *testing.T) {
	var seenKeyID, seenKeySecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKeyID = r.Header.Get("X-API-Key-ID")
		seenKeySecret = r.Header.Get("X-API-Key-Secret")
		resp := qan.CollectResponse{Accepted: 1}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := qan.QANConfig{
		Enabled:          true,
		Endpoint:         server.URL,
		APIKeyID:         "tfk_test123",
		APIKeySecret:     "tfs_secret456",
		BatchSize:        10,
		FlushInterval:    10 * time.Second,
		Timeout:          5 * time.Second,
		MaxRetryAttempts: 1,
	}

	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	_ = exp.Collect(context.Background(), []qan.QANMetricsBucket{{QueryID: "q1"}})
	_ = exp.Flush(context.Background())

	if seenKeyID != "tfk_test123" {
		t.Fatalf("expected API key ID header 'tfk_test123', got '%s'", seenKeyID)
	}
	if seenKeySecret != "tfs_secret456" {
		t.Fatalf("expected API key secret header 'tfs_secret456', got '%s'", seenKeySecret)
	}
}

func TestQANExporter_StartStop(t *testing.T) {
	cfg := qan.QANConfig{
		Enabled:       true,
		Endpoint:      "http://localhost:9999",
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
		Timeout:       5 * time.Second,
	}

	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := exp.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Double start is OK (second goroutine is fine)
	_ = exp.Start(ctx)

	if err := exp.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestQANExporter_PeriodicFlush(t *testing.T) {
	var flushes int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&flushes, 1)
		resp := qan.CollectResponse{Accepted: 1}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := qan.QANConfig{
		Enabled:          true,
		Endpoint:         server.URL,
		BatchSize:        100, // large batch — only periodic flush triggers
		FlushInterval:    50 * time.Millisecond,
		Timeout:          5 * time.Second,
		MaxRetryAttempts: 1,
	}

	exp := qan.NewQANExporter(cfg, "agent-1", zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = exp.Start(ctx)

	// Add a bucket — should be flushed by the periodic timer
	_ = exp.Collect(ctx, []qan.QANMetricsBucket{{QueryID: "q1"}})

	time.Sleep(250 * time.Millisecond)

	cancel()
	_ = exp.Stop()

	if got := atomic.LoadInt32(&flushes); got < 1 {
		t.Fatalf("expected at least 1 periodic flush, got %d", got)
	}
}

func TestQANExporter_DefaultConfig(t *testing.T) {
	// Test that zero-value config gets defaults applied
	exp := qan.NewQANExporter(qan.QANConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9999",
	}, "agent-1", nil) // nil logger should be handled

	if exp == nil {
		t.Fatal("expected non-nil exporter")
	}

	// Verify it can start/stop without error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := exp.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	_ = exp.Stop()
}
