// Package rds_postgresql_test contains unit tests for the RDS PostgreSQL reporter.
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

package rds_postgresql_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
)

func samplePayload() *postgresql.AgentMetricsPayload {
	return &postgresql.AgentMetricsPayload{
		InstanceID: "db-prod",
		Region:     "us-east-1",
		Timestamp:  time.Now().Unix(),
		Metrics: []postgresql.MetricEntry{
			{Name: "db.postgresql.connections.total", Type: "gauge", Value: 42},
		},
	}
}

func TestReporter_NoEndpointIsNoOp(t *testing.T) {
	r := postgresql.NewRDSPostgresReporter("", "", "", zap.NewNop())
	if err := r.Submit(context.Background(), samplePayload()); err != nil {
		t.Errorf("Submit with empty endpoint should be a no-op, got %v", err)
	}
}

func TestReporter_NilPayloadIsNoOp(t *testing.T) {
	r := postgresql.NewRDSPostgresReporter("http://example.invalid", "", "", zap.NewNop())
	if err := r.Submit(context.Background(), nil); err != nil {
		t.Errorf("nil payload should be a no-op: %v", err)
	}
	empty := &postgresql.AgentMetricsPayload{InstanceID: "x"}
	if err := r.Submit(context.Background(), empty); err != nil {
		t.Errorf("empty metrics should be a no-op: %v", err)
	}
}

func TestReporter_SubmitSuccess(t *testing.T) {
	var gotPath, keyID, keySecret, encoding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotPath = req.URL.Path
		keyID = req.Header.Get("X-API-Key-ID")
		keySecret = req.Header.Get("X-API-Key-Secret")
		encoding = req.Header.Get("Content-Encoding")

		// Body must be valid gzip-compressed JSON.
		gr, err := gzip.NewReader(req.Body)
		if err != nil {
			t.Errorf("gzip reader: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = gr.Close() }()
		raw, _ := io.ReadAll(gr)
		var decoded postgresql.AgentMetricsPayload
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Errorf("payload unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := postgresql.NewRDSPostgresReporter(srv.URL, "key-id", "key-secret", zap.NewNop())
	if err := r.Submit(context.Background(), samplePayload()); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotPath != "/api/v2/db-monitoring/aws-rds-postgresql/instances/db-prod/agent-metrics" {
		t.Errorf("unexpected path: %s", gotPath)
	}
	if keyID != "key-id" || keySecret != "key-secret" {
		t.Errorf("auth headers not set: id=%q secret=%q", keyID, keySecret)
	}
	if encoding != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", encoding)
	}
}

func TestReporter_ClientErrorNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	r := postgresql.NewRDSPostgresReporter(srv.URL, "", "", zap.NewNop())
	err := r.Submit(context.Background(), samplePayload())
	if err == nil {
		t.Fatal("expected error for 4xx response")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("4xx should not be retried, got %d calls", got)
	}
}

func TestReporter_ServerErrorRetriesThenFails(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Keep backoff delays tiny by cancelling context quickly is not ideal;
	// instead rely on the default reporter but assert retries were attempted.
	r := postgresql.NewRDSPostgresReporter(srv.URL, "", "", zap.NewNop())

	// Cancel after enough time for at least the first retry, bounding test time.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	err := r.Submit(ctx, samplePayload())
	if err == nil {
		t.Fatal("expected error after exhausting retries or context cancel")
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Errorf("5xx should be retried at least once, got %d calls", got)
	}
}

func TestReporter_ConnectionErrorRetries(t *testing.T) {
	// Point at a closed port so doPost returns a transport error.
	r := postgresql.NewRDSPostgresReporter("http://127.0.0.1:1", "", "", zap.NewNop())
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := r.Submit(ctx, samplePayload()); err == nil {
		t.Error("expected error when endpoint is unreachable")
	}
}
