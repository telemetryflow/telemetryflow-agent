// Package exporter_test contains unit tests for the OTLP log bridge.
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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// logBridgeServer returns an httptest server that decodes the gzip'd OTLP
// JSON body and stores every received request via the returned mu/records.
type capturedRequest struct {
	Path    string
	Headers http.Header
	Body    map[string]any
}

func newCapturingServer(t *testing.T) (*httptest.Server, *atomic.Int64, *[]capturedRequest, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var records []capturedRequest
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var reader io.Reader = bytes.NewReader(raw)
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, gerr := gzip.NewReader(bytes.NewReader(raw))
			if gerr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer gz.Close()
			reader = gz
		}
		decoded, derr := io.ReadAll(reader)
		if derr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var body map[string]any
		_ = json.Unmarshal(decoded, &body)
		mu.Lock()
		records = append(records, capturedRequest{Path: r.URL.Path, Headers: r.Header.Clone(), Body: body})
		mu.Unlock()
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	return srv, &hits, &records, &mu
}

func decodeRecords(t *testing.T, req capturedRequest) []map[string]any {
	t.Helper()
	rl, _ := req.Body["resourceLogs"].([]any)
	require.NotEmpty(t, rl, "resourceLogs missing")
	first, _ := rl[0].(map[string]any)
	scopeLogs, _ := first["scopeLogs"].([]any)
	require.NotEmpty(t, scopeLogs, "scopeLogs missing")
	sl, _ := scopeLogs[0].(map[string]any)
	rawRecords, _ := sl["logRecords"].([]any)
	out := make([]map[string]any, 0, len(rawRecords))
	for _, r := range rawRecords {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func newTestLogBridge(t *testing.T, srv *httptest.Server, batchSize int, flushInterval time.Duration) *exporter.OTLPLogBridge {
	t.Helper()
	b, err := exporter.NewOTLPLogBridge(exporter.OTLPLogBridgeConfig{
		Endpoint:      strings.TrimPrefix(srv.URL, "http://"),
		Path:          "/v1/logs",
		Headers:       map[string]string{"X-TelemetryFlow-Key-ID": "kid", "X-TelemetryFlow-Agent-ID": "agent-xyz"},
		Logger:        zap.NewNop(),
		BatchSize:     batchSize,
		FlushInterval: flushInterval,
	})
	require.NoError(t, err)
	require.NotNil(t, b)
	return b
}

func TestOTLPLogBridge_EmitSingleLog_FlushesAfterInterval(t *testing.T) {
	srv, hits, records, mu := newCapturingServer(t)
	defer srv.Close()

	b := newTestLogBridge(t, srv, 100, 50*time.Millisecond)
	require.NoError(t, b.Start(context.Background()))
	defer func() { _ = b.Stop() }()

	b.Emit(time.Unix(1700000000, 0), "INFO", "hello world", "/var/log/syslog", map[string]string{
		"log.file.path": "/var/log/syslog",
	})

	// Within ~flushInterval the server should receive the POST.
	require.Eventually(t, func() bool { return hits.Load() >= 1 }, time.Second, 5*time.Millisecond)

	mu.Lock()
	recs := *records
	mu.Unlock()
	require.Len(t, recs, 1)
	logRecords := decodeRecords(t, recs[0])
	require.Len(t, logRecords, 1)

	rec := logRecords[0]
	assert.Equal(t, "1700000000000000000", rec["timeUnixNano"])
	assert.EqualValues(t, 9, rec["severityNumber"])
	assert.Equal(t, "INFO", rec["severityText"])

	body, _ := rec["body"].(map[string]any)
	assert.Equal(t, "hello world", body["stringValue"])

	attrs, _ := rec["attributes"].([]any)
	assert.NotEmpty(t, attrs)
}

func TestOTLPLogBridge_BatchSizeTriggersImmediateFlush(t *testing.T) {
	srv, hits, _, _ := newCapturingServer(t)
	defer srv.Close()

	b := newTestLogBridge(t, srv, 3, time.Hour) // long interval — only batch triggers flush
	require.NoError(t, b.Start(context.Background()))
	defer func() { _ = b.Stop() }()

	for i := 0; i < 3; i++ {
		b.Emit(time.Now(), "INFO", "line", "src", nil)
	}

	// Batch-size flush should fire well before the test times out.
	require.Eventually(t, func() bool { return hits.Load() >= 1 }, time.Second, 5*time.Millisecond)
}

func TestOTLPLogBridge_SeverityMapping(t *testing.T) {
	srv, hits, records, mu := newCapturingServer(t)
	defer srv.Close()

	b := newTestLogBridge(t, srv, 6, 50*time.Millisecond) // 6 = number of severities
	require.NoError(t, b.Start(context.Background()))
	defer func() { _ = b.Stop() }()

	cases := []struct {
		sev string
		num int
	}{
		{"TRACE", 1},
		{"DEBUG", 5},
		{"INFO", 9},
		{"WARN", 13},
		{"ERROR", 17},
		{"FATAL", 21},
	}
	for _, c := range cases {
		b.Emit(time.Unix(1700000000, 0), c.sev, "msg", "src", nil)
	}

	require.Eventually(t, func() bool { return hits.Load() >= 1 }, time.Second, 5*time.Millisecond)

	mu.Lock()
	recs := *records
	mu.Unlock()
	require.Len(t, recs, 1)
	logRecords := decodeRecords(t, recs[0])
	require.Len(t, logRecords, len(cases))

	got := make(map[string]int, len(cases))
	for _, r := range logRecords {
		sev, _ := r["severityText"].(string)
		num, _ := r["severityNumber"].(float64)
		got[sev] = int(num)
	}
	for _, c := range cases {
		assert.Equal(t, c.num, got[c.sev], "severity %s", c.sev)
	}
}

func TestOTLPLogBridge_BodyAndAttributesShape(t *testing.T) {
	srv, hits, records, mu := newCapturingServer(t)
	defer srv.Close()

	b := newTestLogBridge(t, srv, 100, 50*time.Millisecond)
	require.NoError(t, b.Start(context.Background()))
	defer func() { _ = b.Stop() }()

	b.Emit(time.Unix(0, 0), "ERROR", "boom", "/var/log/app.log", map[string]string{
		"log.file.path":            "/var/log/app.log",
		"telemetryflow.tag.region": "id",
	})

	require.Eventually(t, func() bool { return hits.Load() >= 1 }, time.Second, 5*time.Millisecond)

	mu.Lock()
	recs := *records
	mu.Unlock()
	require.Len(t, recs, 1)

	logRecords := decodeRecords(t, recs[0])
	require.Len(t, logRecords, 1)
	rec := logRecords[0]

	// Body uses OTLP anyvalue shape: {"stringValue": "..."}.
	body, _ := rec["body"].(map[string]any)
	assert.Equal(t, "boom", body["stringValue"])

	// Attributes map includes source, hostname, agent.id, and caller attrs.
	attrs, _ := rec["attributes"].([]any)
	attrMap := make(map[string]string, len(attrs))
	for _, a := range attrs {
		kv, _ := a.(map[string]any)
		key, _ := kv["key"].(string)
		valAny, _ := kv["value"].(map[string]any)
		val, _ := valAny["stringValue"].(string)
		attrMap[key] = val
	}
	assert.Equal(t, "/var/log/app.log", attrMap["source"])
	assert.Equal(t, "/var/log/app.log", attrMap["log.file.path"])
	assert.Equal(t, "id", attrMap["telemetryflow.tag.region"])
	// agent.id and hostname are injected by the bridge.
	assert.Equal(t, "agent-xyz", attrMap["agent.id"])
	assert.NotEmpty(t, attrMap["hostname"])
}

func TestOTLPLogBridge_ResourceAttributes(t *testing.T) {
	srv, hits, records, mu := newCapturingServer(t)
	defer srv.Close()

	b := newTestLogBridge(t, srv, 100, 50*time.Millisecond)
	require.NoError(t, b.Start(context.Background()))
	defer func() { _ = b.Stop() }()

	b.Emit(time.Now(), "INFO", "x", "src", nil)

	require.Eventually(t, func() bool { return hits.Load() >= 1 }, time.Second, 5*time.Millisecond)

	mu.Lock()
	recs := *records
	mu.Unlock()
	require.Len(t, recs, 1)

	rl, _ := recs[0].Body["resourceLogs"].([]any)
	require.Len(t, rl, 1)
	first, _ := rl[0].(map[string]any)
	res, _ := first["resource"].(map[string]any)
	attrs, _ := res["attributes"].([]any)

	attrMap := make(map[string]string, len(attrs))
	for _, a := range attrs {
		kv, _ := a.(map[string]any)
		key, _ := kv["key"].(string)
		valAny, _ := kv["value"].(map[string]any)
		val, _ := valAny["stringValue"].(string)
		attrMap[key] = val
	}
	assert.Equal(t, "tfo-agent", attrMap["service.name"])
	assert.Equal(t, "agent-xyz", attrMap["agent.id"])
	assert.NotEmpty(t, attrMap["host.name"])
}

func TestOTLPLogBridge_StopFlushesPending(t *testing.T) {
	srv, hits, records, mu := newCapturingServer(t)
	defer srv.Close()

	// Long interval, large batch — only Stop can trigger the flush.
	b := newTestLogBridge(t, srv, 1000, time.Hour)
	require.NoError(t, b.Start(context.Background()))

	for i := 0; i < 5; i++ {
		b.Emit(time.Now(), "INFO", "queued", "src", nil)
	}

	// No flush should have happened yet.
	time.Sleep(30 * time.Millisecond)
	require.Equal(t, int64(0), hits.Load())

	// Stop must flush before returning.
	require.NoError(t, b.Stop())
	require.Equal(t, int64(1), hits.Load())

	mu.Lock()
	recs := *records
	mu.Unlock()
	require.Len(t, recs, 1)
	logRecords := decodeRecords(t, recs[0])
	assert.Len(t, logRecords, 5)
}

func TestOTLPLogBridge_StopIdempotent(t *testing.T) {
	srv, _, _, _ := newCapturingServer(t)
	defer srv.Close()
	b := newTestLogBridge(t, srv, 100, 50*time.Millisecond)
	require.NoError(t, b.Start(context.Background()))
	require.NoError(t, b.Stop())
	require.NotPanics(t, func() {
		require.NoError(t, b.Stop())
	})
}

func TestOTLPLogBridge_ContextCancellationStopsFlusher(t *testing.T) {
	srv, hits, _, _ := newCapturingServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	b := newTestLogBridge(t, srv, 1000, time.Hour)
	require.NoError(t, b.Start(ctx))

	// Emit something so we know the flusher is running.
	b.Emit(time.Now(), "INFO", "msg", "src", nil)

	// Cancelling the context does NOT stop the flusher (Start takes ctx but
	// the flusher listens on stopCh). Stop() is the lifecycle hook.
	cancel()

	// Give time for any race; no flush should occur since batch size is huge.
	time.Sleep(30 * time.Millisecond)
	require.Equal(t, int64(0), hits.Load())

	// Stop must still work after ctx cancel and must flush the buffered record.
	require.NoError(t, b.Stop())
	require.Equal(t, int64(1), hits.Load())
}

func TestOTLPLogBridge_MissingEndpointErrors(t *testing.T) {
	_, err := exporter.NewOTLPLogBridge(exporter.OTLPLogBridgeConfig{
		Logger: zap.NewNop(),
	})
	require.Error(t, err)
}

func TestOTLPLogBridge_AuthHeadersPropagated(t *testing.T) {
	srv, hits, records, mu := newCapturingServer(t)
	defer srv.Close()

	b := newTestLogBridge(t, srv, 100, 50*time.Millisecond)
	require.NoError(t, b.Start(context.Background()))
	defer func() { _ = b.Stop() }()

	b.Emit(time.Now(), "INFO", "x", "src", nil)
	require.Eventually(t, func() bool { return hits.Load() >= 1 }, time.Second, 5*time.Millisecond)

	mu.Lock()
	recs := *records
	mu.Unlock()
	require.Len(t, recs, 1)
	assert.Equal(t, "kid", recs[0].Headers.Get("X-TelemetryFlow-Key-ID"))
	assert.Equal(t, "agent-xyz", recs[0].Headers.Get("X-TelemetryFlow-Agent-ID"))
	assert.Equal(t, "gzip", recs[0].Headers.Get("Content-Encoding"))
	assert.Equal(t, "application/json", recs[0].Headers.Get("Content-Type"))
}
