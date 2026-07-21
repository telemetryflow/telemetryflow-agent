// Package remotewrite_test contains HTTP handler, decoder, and receiver
// lifecycle tests for the Prometheus Remote Write receiver.
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
package remotewrite_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	remotewrite "github.com/telemetryflow/telemetryflow-agent/internal/receiver/remotewrite"
)

const (
	contentType = "application/x-protobuf"
	rwVersion   = "0.1.0"
)

// encodeWriteRequest marshals a WriteRequest to protobuf then snappy-compresses it,
// producing a payload byte-for-byte identical to what Prometheus sends.
func encodeWriteRequest(t *testing.T, req *prompb.WriteRequest) []byte {
	t.Helper()
	raw, err := req.Marshal()
	require.NoError(t, err)
	return snappy.Encode(nil, raw)
}

func sampleWriteRequest() *prompb.WriteRequest {
	return &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{
			{
				Labels: []prompb.Label{
					{Name: "__name__", Value: "cpu_usage"},
					{Name: "instance", Value: "host-1"},
				},
				Samples: []prompb.Sample{
					{Value: 0.5, Timestamp: 1000},
					{Value: 0.7, Timestamp: 2000},
				},
			},
		},
	}
}

func newRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/write", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("X-Prometheus-Remote-Write-Version", rwVersion)
	return r
}

// --- Decoder ---

func TestDecodeWriteRequest_Valid(t *testing.T) {
	body := encodeWriteRequest(t, sampleWriteRequest())
	req, err := remotewrite.DecodeWriteRequestExported(body)
	require.NoError(t, err)
	require.Len(t, req.Timeseries, 1)
	assert.Len(t, req.Timeseries[0].Samples, 2)
}

func TestDecodeWriteRequest_BadSnappy(t *testing.T) {
	_, err := remotewrite.DecodeWriteRequestExported([]byte("not-snappy-data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "snappy decode")
}

func TestDecodeWriteRequest_BadProtobuf(t *testing.T) {
	// Valid snappy stream wrapping bytes that are not a valid WriteRequest.
	garbage := snappy.Encode(nil, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	_, err := remotewrite.DecodeWriteRequestExported(garbage)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protobuf unmarshal")
}

// --- Handler ---

func TestWriteHandler_Valid(t *testing.T) {
	out := make(chan []collector.Metric, 4)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, 5*time.Second)

	rec := httptest.NewRecorder()
	h(rec, newRequest(t, encodeWriteRequest(t, sampleWriteRequest())))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	select {
	case batch := <-out:
		assert.Len(t, batch, 2) // two samples -> two metrics
		assert.Equal(t, "cpu_usage", batch[0].Name)
	default:
		t.Fatal("expected metrics on channel")
	}
}

func TestWriteHandler_BadContentType(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, time.Second)
	r := newRequest(t, encodeWriteRequest(t, sampleWriteRequest()))
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported Content-Type")
}

func TestWriteHandler_BadVersion(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, time.Second)
	r := newRequest(t, encodeWriteRequest(t, sampleWriteRequest()))
	r.Header.Set("X-Prometheus-Remote-Write-Version", "9.9.9")
	rec := httptest.NewRecorder()
	h(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported X-Prometheus-Remote-Write-Version")
}

func TestWriteHandler_MalformedBody(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, time.Second)
	rec := httptest.NewRecorder()
	h(rec, newRequest(t, []byte("garbage-not-snappy")))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "decode error")
}

func TestWriteHandler_ReadBodyError(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, time.Second)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/write", errReader{})
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("X-Prometheus-Remote-Write-Version", rwVersion)
	rec := httptest.NewRecorder()
	h(rec, r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to read request body")
}

func TestWriteHandler_EmptySeries(t *testing.T) {
	// No timeseries -> no metrics pushed, still success (204).
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, time.Second)
	rec := httptest.NewRecorder()
	h(rec, newRequest(t, encodeWriteRequest(t, &prompb.WriteRequest{})))
	assert.Equal(t, http.StatusNoContent, rec.Code)
	select {
	case <-out:
		t.Fatal("expected no metrics for empty series")
	default:
	}
}

func TestWriteHandler_InvalidSeriesSkipped(t *testing.T) {
	// One series missing __name__ (skipped), one valid.
	req := &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{
			{
				Labels:  []prompb.Label{{Name: "env", Value: "prod"}},
				Samples: []prompb.Sample{{Value: 1, Timestamp: 1}},
			},
			{
				Labels:  []prompb.Label{{Name: "__name__", Value: "ok_metric"}},
				Samples: []prompb.Sample{{Value: 2, Timestamp: 2}},
			},
		},
	}
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, time.Second)
	rec := httptest.NewRecorder()
	h(rec, newRequest(t, encodeWriteRequest(t, req)))
	assert.Equal(t, http.StatusNoContent, rec.Code)
	batch := <-out
	require.Len(t, batch, 1)
	assert.Equal(t, "ok_metric", batch[0].Name)
}

func TestWriteHandler_BufferFull(t *testing.T) {
	out := make(chan []collector.Metric) // unbuffered, no reader -> full
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, 3*time.Second)
	rec := httptest.NewRecorder()
	h(rec, newRequest(t, encodeWriteRequest(t, sampleWriteRequest())))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "3", rec.Header().Get("Retry-After"))
}

func TestWriteHandler_BufferFull_RetryAfterFloor(t *testing.T) {
	out := make(chan []collector.Metric)
	// Sub-second flush interval -> Retry-After floors to 1.
	h := remotewrite.WriteHandlerExported(remotewrite.RemoteWriteReceiverConfig{}, out, 100*time.Millisecond)
	rec := httptest.NewRecorder()
	h(rec, newRequest(t, encodeWriteRequest(t, sampleWriteRequest())))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
}

// --- Basic auth ---

func authConfig() remotewrite.RemoteWriteReceiverConfig {
	return remotewrite.RemoteWriteReceiverConfig{
		BasicAuth: &remotewrite.BasicAuthConfig{Username: "user", Password: "pass"},
	}
}

func TestWriteHandler_BasicAuth_Success(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(authConfig(), out, time.Second)
	r := newRequest(t, encodeWriteRequest(t, sampleWriteRequest()))
	r.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	h(rec, r)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestWriteHandler_BasicAuth_WrongPassword(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(authConfig(), out, time.Second)
	r := newRequest(t, encodeWriteRequest(t, sampleWriteRequest()))
	r.SetBasicAuth("user", "wrong")
	rec := httptest.NewRecorder()
	h(rec, r)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
}

func TestWriteHandler_BasicAuth_Missing(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(authConfig(), out, time.Second)
	rec := httptest.NewRecorder()
	h(rec, newRequest(t, encodeWriteRequest(t, sampleWriteRequest())))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestWriteHandler_BasicAuth_ManualHeaderFallback(t *testing.T) {
	// r.BasicAuth() fails to parse but a manual "Basic " header is present & valid.
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(authConfig(), out, time.Second)
	r := newRequest(t, encodeWriteRequest(t, sampleWriteRequest()))
	creds := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	r.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()
	h(rec, r)
	// Note: net/http's r.BasicAuth parses this fine; either way must succeed.
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestWriteHandler_BasicAuth_MalformedBase64(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	h := remotewrite.WriteHandlerExported(authConfig(), out, time.Second)
	r := newRequest(t, encodeWriteRequest(t, sampleWriteRequest()))
	r.Header.Set("Authorization", "Basic !!!not-base64!!!")
	rec := httptest.NewRecorder()
	h(rec, r)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Receiver lifecycle ---

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestReceiver_Defaults(t *testing.T) {
	r := remotewrite.NewRemoteWriteReceiver(remotewrite.RemoteWriteReceiverConfig{}, zap.NewNop())
	assert.Equal(t, "remote_write_receiver", r.Name())
	assert.False(t, r.IsRunning())
}

func TestReceiver_StartStopCollect(t *testing.T) {
	cfg := remotewrite.RemoteWriteReceiverConfig{Port: freePort(t), BufferSize: 8}
	r := remotewrite.NewRemoteWriteReceiver(cfg, zap.NewNop())

	require.NoError(t, r.Start(context.Background()))
	assert.True(t, r.IsRunning())
	// Second Start is a no-op.
	require.NoError(t, r.Start(context.Background()))

	// Give the goroutine a moment to bind.
	time.Sleep(50 * time.Millisecond)

	// Post a valid payload over the live loopback server.
	url := "http://127.0.0.1:" + itoa(cfg.Port) + "/api/v1/write"
	httpReq, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(encodeWriteRequest(t, sampleWriteRequest()))))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", rwVersion)
	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	metrics, err := r.Collect(context.Background())
	require.NoError(t, err)
	assert.Len(t, metrics, 2)

	require.NoError(t, r.Stop())
	assert.False(t, r.IsRunning())
	// Second Stop is a no-op.
	require.NoError(t, r.Stop())
}

func TestReceiver_StartPortInUse(t *testing.T) {
	port := freePort(t)
	// Occupy the port so the receiver's ListenAndServe fails inside its goroutine.
	// Bind on all interfaces (":port") to conflict with the receiver's ":port" server.
	l, err := net.Listen("tcp", ":"+itoa(port))
	require.NoError(t, err)
	defer l.Close()

	r := remotewrite.NewRemoteWriteReceiver(remotewrite.RemoteWriteReceiverConfig{Port: port}, zap.NewNop())
	require.NoError(t, r.Start(context.Background()))
	// The serve goroutine should observe the bind error and flip running to false.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !r.IsRunning() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.False(t, r.IsRunning())
	_ = r.Stop()
}

func TestReceiver_CollectEmpty(t *testing.T) {
	cfg := remotewrite.RemoteWriteReceiverConfig{Port: freePort(t)}
	r := remotewrite.NewRemoteWriteReceiver(cfg, zap.NewNop())
	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()
	metrics, err := r.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// itoa avoids importing strconv purely for a small port conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// errReader always returns an error, exercising the io.ReadAll failure path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, assert.AnError }
