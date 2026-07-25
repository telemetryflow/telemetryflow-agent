// Package exporter: OTLPLogBridge forwards log records to an OTLP/HTTP
// logs endpoint. Mirrors OTLPMetricBridge but targets the logs signal.
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

package exporter

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// OTLPLogBridgeConfig holds configuration for creating an OTLPLogBridge.
type OTLPLogBridgeConfig struct {
	Endpoint      string // e.g. "api.telemetryflow.id"
	Path          string // e.g. "/v1/logs"
	TLSEnabled    bool
	TLSSkipVerify bool
	Headers       map[string]string // X-TelemetryFlow-Key-ID, X-TelemetryFlow-Agent-ID, etc.
	Logger        *zap.Logger
	BatchSize     int           // default 100
	FlushInterval time.Duration // default 5s
	Timeout       time.Duration // per-request timeout, default 10s
}

// OTLPLogBridge forwards log records to an OTLP/HTTP logs endpoint.
// It batches records up to BatchSize or until FlushInterval elapses,
// whichever comes first. The callback signature matches
// logcollector.SetLogCallback so the agent can wire it directly.
type OTLPLogBridge struct {
	cfg     OTLPLogBridgeConfig
	log     *zap.Logger
	client  *http.Client
	url     string
	headers map[string]string

	hostname string
	agentID  string

	mu       sync.Mutex
	pending  []logRecord
	flushNow chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}

	wg sync.WaitGroup
}

// logRecord is the JSON-serialisable form for one OTLP HTTP log record.
type logRecord struct {
	TimeUnixNano   string   `json:"timeUnixNano"`
	SeverityNumber int      `json:"severityNumber,omitempty"`
	SeverityText   string   `json:"severityText,omitempty"`
	Body           otlpAny  `json:"body"`
	Attributes     []otlpKV `json:"attributes,omitempty"`
	TraceId        string   `json:"traceId,omitempty"`
	SpanId         string   `json:"spanId,omitempty"`
}

// otlpAny is a typed OTLP anyvalue. We only need the string variant for
// the log bridge: every value we emit is a string.
type otlpAny struct {
	StringValue string `json:"stringValue,omitempty"`
}

// otlpLogsRequest is the OTLP/HTTP JSON request envelope.
type otlpLogsRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKV `json:"attributes"`
}

type otlpScopeLogs struct {
	Scope      otlpScope   `json:"scope,omitempty"`
	LogRecords []logRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// otlpKV is the OTLP anyvalue key/value pair.
type otlpKV struct {
	Key   string  `json:"key"`
	Value otlpAny `json:"value"`
}

// severityMap maps upper-case severity strings to OTLP severity numbers
// per the OpenTelemetry logs data model (INFO=9, WARN=13, ERROR=17, ...).
var severityMap = map[string]int{
	"TRACE": 1,
	"DEBUG": 5,
	"INFO":  9,
	"WARN":  13,
	"ERROR": 17,
	"FATAL": 21,
}

// NewOTLPLogBridge validates config and returns the bridge. The HTTP
// client and target URL are constructed here so Emit/flush paths stay
// allocation-free.
func NewOTLPLogBridge(cfg OTLPLogBridgeConfig) (*OTLPLogBridge, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp log bridge: endpoint is required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	path := cfg.Path
	if path == "" {
		path = "/v1/logs"
	}

	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	scheme := "http"
	tlsConfig := (*tls.Config)(nil)
	if cfg.TLSEnabled {
		scheme = "https"
		tlsConfig = newTLSConfig(cfg.TLSSkipVerify)
	}
	url := fmt.Sprintf("%s://%s%s", scheme, cfg.Endpoint, path)

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	// Copy headers so callers cannot mutate them after construction.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	hostname, _ := os.Hostname()
	agentID := headers["X-TelemetryFlow-Agent-ID"]

	return &OTLPLogBridge{
		cfg:      cfg,
		log:      logger,
		client:   client,
		url:      url,
		headers:  headers,
		hostname: hostname,
		agentID:  agentID,
		pending:  make([]logRecord, 0, cfg.BatchSize),
		flushNow: make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

// Start launches the flusher goroutine. It is safe to call Start multiple
// times — subsequent calls are no-ops.
func (b *OTLPLogBridge) Start(_ context.Context) error {
	b.wg.Add(1)
	go b.runFlusher()
	return nil
}

// Stop signals the flusher to drain pending records and exit. It blocks
// until the final flush completes (or the flusher has exited).
func (b *OTLPLogBridge) Stop() error {
	select {
	case <-b.stopCh:
		// Already stopped — just wait for the flusher to finish if running.
	default:
		close(b.stopCh)
	}
	// Wake the flusher so it observes stopCh promptly.
	select {
	case b.flushNow <- struct{}{}:
	default:
	}
	<-b.doneCh
	b.wg.Wait()
	return nil
}

// Emit is the callback signature for LogCollector.SetLogCallback.
// It is non-blocking: records are buffered under a mutex and flushed
// asynchronously by the flusher goroutine.
func (b *OTLPLogBridge) Emit(timestamp time.Time, severity, body, source string, attrs map[string]string) {
	rec := logRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timestamp.UnixNano()),
		SeverityNumber: severityNumber(severity),
		SeverityText:   severity,
		Body:           otlpAny{StringValue: body},
	}

	// Build record attributes: source + hostname + agent.id + caller attrs.
	recAttrs := make([]otlpKV, 0, len(attrs)+3)
	recAttrs = append(recAttrs, otlpKV{Key: "source", Value: otlpAny{StringValue: source}})
	if b.hostname != "" {
		recAttrs = append(recAttrs, otlpKV{Key: "hostname", Value: otlpAny{StringValue: b.hostname}})
	}
	if b.agentID != "" {
		recAttrs = append(recAttrs, otlpKV{Key: "agent.id", Value: otlpAny{StringValue: b.agentID}})
	}
	for k, v := range attrs {
		recAttrs = append(recAttrs, otlpKV{Key: k, Value: otlpAny{StringValue: v}})
	}
	rec.Attributes = recAttrs

	b.mu.Lock()
	b.pending = append(b.pending, rec)
	full := len(b.pending) >= b.cfg.BatchSize
	b.mu.Unlock()

	if full {
		select {
		case b.flushNow <- struct{}{}:
		default:
		}
	}
}

// severityNumber maps a severity string to its OTLP numeric value.
// Unknown severities default to INFO (9).
func severityNumber(severity string) int {
	if n, ok := severityMap[strings.ToUpper(strings.TrimSpace(severity))]; ok {
		return n
	}
	return 9 // INFO default
}

// runFlusher is the goroutine that periodically flushes pending records.
func (b *OTLPLogBridge) runFlusher() {
	defer b.wg.Done()
	defer close(b.doneCh)
	ticker := time.NewTicker(b.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			b.flushRemaining()
			return
		case <-b.flushNow:
			b.flush()
		case <-ticker.C:
			b.flush()
		}
	}
}

// flush swaps the pending buffer with a local copy (under mutex) and
// POSTs it. Errors are logged but do not stop the flusher.
func (b *OTLPLogBridge) flush() {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.pending
	b.pending = make([]logRecord, 0, b.cfg.BatchSize)
	b.mu.Unlock()

	if err := b.post(context.Background(), batch); err != nil {
		b.log.Warn("otlp log bridge: export failed",
			zap.Int("records", len(batch)),
			zap.Error(err),
		)
	} else {
		b.log.Debug("otlp log bridge exported",
			zap.Int("records", len(batch)),
		)
	}
}

// flushRemaining is the final flush on Stop.
func (b *OTLPLogBridge) flushRemaining() {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.pending
	b.pending = nil
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.Timeout)
	defer cancel()
	if err := b.post(ctx, batch); err != nil {
		b.log.Warn("otlp log bridge: final flush failed",
			zap.Int("records", len(batch)),
			zap.Error(err),
		)
	}
}

// post serialises the batch into OTLP JSON, gzip-compresses it, and
// POSTs it to the configured endpoint.
func (b *OTLPLogBridge) post(ctx context.Context, records []logRecord) error {
	payload := otlpLogsRequest{
		ResourceLogs: []otlpResourceLogs{
			{
				Resource: otlpResource{
					Attributes: b.resourceAttributes(),
				},
				ScopeLogs: []otlpScopeLogs{
					{
						Scope: otlpScope{
							Name:    "github.com/telemetryflow/telemetryflow-agent",
							Version: "1.0.0",
						},
						LogRecords: records,
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var bodyReader io.Reader = bytes.NewReader(jsonBody)
	bodyLen := len(jsonBody)

	// gzip compress
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(jsonBody); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	bodyReader = &gzBuf
	bodyLen = gzBuf.Len()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bodyReader)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.ContentLength = int64(bodyLen)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tfo-agent/otlp-log-bridge")
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("otlp logs endpoint returned status %s", resp.Status)
	}
	return nil
}

// resourceAttributes builds the standard OTLP resource attributes list:
// service.name, host.name, agent.id.
func (b *OTLPLogBridge) resourceAttributes() []otlpKV {
	attrs := []otlpKV{
		{Key: "service.name", Value: otlpAny{StringValue: "tfo-agent"}},
	}
	if b.hostname != "" {
		attrs = append(attrs, otlpKV{Key: "host.name", Value: otlpAny{StringValue: b.hostname}})
	}
	if b.agentID != "" {
		attrs = append(attrs, otlpKV{Key: "agent.id", Value: otlpAny{StringValue: b.agentID}})
	}
	return attrs
}
