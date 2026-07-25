// Package exporter: loki_output.go implements a plugin.Output that ships log
// records (carried as plugin.Metric.Description) to Grafana Loki via the JSON
// push API. Records are grouped into streams by their resolved label set and
// flushed either when BatchSize entries accumulate or after FlushInterval
// elapses, whichever happens first.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// BasicAuth carries HTTP basic-auth credentials for LokiOutput.
type BasicAuth struct {
	Username string
	Password string
}

// LokiOutputConfig configures a LokiOutput.
type LokiOutputConfig struct {
	// Endpoint is the Loki base URL, e.g. https://loki.internal.
	Endpoint string

	// Path is the push endpoint. Defaults to /loki/api/v1/push.
	Path string

	// TenantID sets the X-Scope-OrgID header for multi-tenant Loki.
	TenantID string

	// Auth carries HTTP basic-auth credentials.
	Auth BasicAuth

	// Headers are extra HTTP headers applied to every push.
	Headers map[string]string

	// Timeout is the per-request HTTP timeout. Default 10s.
	Timeout time.Duration

	// BatchSize is the maximum number of pending log entries that trigger
	// an immediate flush. Default 100.
	BatchSize int

	// FlushInterval is the maximum time an entry waits before being pushed.
	// Default 5s.
	FlushInterval time.Duration

	// TLSEnabled is advisory: the push is HTTPS whenever Endpoint's scheme
	// is https. Kept for API symmetry with other outputs.
	TLSEnabled bool

	// TLSSkipVerify disables TLS certificate verification. Intended for
	// internal/lab deployments only.
	TLSSkipVerify bool

	// Logger receives structured diagnostics. Defaults to a nop logger.
	Logger *zap.Logger

	// Labels are static labels applied to every stream.
	Labels map[string]string

	// LabelTemplate extracts dynamic labels from each log entry's existing
	// labels via Go template expansion against the metric's Labels map.
	// Example: {"service": "{{.service.name}}"} resolves labels["service.name"].
	LabelTemplate map[string]string
}

// lokiStream accumulates entries destined for a single Loki stream.
type lokiStream struct {
	labels map[string]string
	values []lokiValue
}

// lokiValue is a single [unix_ns, line] tuple waiting to be flushed.
type lokiValue struct {
	ts   time.Time
	line string
}

// lokiPushRequest is the JSON body POSTed to /loki/api/v1/push.
type lokiPushRequest struct {
	Streams []lokiStreamJSON `json:"streams"`
}

// lokiStreamJSON is the per-stream JSON representation.
type lokiStreamJSON struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// LokiOutput is a plugin.Output that ships log records to Grafana Loki.
type LokiOutput struct {
	cfg      LokiOutputConfig
	log      *zap.Logger
	client   *http.Client
	endpoint string

	mu      sync.Mutex
	pending map[string]*lokiStream
	count   int

	inbound   chan plugin.Metric
	stopCh    chan struct{}
	doneCh    chan struct{}
	templates map[string]*template.Template

	running atomic.Bool
}

// inboundBufferSize caps the inbound channel. Writes block (backpressure)
// when the flusher falls behind rather than dropping entries.
const inboundBufferSize = 1024

// NewLokiOutput validates the configuration and returns a ready output.
// Connect must still be called before Write.
func NewLokiOutput(cfg LokiOutputConfig) (*LokiOutput, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("loki: endpoint is required")
	}
	if cfg.Path == "" {
		cfg.Path = "/loki/api/v1/push"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("loki")

	templates := make(map[string]*template.Template, len(cfg.LabelTemplate))
	for k, v := range cfg.LabelTemplate {
		tmpl, err := template.New(k).Parse(v)
		if err != nil {
			return nil, fmt.Errorf("loki: label template %q: %w", k, err)
		}
		templates[k] = tmpl
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
	}
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout}

	endpoint := strings.TrimRight(cfg.Endpoint, "/") + cfg.Path

	return &LokiOutput{
		cfg:       cfg,
		log:       logger,
		client:    client,
		endpoint:  endpoint,
		pending:   make(map[string]*lokiStream),
		inbound:   make(chan plugin.Metric, inboundBufferSize),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		templates: templates,
	}, nil
}

// Name implements plugin.Output.
func (o *LokiOutput) Name() string { return "loki" }

// Connect starts the background flusher goroutine.
func (o *LokiOutput) Connect() error {
	if o.client == nil {
		return errors.New("loki: client not initialised")
	}
	if !o.running.CompareAndSwap(false, true) {
		return errors.New("loki: already connected")
	}
	go o.run()
	o.log.Info("loki connected",
		zap.String("endpoint", o.endpoint),
		zap.Int("batch_size", o.cfg.BatchSize),
		zap.Duration("flush_interval", o.cfg.FlushInterval),
	)
	return nil
}

// Close flushes any buffered entries, stops the flusher, and releases the
// HTTP client's idle connections. Safe to call multiple times.
func (o *LokiOutput) Close() error {
	if !o.running.Load() {
		return nil
	}
	close(o.stopCh)
	<-o.doneCh
	o.running.Store(false)
	if o.client != nil {
		o.client.CloseIdleConnections()
	}
	return nil
}

// Write enqueues metrics for asynchronous push. The log line is taken from
// m.Description (M3 convention).
func (o *LokiOutput) Write(metrics []plugin.Metric) error {
	if !o.running.Load() {
		return errors.New("loki: not connected")
	}
	if len(metrics) == 0 {
		return nil
	}
	for i := range metrics {
		select {
		case o.inbound <- metrics[i]:
		case <-o.stopCh:
			return errors.New("loki: output stopped")
		}
	}
	return nil
}

// run is the single background flusher goroutine. It owns pending and is the
// only writer to it; the mutex is kept defensive for future extension. It
// exits when stopCh closes, after draining inbound and performing a final
// flush.
func (o *LokiOutput) run() {
	defer close(o.doneCh)
	ticker := time.NewTicker(o.cfg.FlushInterval)
	defer ticker.Stop()

	handle := func(m plugin.Metric) {
		o.appendMetric(m)
		o.mu.Lock()
		count := o.count
		o.mu.Unlock()
		if count >= o.cfg.BatchSize {
			o.flush()
		}
	}

	for {
		select {
		case m := <-o.inbound:
			handle(m)
		case <-ticker.C:
			o.flush()
		case <-o.stopCh:
			// Drain any queued metrics before the final flush so a
			// Close() immediately following Write() does not lose data.
			// BatchSize is still honoured inside the drain so the
			// flush cadence matches the live path.
			for {
				select {
				case m := <-o.inbound:
					handle(m)
				default:
					o.flush()
					return
				}
			}
		}
	}
}

// appendMetric resolves the stream labels for a metric and appends its log
// line to the corresponding pending stream, creating it if necessary.
func (o *LokiOutput) appendMetric(m plugin.Metric) {
	labels := o.resolveLabels(m)
	key := streamKey(labels)
	o.mu.Lock()
	defer o.mu.Unlock()
	s, ok := o.pending[key]
	if !ok {
		s = &lokiStream{labels: labels}
		o.pending[key] = s
	}
	s.values = append(s.values, lokiValue{ts: m.Timestamp, line: m.Description})
	o.count++
}

// resolveLabels builds the stream label set for a metric. The metric's own
// labels form the base layer; static Labels from config override them; finally
// LabelTemplate entries are expanded against the metric's labels and override
// on conflict. Per the spec, the resulting map (sorted + JSON-encoded) is the
// stream key, so metrics that produce the same map group into one stream.
func (o *LokiOutput) resolveLabels(m plugin.Metric) map[string]string {
	out := make(map[string]string, len(o.cfg.Labels)+len(o.templates)+len(m.Labels))
	for k, v := range m.Labels {
		out[k] = v
	}
	for k, v := range o.cfg.Labels {
		out[k] = v
	}
	if len(o.templates) > 0 {
		data := nestedLabels(m.Labels)
		for k, tmpl := range o.templates {
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, data); err != nil {
				o.log.Warn("loki: label template error",
					zap.String("label", k),
					zap.Error(err),
				)
				continue
			}
			val := strings.TrimSpace(buf.String())
			if val != "" {
				out[k] = val
			}
		}
	}
	return out
}

// streamKey returns the canonical JSON encoding of the label map (Go's
// encoding/json emits map keys in sorted order), used to group entries that
// share the same label set into a single Loki stream.
func streamKey(labels map[string]string) string {
	b, err := json.Marshal(labels)
	if err != nil {
		// map[string]string is always marshalable; fall back to an
		// empty object so a malformed label never panics the flusher.
		return "{}"
	}
	return string(b)
}

// flush encodes the pending streams and POSTs them to Loki. Errors are
// logged but do not stop the flusher; the buffered data is dropped to keep
// memory bounded.
func (o *LokiOutput) flush() {
	o.mu.Lock()
	if o.count == 0 {
		o.mu.Unlock()
		return
	}
	pending := o.pending
	o.pending = make(map[string]*lokiStream)
	o.count = 0
	o.mu.Unlock()

	streams := make([]lokiStreamJSON, 0, len(pending))
	totalValues := 0
	for _, s := range pending {
		values := make([][2]string, len(s.values))
		for i, v := range s.values {
			ts := v.ts
			if ts.IsZero() {
				ts = time.Now()
			}
			values[i] = [2]string{
				strconv.FormatInt(ts.UnixNano(), 10),
				v.line,
			}
		}
		totalValues += len(values)
		streams = append(streams, lokiStreamJSON{
			Stream: s.labels,
			Values: values,
		})
	}

	body, err := json.Marshal(lokiPushRequest{Streams: streams})
	if err != nil {
		o.log.Error("loki: encode push", zap.Error(err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		o.log.Error("loki: build request", zap.Error(err))
		return
	}
	o.applyHeaders(req)

	resp, err := o.client.Do(req)
	if err != nil {
		o.log.Error("loki: post", zap.Error(err))
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		o.log.Warn("loki: receiver returned non-success",
			zap.Int("status", resp.StatusCode),
			zap.Int("streams", len(streams)),
			zap.Int("entries", totalValues),
		)
		return
	}
	o.log.Debug("loki push ok",
		zap.Int("streams", len(streams)),
		zap.Int("entries", totalValues),
		zap.Int("status", resp.StatusCode),
	)
}

// applyHeaders sets the canonical Loki headers, the User-Agent, any
// configured auth, the tenant header, and user-supplied extra headers.
func (o *LokiOutput) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	if o.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", o.cfg.TenantID)
	}
	if o.cfg.Auth.Username != "" || o.cfg.Auth.Password != "" {
		req.SetBasicAuth(o.cfg.Auth.Username, o.cfg.Auth.Password)
	}
	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}
}

// nestedLabels converts a flat map[string]string with dotted keys into a
// nested map[string]interface{} so that Go templates can reference
// {{.service.name}} for the labels["service.name"] entry. Non-dotted keys
// are passed through unchanged.
func nestedLabels(labels map[string]string) map[string]interface{} {
	root := make(map[string]interface{}, len(labels))
	for k, v := range labels {
		if !strings.Contains(k, ".") {
			root[k] = v
			continue
		}
		parts := strings.Split(k, ".")
		current := root
		for i, p := range parts {
			if i == len(parts)-1 {
				current[p] = v
				continue
			}
			next, ok := current[p].(map[string]interface{})
			if !ok {
				next = make(map[string]interface{})
				current[p] = next
			}
			current = next
		}
	}
	return root
}

// init self-registers the output with the plugin registry so it is
// reachable via the typed registry by name. The instance returned is
// unconfigured; the pipeline builder is expected to call NewLokiOutput with
// the resolved configuration before Connect/Write.
func init() {
	plugin.MustAddOutput("loki", func() plugin.Output {
		out, err := NewLokiOutput(LokiOutputConfig{})
		if err != nil {
			// Constructor with empty cfg returns an error (endpoint
			// required); fall back to a zero struct so registration
			// still succeeds. Real wiring always goes through the
			// explicit constructor with a populated cfg.
			return &LokiOutput{}
		}
		return out
	})
}
