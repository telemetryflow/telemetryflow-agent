// Package exporter: prometheus_remote_write_output.go implements a proper
// Prometheus remote-write output using the prompb protobuf schema plus snappy
// block compression, as required by real remote-write receivers (Mimir,
// Cortex, Thanos, VictoriaMetrics). It replaces the legacy TEXT-format stub
// that lives in internal/integrations/prometheus.go.
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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// PromRemoteWriteConfig configures a PromRemoteWriteOutput.
type PromRemoteWriteConfig struct {
	// Endpoint is the full remote-write URL, e.g.
	// "https://mimir.internal/api/v1/push".
	Endpoint string

	// Headers are extra HTTP headers applied to every push (e.g.
	// X-Scope-OrgID for Mimir tenants).
	Headers map[string]string

	// AuthType selects the authentication scheme: "basic" (default),
	// "bearer", or "none".
	AuthType string

	// Username + Password are used when AuthType == "basic".
	Username string
	Password string

	// Token is used when AuthType == "bearer" (sent as
	// "Authorization: Bearer <token>").
	Token string

	// TLSSkipVerify disables TLS certificate verification. Intended for
	// internal/lab deployments only.
	TLSSkipVerify bool

	// Timeout is the per-request HTTP timeout. Default 30s.
	Timeout time.Duration

	// BatchSize is the maximum number of metrics encoded per push. Default
	// 5000.
	BatchSize int

	// FlushInterval is reserved for the async flusher path; the synchronous
	// Write path flushes immediately. Default 5s.
	FlushInterval time.Duration

	// Logger receives structured diagnostics. Defaults to a nop logger.
	Logger *zap.Logger
}

// PromRemoteWriteOutput is a plugin.Output that ships metrics to a Prometheus
// remote-write receiver using the canonical protobuf + snappy block encoding.
type PromRemoteWriteOutput struct {
	cfg    PromRemoteWriteConfig
	log    *zap.Logger
	client *http.Client

	// endpoint is captured separately so tests can override it after
	// construction without mutating the user-facing cfg struct.
	endpoint string
}

// remoteWriteVersion is the value of the X-Prometheus-Remote-Write-Version
// header. "0.1.0" is the universally compatible value supported by every
// production remote-write receiver.
const remoteWriteVersion = "0.1.0"

// NewPromRemoteWriteOutput validates the configuration and returns a ready
// output. Connect must still be called before Write.
func NewPromRemoteWriteOutput(cfg PromRemoteWriteConfig) (*PromRemoteWriteOutput, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("prometheus_remote_write: endpoint is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 5000
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("prom_remote_write")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
	}
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout}

	return &PromRemoteWriteOutput{
		cfg:      cfg,
		log:      logger,
		client:   client,
		endpoint: cfg.Endpoint,
	}, nil
}

// Name implements plugin.Output.
func (o *PromRemoteWriteOutput) Name() string { return "prometheus_remote_write" }

// Connect probes the receiver with an empty WriteRequest so that startup
// failures (auth, network, wrong endpoint) surface immediately rather than
// on the first real batch.
func (o *PromRemoteWriteOutput) Connect() error {
	if o.client == nil {
		return errors.New("prometheus_remote_write: client not initialised")
	}
	empty := &prompb.WriteRequest{}
	body, err := o.encode(empty)
	if err != nil {
		return fmt.Errorf("prometheus_remote_write: encode probe: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("prometheus_remote_write: build probe: %w", err)
	}
	o.applyHeaders(req)
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("prometheus_remote_write: connect probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	// 2xx (and 4xx for auth/tenant errors) all prove the endpoint is
	// reachable; the caller decides whether to retry on 4xx.
	if resp.StatusCode >= 300 {
		return fmt.Errorf("prometheus_remote_write: probe returned %s", resp.Status)
	}
	o.log.Info("prometheus remote-write connected",
		zap.String("endpoint", o.endpoint),
		zap.String("remote_write_version", remoteWriteVersion),
	)
	return nil
}

// Close releases the HTTP client's idle connections.
func (o *PromRemoteWriteOutput) Close() error {
	if o.client != nil {
		o.client.CloseIdleConnections()
	}
	return nil
}

// Write implements plugin.Output. It encodes the batch per the Prometheus
// remote-write spec (prompb.Marshal + snappy.Encode block format) and POSTs
// it to the configured endpoint, chunking internally to honor BatchSize.
func (o *PromRemoteWriteOutput) Write(metrics []plugin.Metric) error {
	if o.client == nil {
		return errors.New("prometheus_remote_write: not connected")
	}
	if len(metrics) == 0 {
		return nil
	}

	batchSize := o.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 5000
	}

	for start := 0; start < len(metrics); start += batchSize {
		end := start + batchSize
		if end > len(metrics) {
			end = len(metrics)
		}
		chunk := metrics[start:end]

		wr := buildWriteRequest(chunk)
		body, err := o.encode(&wr)
		if err != nil {
			return fmt.Errorf("prometheus_remote_write: encode: %w", err)
		}

		req, err := http.NewRequest(http.MethodPost, o.endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("prometheus_remote_write: build request: %w", err)
		}
		o.applyHeaders(req)

		resp, err := o.client.Do(req)
		if err != nil {
			return fmt.Errorf("prometheus_remote_write: post: %w", err)
		}
		// Drain & close so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("prometheus_remote_write: receiver returned %s", resp.Status)
		}
		o.log.Debug("prometheus remote-write push ok",
			zap.Int("metrics", len(chunk)),
			zap.Int("timeseries", len(wr.Timeseries)),
			zap.Int("status", resp.StatusCode),
		)
	}
	return nil
}

// Export is the legacy MetricSink adapter. It bridges the existing
// internal/exporter.MetricForwarder (which speaks collector.Metric) onto the
// typed plugin.Output.Write path.
func (o *PromRemoteWriteOutput) Export(ctx context.Context, metrics []collector.Metric, _ map[string]string) error {
	// Honour context cancellation even though the underlying HTTP client is
	// not context-aware in the legacy forwarder wiring.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return o.Write(plugin.FromLegacyMetrics(metrics))
}

// encode marshals a WriteRequest with protobuf and compresses it with snappy
// block format, returning the exact bytes that should be used as the
// http.Request body.
func (o *PromRemoteWriteOutput) encode(wr *prompb.WriteRequest) ([]byte, error) {
	raw, err := wr.Marshal()
	if err != nil {
		return nil, fmt.Errorf("prompb marshal: %w", err)
	}
	compressed := snappy.Encode(nil, raw)
	return compressed, nil
}

// applyHeaders sets the canonical remote-write headers, the User-Agent, any
// configured auth header, and any user-supplied extra headers.
func (o *PromRemoteWriteOutput) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", remoteWriteVersion)
	req.Header.Set("User-Agent", version.UserAgent())

	switch o.cfg.AuthType {
	case "bearer", "Bearer":
		if o.cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+o.cfg.Token)
		}
	case "none", "":
		// no auth header
	default:
		// "basic" and anything else fall through to basic auth.
		if o.cfg.Username != "" || o.cfg.Password != "" {
			req.SetBasicAuth(o.cfg.Username, o.cfg.Password)
		}
	}

	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}
}

// buildWriteRequest converts a slice of plugin.Metric into a prompb.WriteRequest,
// expanding each metric into one TimeSeries carrying a single Sample. Labels
// are sorted alphabetically (required by the remote-write spec: __name__ plus
// all metric labels).
func buildWriteRequest(metrics []plugin.Metric) prompb.WriteRequest {
	ts := make([]prompb.TimeSeries, 0, len(metrics))
	for _, m := range metrics {
		ts = append(ts, prompb.TimeSeries{
			Labels: buildLabels(m),
			Samples: []prompb.Sample{{
				Value:     m.Value,
				Timestamp: m.Timestamp.UnixMilli(),
			}},
		})
	}
	return prompb.WriteRequest{Timeseries: ts}
}

// buildLabels produces the sorted prompb.Label slice for a metric: __name__
// first (kept in the alphabetical sort like every other label, as required by
// remote-write receivers), followed by every dimension label.
func buildLabels(m plugin.Metric) []prompb.Label {
	labels := make([]prompb.Label, 0, len(m.Labels)+1)
	labels = append(labels, prompb.Label{Name: "__name__", Value: m.Name})
	for k, v := range m.Labels {
		labels = append(labels, prompb.Label{Name: k, Value: v})
	}
	sort.Slice(labels, func(i, j int) bool {
		return labels[i].Name < labels[j].Name
	})
	return labels
}

// init self-registers the output with the plugin registry so it is reachable
// via the typed registry by name. The instance returned is unconfigured; the
// pipeline builder is expected to call NewPromRemoteWriteOutput with the
// resolved configuration before Connect/Write.
func init() {
	plugin.MustAddOutput("prometheus_remote_write", func() plugin.Output {
		out, err := NewPromRemoteWriteOutput(PromRemoteWriteConfig{})
		if err != nil {
			// Constructor with empty cfg returns an error (endpoint
			// required); fall back to a zero struct so registration
			// still succeeds. Real wiring always goes through the
			// explicit constructor with a populated cfg.
			return &PromRemoteWriteOutput{}
		}
		return out
	})
}
