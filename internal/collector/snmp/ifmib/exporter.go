// IF-MIB sample exporter: batched HTTP JSON push to the TFO Platform
// network-map interface-metrics ingestion endpoint.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package ifmib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ingestPath is the TFO Platform interface-metrics ingestion endpoint path.
// Requires permission monitoring:network-map:write and returns 204 on success.
const ingestPath = "/api/v2/monitoring/network-map/snmp/interface-metrics"

// InterfaceSample is one IF-MIB interface sample in the ingestion contract.
// inUtilizationPct/outUtilizationPct are computed by the agent from consecutive
// counter deltas and ifSpeed.
type InterfaceSample struct {
	DeviceID          string  `json:"deviceId"`
	DeviceName        string  `json:"deviceName"`
	IfIndex           int     `json:"ifIndex"`
	IfName            string  `json:"ifName"`
	IfSpeedBps        uint64  `json:"ifSpeedBps"`
	InOctets          uint64  `json:"inOctets"`
	OutOctets         uint64  `json:"outOctets"`
	InErrors          uint64  `json:"inErrors"`
	OutErrors         uint64  `json:"outErrors"`
	InDiscards        uint64  `json:"inDiscards"`
	OutDiscards       uint64  `json:"outDiscards"`
	InUtilizationPct  float64 `json:"inUtilizationPct"`
	OutUtilizationPct float64 `json:"outUtilizationPct"`
	OperStatus        string  `json:"operStatus"`
	Timestamp         string  `json:"timestamp"` // RFC 3339 / ISO 8601, millisecond precision
}

// ingestRequest is the POST body: { "samples": [ ... ] }.
type ingestRequest struct {
	Samples []InterfaceSample `json:"samples"`
}

// exporter pushes batches of interface samples to the platform endpoint with
// bounded exponential-backoff retries.
type exporter struct {
	cfg    config.SNMPInterfaceCollectorConfig
	logger *zap.Logger
	client *http.Client
	url    string
}

// newExporter constructs an exporter from the collector config.
func newExporter(cfg config.SNMPInterfaceCollectorConfig, logger *zap.Logger) *exporter {
	base := strings.TrimRight(cfg.BackendEndpoint, "/")
	return &exporter{
		cfg:    cfg,
		logger: logger.Named("exporter"),
		client: &http.Client{Timeout: cfg.Timeout},
		url:    base + ingestPath,
	}
}

// Push sends all samples in batches of at most cfg.BatchSize. A configured but
// empty endpoint drops the batch (with a debug log) rather than erroring, so a
// misconfigured agent degrades gracefully.
func (e *exporter) Push(ctx context.Context, samples []InterfaceSample) error {
	if len(samples) == 0 {
		return nil
	}
	if e.cfg.BackendEndpoint == "" {
		e.logger.Debug("no backend_endpoint configured, dropping samples",
			zap.Int("samples", len(samples)),
		)
		return nil
	}

	for start := 0; start < len(samples); start += e.cfg.BatchSize {
		end := start + e.cfg.BatchSize
		if end > len(samples) {
			end = len(samples)
		}
		if err := e.pushWithRetry(ctx, samples[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (e *exporter) pushWithRetry(ctx context.Context, batch []InterfaceSample) error {
	var lastErr error
	for attempt := 0; attempt < e.cfg.MaxRetryAttempts; attempt++ {
		err := e.push(ctx, batch)
		if err == nil {
			return nil
		}
		lastErr = err
		backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}
		e.logger.Debug("interface-metrics push failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("interface-metrics push failed after %d attempts: %w", e.cfg.MaxRetryAttempts, lastErr)
}

func (e *exporter) push(ctx context.Context, batch []InterfaceSample) error {
	body, err := json.Marshal(ingestRequest{Samples: batch})
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tfo-agent/snmp-ifmib")
	e.applyAuth(req)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ingestion endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// applyAuth sets the platform auth headers. A Bearer JWT takes precedence when
// configured; otherwise the agent's API-key headers are used.
func (e *exporter) applyAuth(req *http.Request) {
	if e.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.BearerToken)
		return
	}
	if e.cfg.APIKeyID != "" {
		req.Header.Set("X-API-Key-ID", e.cfg.APIKeyID)
	}
	if e.cfg.APIKeySecret != "" {
		req.Header.Set("X-API-Key-Secret", e.cfg.APIKeySecret)
	}
}
