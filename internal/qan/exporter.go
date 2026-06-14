// Package qan provides the QAN exporter — a batched HTTP JSON push sink.
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

package qan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// qanIngestPath is the TFO Platform QAN API endpoint path.
const qanIngestPath = "/api/v2/qan/collect"

// QANExporter implements QANSink. It buffers incoming QAN buckets and
// periodically flushes them to the TFO Platform QAN endpoint via HTTP JSON.
// The exporter batches up to BatchSize buckets or flushes every FlushInterval,
// whichever comes first. Failed pushes are retried with exponential backoff.
type QANExporter struct {
	cfg     QANConfig
	agentID string
	logger  *zap.Logger
	client  *http.Client

	mu     sync.Mutex
	buffer []QANMetricsBucket

	stopMu    sync.Mutex
	flushStop chan struct{}
	flushWg   sync.WaitGroup
}

// NewQANExporter creates a new QAN exporter.
func NewQANExporter(cfg QANConfig, agentID string, logger *zap.Logger) *QANExporter {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetryAttempts == 0 {
		cfg.MaxRetryAttempts = 3
	}

	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &QANExporter{
		cfg:     cfg,
		agentID: agentID,
		logger:  logger.Named("qan-exporter"),
		client:  &http.Client{Timeout: cfg.Timeout},
		buffer:  make([]QANMetricsBucket, 0, cfg.BatchSize),
	}
}

// Start begins the periodic flush goroutine.
func (e *QANExporter) Start(ctx context.Context) error {
	e.stopMu.Lock()
	if e.flushStop != nil {
		e.stopMu.Unlock()
		return fmt.Errorf("qan exporter already started")
	}
	stopCh := make(chan struct{})
	e.flushStop = stopCh
	e.stopMu.Unlock()

	e.flushWg.Add(1)
	go func() {
		defer e.flushWg.Done()
		ticker := time.NewTicker(e.cfg.FlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = e.Flush(context.Background())
				return
			case <-stopCh:
				_ = e.Flush(context.Background())
				return
			case <-ticker.C:
				_ = e.Flush(ctx)
			}
		}
	}()
	e.logger.Info("QAN exporter started",
		zap.String("endpoint", e.cfg.Endpoint),
		zap.Int("batch_size", e.cfg.BatchSize),
		zap.Duration("flush_interval", e.cfg.FlushInterval),
	)
	return nil
}

// Stop flushes remaining buffers and stops the flush goroutine.
func (e *QANExporter) Stop() error {
	e.stopMu.Lock()
	stopCh := e.flushStop
	e.flushStop = nil
	e.stopMu.Unlock()

	if stopCh != nil {
		close(stopCh)
		e.flushWg.Wait()
	}
	return nil
}

// Collect implements QANSink — buffers buckets for the next flush.
func (e *QANExporter) Collect(ctx context.Context, buckets []QANMetricsBucket) error {
	if len(buckets) == 0 {
		return nil
	}

	e.mu.Lock()
	e.buffer = append(e.buffer, buckets...)
	shouldFlush := len(e.buffer) >= e.cfg.BatchSize
	e.mu.Unlock()

	if shouldFlush {
		return e.Flush(ctx)
	}
	return nil
}

// Flush sends all buffered buckets to the QAN endpoint.
func (e *QANExporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	if len(e.buffer) == 0 {
		e.mu.Unlock()
		return nil
	}
	batch := e.buffer
	e.buffer = make([]QANMetricsBucket, 0, e.cfg.BatchSize)
	e.mu.Unlock()

	return e.pushWithRetry(ctx, batch)
}

func (e *QANExporter) pushWithRetry(ctx context.Context, batch []QANMetricsBucket) error {
	if e.cfg.Endpoint == "" {
		e.logger.Debug("No QAN endpoint configured, dropping batch",
			zap.Int("buckets", len(batch)),
		)
		return nil
	}

	var lastErr error
	for attempt := 0; attempt < e.cfg.MaxRetryAttempts; attempt++ {
		if err := e.push(ctx, batch); err != nil {
			lastErr = err
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			e.logger.Debug("QAN push failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
				zap.Error(err),
			)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}
		return nil
	}
	return fmt.Errorf("qan push failed after %d attempts: %w", e.cfg.MaxRetryAttempts, lastErr)
}

func (e *QANExporter) push(ctx context.Context, batch []QANMetricsBucket) error {
	payload := CollectRequest{
		AgentID: e.agentID,
		Buckets: batch,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("qan marshal payload: %w", err)
	}

	url := e.cfg.Endpoint + qanIngestPath

	reqCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("qan create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tfo-agent/qan-exporter")

	if e.cfg.APIKeyID != "" && e.cfg.APIKeySecret != "" {
		req.Header.Set("X-API-Key-ID", e.cfg.APIKeyID)
		req.Header.Set("X-API-Key-Secret", e.cfg.APIKeySecret)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("qan http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("qan endpoint returned %d", resp.StatusCode)
	}

	var ingestResp CollectResponse
	if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err == nil {
		e.logger.Debug("QAN buckets pushed",
			zap.Int("accepted", ingestResp.Accepted),
			zap.Int("rejected", ingestResp.Rejected),
		)
	}

	return nil
}
