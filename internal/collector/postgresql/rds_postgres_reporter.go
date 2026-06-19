// Package postgresql implements the PostgreSQL database monitoring collector.
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

package postgresql

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// RDSPostgresReporter submits RDS PostgreSQL agent-side metrics to the TFO Platform
// via the /api/v2/db-monitoring/aws-rds-postgresql/instances/:id/agent-metrics endpoint.
//
// It authenticates with the TFO API key and uses retry with exponential backoff on
// 5xx errors.
type RDSPostgresReporter struct {
	endpoint     string
	apiKeyID     string
	apiKeySecret string
	httpClient   *http.Client
	logger       *zap.Logger

	// Retry configuration
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
}

// NewRDSPostgresReporter creates a new reporter for submitting RDS PostgreSQL metrics.
// If endpoint is empty, the reporter is a no-op (metrics are collected but not submitted).
func NewRDSPostgresReporter(endpoint, apiKeyID, apiKeySecret string, logger *zap.Logger) *RDSPostgresReporter {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &RDSPostgresReporter{
		endpoint:     endpoint,
		apiKeyID:     apiKeyID,
		apiKeySecret: apiKeySecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		logger:     logger.Named("rds_postgres_reporter"),
		maxRetries: 3,
		baseDelay:  time.Second,
		maxDelay:   30 * time.Second,
	}
}

// Submit sends the AgentMetricsPayload to the TFO Platform for a specific RDS instance.
// The payload is POSTed as gzip-compressed JSON to:
//
//	/api/v2/db-monitoring/aws-rds-postgresql/instances/{instanceID}/agent-metrics
//
// Retries on 5xx responses with exponential backoff. Non-retryable errors (4xx)
// return immediately.
func (r *RDSPostgresReporter) Submit(ctx context.Context, payload *AgentMetricsPayload) error {
	if r.endpoint == "" {
		// No endpoint configured -- skip submission (metrics collected but not pushed)
		return nil
	}
	if payload == nil || len(payload.Metrics) == 0 {
		return nil
	}

	url := fmt.Sprintf("%s/api/v2/db-monitoring/aws-rds-postgresql/instances/%s/agent-metrics",
		r.endpoint, payload.InstanceID)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			delay := r.baseDelay * time.Duration(1<<(attempt-1)) // exponential backoff
			if delay > r.maxDelay {
				delay = r.maxDelay
			}
			r.logger.Debug("Retrying metric submission",
				zap.String("instance_id", payload.InstanceID),
				zap.Int("attempt", attempt),
				zap.Duration("delay", delay),
			)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		statusCode, err := r.doPost(ctx, url, body)
		if err != nil {
			lastErr = err
			r.logger.Debug("POST failed",
				zap.String("instance_id", payload.InstanceID),
				zap.Int("attempt", attempt),
				zap.Error(err),
			)
			continue
		}

		// Success
		if statusCode >= 200 && statusCode < 300 {
			r.logger.Debug("Metrics submitted successfully",
				zap.String("instance_id", payload.InstanceID),
				zap.Int("status", statusCode),
				zap.Int("metrics", len(payload.Metrics)),
			)
			return nil
		}

		// Client errors are not retryable
		if statusCode >= 400 && statusCode < 500 {
			return fmt.Errorf("metric submission rejected (status %d) for instance %s",
				statusCode, payload.InstanceID)
		}

		// Server errors are retryable
		lastErr = fmt.Errorf("server error (status %d) for instance %s",
			statusCode, payload.InstanceID)
	}

	return fmt.Errorf("metric submission failed after %d attempts: %w",
		r.maxRetries+1, lastErr)
}

// doPost performs the actual HTTP POST with gzip compression and API key authentication.
func (r *RDSPostgresReporter) doPost(ctx context.Context, url string, body []byte) (int, error) {
	// Gzip compress the payload
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(body); err != nil {
		return 0, fmt.Errorf("gzip write: %w", err)
	}
	if err := gw.Close(); err != nil {
		return 0, fmt.Errorf("gzip close: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	// Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tfo-agent/rds-postgres-reporter")

	// API Key authentication
	if r.apiKeyID != "" && r.apiKeySecret != "" {
		req.Header.Set("X-API-Key-ID", r.apiKeyID)
		req.Header.Set("X-API-Key-Secret", r.apiKeySecret)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("http post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain body to ensure connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}
