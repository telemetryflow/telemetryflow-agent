// Package aurora implements the Amazon Aurora database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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

package aurora

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

const (
	// ingestEndpoint is the TFO Platform API endpoint for Aurora metrics.
	ingestEndpoint = "/api/v2/db-monitoring/aurora/metrics/ingest"

	// httpTimeout is the HTTP client timeout for push requests.
	httpTimeout = 30 * time.Second

	// maxRetryAttempts is the maximum number of retry attempts for push requests.
	maxRetryAttempts = 3
)

// auroraIngestRequest is the request payload sent to the TFO Platform.
type auroraIngestRequest struct {
	Metrics     []collector.Metric `json:"metrics"`
	CollectedAt time.Time          `json:"collected_at"`
	AgentID     string             `json:"agent_id,omitempty"`
	ClusterID   string             `json:"cluster_id,omitempty"`
}

// auroraIngestResponse is the response from the TFO Platform ingest endpoint.
type auroraIngestResponse struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors,omitempty"`
}

// pushMetrics sends a batch of metrics to the TelemetryFlow Platform.
// Uses the configured TFO endpoint with API-key authentication.
func (c *AuroraCollector) pushMetrics(ctx context.Context, metrics []collector.Metric) error {
	if len(metrics) == 0 {
		return nil
	}

	endpoint := c.cfg.PushEndpoint
	if endpoint == "" {
		// No push endpoint configured; metrics stay in the buffer for
		// the standard OTLP exporter to pick up.
		c.logger.Debug("No Aurora push endpoint configured, metrics available via OTLP export",
			zap.Int("metrics", len(metrics)),
		)
		return nil
	}

	apiKeyID := c.cfg.PushAPIKeyID
	apiKeySecret := c.cfg.PushAPIKeySecret

	// Build the request payload
	payload := auroraIngestRequest{
		Metrics:     metrics,
		CollectedAt: time.Now().UTC(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal aurora ingest payload: %w", err)
	}

	url := endpoint + ingestEndpoint

	var lastErr error
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		lastErr = c.sendIngestRequest(ctx, url, apiKeyID, apiKeySecret, body)
		if lastErr == nil {
			return nil
		}

		// Exponential backoff
		backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}

		c.logger.Debug("Push failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Duration("backoff", backoff),
			zap.Error(lastErr),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			continue
		}
	}

	return fmt.Errorf("push failed after %d attempts: %w", maxRetryAttempts, lastErr)
}

// sendIngestRequest sends a single HTTP POST request to the ingest endpoint.
func (c *AuroraCollector) sendIngestRequest(
	ctx context.Context,
	url, apiKeyID, apiKeySecret string,
	body []byte,
) error {
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tfo-agent/aurora-collector")

	// API-key authentication
	if apiKeyID != "" && apiKeySecret != "" {
		req.Header.Set("X-API-Key-ID", apiKeyID)
		req.Header.Set("X-API-Key-Secret", apiKeySecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ingest endpoint returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response for diagnostics
	var ingestResp auroraIngestResponse
	if err := json.Unmarshal(respBody, &ingestResp); err == nil {
		c.logger.Debug("Aurora metrics pushed",
			zap.Int("accepted", ingestResp.Accepted),
			zap.Int("rejected", ingestResp.Rejected),
		)
	}

	return nil
}
