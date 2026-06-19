// Package exporter_test contains integration tests for TelemetryFlow Agent
// exporter components verifying end-to-end data delivery.
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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

func TestHeartbeatIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("should handle heartbeat lifecycle", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		// Create API client with test config
		client := api.NewClient(api.ClientConfig{
			BaseURL:       "http://localhost:3100",
			APIKeyID:      "test-key",
			APIKeySecret:  "test-secret",
			Timeout:       5 * time.Second,
			RetryAttempts: 1,
			Logger:        logger,
		})

		cfg := exporter.HeartbeatConfig{
			AgentID:           "integration-test-agent",
			Hostname:          "test-host",
			Interval:          2 * time.Second,
			Timeout:           time.Second,
			IncludeSystemInfo: false, // Disable for faster test
			Client:            client,
			Logger:            logger,
		}

		h := exporter.NewHeartbeat(cfg)
		require.NotNil(t, h)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Start heartbeat
		errChan := make(chan error, 1)
		go func() {
			errChan <- h.Start(ctx)
		}()

		// Let it run briefly
		time.Sleep(time.Second)
		assert.True(t, h.IsRunning())

		// Stop heartbeat
		err := h.Stop()
		assert.NoError(t, err)
		assert.False(t, h.IsRunning())

		// Wait for completion
		cancel()
		err = <-errChan
		// Heartbeat returns context.Canceled or nil depending on timing
		// Either is acceptable for graceful shutdown
		if err != nil {
			assert.ErrorIs(t, err, context.Canceled)
		}
	})
}
