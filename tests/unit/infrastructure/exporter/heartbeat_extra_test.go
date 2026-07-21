// Package exporter_test contains additional unit tests for the heartbeat exporter
// covering system-info collection, collector-state reporting, and error paths.
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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func TestHeartbeat_SendNowWithSystemInfoAndStates(t *testing.T) {
	mockClient := mocks.NewMockAPIClient()
	mockClient.On("Heartbeat", mock.Anything, "agent-x", mock.Anything).Return(nil)

	h := exporter.NewHeartbeat(exporter.HeartbeatConfig{
		AgentID:           "agent-x",
		Hostname:          "host",
		Timeout:           2 * time.Second,
		IncludeSystemInfo: true,
		StatusReport:      true,
		Tags:              map[string]string{"env": "test"},
		Labels:            map[string]string{"team": "obs"},
		Client:            mockClient,
		Logger:            zap.NewNop(),
	})

	h.SetCollectorStatesFn(func() []collector.CollectorStatus {
		return []collector.CollectorStatus{
			{
				Name:         "cpu",
				State:        collector.StateRunning,
				StartedAt:    time.Now().Add(-time.Minute),
				FailureCount: 0,
			},
			{
				Name:         "disk",
				State:        collector.StateFailed,
				LastError:    "mount error",
				FailureCount: 3,
			},
		}
	})

	require.NoError(t, h.SendNow(context.Background()))
	mockClient.AssertExpectations(t)
}

func TestHeartbeat_SendNowError(t *testing.T) {
	mockClient := mocks.NewMockAPIClient()
	mockClient.On("Heartbeat", mock.Anything, "agent-err", mock.Anything).
		Return(errors.New("network error"))

	h := exporter.NewHeartbeat(exporter.HeartbeatConfig{
		AgentID: "agent-err",
		Timeout: time.Second,
		Client:  mockClient,
		Logger:  zap.NewNop(),
	})

	err := h.SendNow(context.Background())
	assert.Error(t, err)
}

func TestHeartbeat_StatusReportWithoutSystemInfo(t *testing.T) {
	mockClient := mocks.NewMockAPIClient()
	mockClient.On("Heartbeat", mock.Anything, "agent-s", mock.Anything).Return(nil)

	h := exporter.NewHeartbeat(exporter.HeartbeatConfig{
		AgentID:      "agent-s",
		Timeout:      time.Second,
		StatusReport: true, // no IncludeSystemInfo -> sysInfo allocated in the states branch
		Client:       mockClient,
		Logger:       zap.NewNop(),
	})
	h.SetCollectorStatesFn(func() []collector.CollectorStatus {
		return []collector.CollectorStatus{{Name: "net", State: collector.StateRunning}}
	})

	require.NoError(t, h.SendNow(context.Background()))
	mockClient.AssertExpectations(t)
}
