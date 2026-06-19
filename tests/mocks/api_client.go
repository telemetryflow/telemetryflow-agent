// Package mocks provides test doubles — mock API client, mock collector,
// mock exporter, mock Kubernetes client, and mock logger — for use in unit
// and integration tests across the TelemetryFlow Agent.
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
package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

// HeartbeatRequest represents a heartbeat request
type HeartbeatRequest struct {
	AgentID   string            `json:"agent_id"`
	Hostname  string            `json:"hostname"`
	Timestamp int64             `json:"timestamp"`
	Status    string            `json:"status"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// HeartbeatResponse represents a heartbeat response
type HeartbeatResponse struct {
	Status       string `json:"status"`
	ServerTime   int64  `json:"server_time"`
	NextInterval int    `json:"next_interval"`
}

// MockAPIClient is a mock implementation of the API client
type MockAPIClient struct {
	mock.Mock
}

// NewMockAPIClient creates a new mock API client
func NewMockAPIClient() *MockAPIClient {
	return &MockAPIClient{}
}

// SendHeartbeat mocks the heartbeat API call
func (m *MockAPIClient) SendHeartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*HeartbeatResponse), args.Error(1)
}

// SendMetrics mocks the metrics export API call
func (m *MockAPIClient) SendMetrics(ctx context.Context, data []byte) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

// SendLogs mocks the logs export API call
func (m *MockAPIClient) SendLogs(ctx context.Context, data []byte) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

// Register mocks the agent registration API call
func (m *MockAPIClient) Register(ctx context.Context, agentID, hostname string) error {
	args := m.Called(ctx, agentID, hostname)
	return args.Error(0)
}

// Deregister mocks the agent deregistration API call
func (m *MockAPIClient) Deregister(ctx context.Context, agentID string) error {
	args := m.Called(ctx, agentID)
	return args.Error(0)
}

// Close mocks closing the client connection
func (m *MockAPIClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Heartbeat mocks the heartbeat API call (implements exporter.HeartbeatClient)
func (m *MockAPIClient) Heartbeat(ctx context.Context, agentID string, sysInfo *api.SystemInfoPayload) error {
	args := m.Called(ctx, agentID, sysInfo)
	return args.Error(0)
}
