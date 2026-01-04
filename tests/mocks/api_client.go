// Package mocks provides mock implementations for testing.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
