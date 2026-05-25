// Package mocks provides test doubles — mock API client, mock collector,
// mock exporter, mock Kubernetes client, and mock logger — for use in unit
// and integration tests across the TelemetryFlow Agent.
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
package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// ExportRequest represents an export request
type ExportRequest struct {
	Data       []byte            `json:"data"`
	DataType   string            `json:"data_type"` // metrics, logs, traces
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ExportResponse represents an export response
type ExportResponse struct {
	Status       string `json:"status"`
	ItemsWritten int    `json:"items_written"`
	Error        string `json:"error,omitempty"`
}

// MockExporter is a mock implementation of the Exporter interface
type MockExporter struct {
	mock.Mock
	name    string
	running bool
}

// NewMockExporter creates a new mock exporter
func NewMockExporter(name string) *MockExporter {
	return &MockExporter{
		name: name,
	}
}

// Name returns the exporter name
func (m *MockExporter) Name() string {
	return m.name
}

// Start mocks starting the exporter
func (m *MockExporter) Start(ctx context.Context) error {
	args := m.Called(ctx)
	m.running = true
	return args.Error(0)
}

// Stop mocks stopping the exporter
func (m *MockExporter) Stop() error {
	args := m.Called()
	m.running = false
	return args.Error(0)
}

// Export mocks exporting data
func (m *MockExporter) Export(ctx context.Context, data interface{}) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

// ExportMetrics mocks exporting metrics
func (m *MockExporter) ExportMetrics(ctx context.Context, data []byte) (*ExportResponse, error) {
	args := m.Called(ctx, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ExportResponse), args.Error(1)
}

// ExportLogs mocks exporting logs
func (m *MockExporter) ExportLogs(ctx context.Context, data []byte) (*ExportResponse, error) {
	args := m.Called(ctx, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ExportResponse), args.Error(1)
}

// IsRunning returns whether the exporter is running
func (m *MockExporter) IsRunning() bool {
	return m.running
}

// Flush mocks flushing pending data
func (m *MockExporter) Flush(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
