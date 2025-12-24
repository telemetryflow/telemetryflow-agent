// Package mocks provides mock implementations for testing.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
