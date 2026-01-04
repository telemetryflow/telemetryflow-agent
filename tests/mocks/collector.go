// Package mocks provides mock implementations for testing.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
)

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeCounter   MetricType = "counter"
	MetricTypeHistogram MetricType = "histogram"
)

// Metric represents a collected metric
type Metric struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        MetricType        `json:"type"`
	Value       float64           `json:"value"`
	Timestamp   time.Time         `json:"timestamp"`
	Labels      map[string]string `json:"labels,omitempty"`
	Unit        string            `json:"unit,omitempty"`
}

// MockCollector is a mock implementation of the Collector interface
type MockCollector struct {
	mock.Mock
	name    string
	running bool
}

// NewMockCollector creates a new mock collector
func NewMockCollector(name string) *MockCollector {
	return &MockCollector{
		name: name,
	}
}

// Name returns the collector name
func (m *MockCollector) Name() string {
	return m.name
}

// Start mocks starting the collector
func (m *MockCollector) Start(ctx context.Context) error {
	args := m.Called(ctx)
	m.running = true
	return args.Error(0)
}

// Stop mocks stopping the collector
func (m *MockCollector) Stop() error {
	args := m.Called()
	m.running = false
	return args.Error(0)
}

// Collect mocks collecting metrics
func (m *MockCollector) Collect(ctx context.Context) ([]Metric, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]Metric), args.Error(1)
}

// IsRunning returns whether the collector is running
func (m *MockCollector) IsRunning() bool {
	return m.running
}

// MockMetrics returns a set of mock metrics for testing
func MockMetrics() []Metric {
	now := time.Now()
	return []Metric{
		{
			Name:        "system_cpu_usage_percent",
			Description: "CPU usage percentage",
			Type:        MetricTypeGauge,
			Value:       45.5,
			Timestamp:   now,
			Labels: map[string]string{
				"host": "test-host",
				"cpu":  "total",
			},
			Unit: "percent",
		},
		{
			Name:        "system_memory_usage_bytes",
			Description: "Memory usage in bytes",
			Type:        MetricTypeGauge,
			Value:       4294967296, // 4GB
			Timestamp:   now,
			Labels: map[string]string{
				"host": "test-host",
			},
			Unit: "bytes",
		},
		{
			Name:        "system_disk_usage_percent",
			Description: "Disk usage percentage",
			Type:        MetricTypeGauge,
			Value:       67.3,
			Timestamp:   now,
			Labels: map[string]string{
				"host":       "test-host",
				"mountpoint": "/",
			},
			Unit: "percent",
		},
		{
			Name:        "system_network_bytes_sent_total",
			Description: "Total network bytes sent",
			Type:        MetricTypeCounter,
			Value:       1073741824, // 1GB
			Timestamp:   now,
			Labels: map[string]string{
				"host":      "test-host",
				"interface": "eth0",
			},
			Unit: "bytes",
		},
	}
}
