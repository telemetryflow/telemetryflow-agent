// Package collector defines the interface for telemetry collectors.
package collector

import (
	"context"
	"time"
)

// Collector is the interface that all collectors must implement
type Collector interface {
	// Name returns the collector name
	Name() string

	// Start starts the collector and begins collecting metrics
	Start(ctx context.Context) error

	// Stop gracefully stops the collector
	Stop() error

	// Collect performs a single collection cycle
	Collect(ctx context.Context) ([]Metric, error)

	// IsRunning returns whether the collector is running
	IsRunning() bool
}

// Metric represents a collected metric
type Metric struct {
	// Name is the metric name
	Name string `json:"name"`

	// Description is a human-readable description
	Description string `json:"description,omitempty"`

	// Type is the metric type (gauge, counter, histogram)
	Type MetricType `json:"type"`

	// Value is the metric value
	Value float64 `json:"value"`

	// Timestamp is when the metric was collected
	Timestamp time.Time `json:"timestamp"`

	// Labels are key-value pairs for dimensions
	Labels map[string]string `json:"labels,omitempty"`

	// Unit is the metric unit (bytes, percent, seconds, etc.)
	Unit string `json:"unit,omitempty"`
}

// MetricType represents the type of metric
type MetricType string

const (
	// MetricTypeGauge is a gauge metric (can go up or down)
	MetricTypeGauge MetricType = "gauge"

	// MetricTypeCounter is a counter metric (monotonically increasing)
	MetricTypeCounter MetricType = "counter"

	// MetricTypeHistogram is a histogram metric
	MetricTypeHistogram MetricType = "histogram"

	// MetricTypeSummary is a summary metric
	MetricTypeSummary MetricType = "summary"
)

// SystemInfo contains system information for heartbeat
type SystemInfo struct {
	// Host information
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"osVersion,omitempty"`
	KernelVersion string `json:"kernelVersion,omitempty"`
	Architecture string `json:"architecture"`
	Uptime       uint64 `json:"uptime"`

	// CPU information
	CPUCores     int     `json:"cpuCores"`
	CPUModel     string  `json:"cpuModel,omitempty"`
	CPUUsage     float64 `json:"cpuUsage"`

	// Memory information
	MemoryTotal     uint64  `json:"memoryTotal"`
	MemoryUsed      uint64  `json:"memoryUsed"`
	MemoryAvailable uint64  `json:"memoryAvailable"`
	MemoryUsage     float64 `json:"memoryUsage"`

	// Disk information
	DiskTotal     uint64  `json:"diskTotal"`
	DiskUsed      uint64  `json:"diskUsed"`
	DiskAvailable uint64  `json:"diskAvailable"`
	DiskUsage     float64 `json:"diskUsage"`

	// Network information
	NetworkBytesSent uint64 `json:"networkBytesSent,omitempty"`
	NetworkBytesRecv uint64 `json:"networkBytesRecv,omitempty"`
}

// MetricBatch represents a batch of metrics for export
type MetricBatch struct {
	// Metrics is the list of metrics
	Metrics []Metric `json:"metrics"`

	// CollectedAt is when the batch was created
	CollectedAt time.Time `json:"collectedAt"`

	// AgentID is the agent that collected the metrics
	AgentID string `json:"agentId"`

	// Hostname is the host where metrics were collected
	Hostname string `json:"hostname"`
}

// NewMetric creates a new metric with current timestamp
func NewMetric(name string, value float64, metricType MetricType) Metric {
	return Metric{
		Name:      name,
		Type:      metricType,
		Value:     value,
		Timestamp: time.Now(),
		Labels:    make(map[string]string),
	}
}

// WithLabels adds labels to a metric
func (m Metric) WithLabels(labels map[string]string) Metric {
	for k, v := range labels {
		m.Labels[k] = v
	}
	return m
}

// WithLabel adds a single label to a metric
func (m Metric) WithLabel(key, value string) Metric {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	m.Labels[key] = value
	return m
}

// WithUnit sets the unit for a metric
func (m Metric) WithUnit(unit string) Metric {
	m.Unit = unit
	return m
}

// WithDescription sets the description for a metric
func (m Metric) WithDescription(desc string) Metric {
	m.Description = desc
	return m
}
