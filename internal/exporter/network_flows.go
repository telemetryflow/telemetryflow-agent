// Package exporter contains all outbound data-path components: OTLP metric/
// trace/log export, periodic heartbeat to the TelemetryFlow backend, Kubernetes
// cluster-state sync, and the self-observability Prometheus registry and
// HTTP /metrics server.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// NetworkFlowRecord represents a single pod-to-pod network flow event
// aligned with the Hubble flow model for K8S network observability.
type NetworkFlowRecord struct {
	Timestamp       string            `json:"timestamp"`
	SourceNamespace string            `json:"source_namespace"`
	SourcePod       string            `json:"source_pod"`
	SourceIP        string            `json:"source_ip"`
	SourcePort      uint16            `json:"source_port"`
	SourceLabels    map[string]string `json:"source_labels,omitempty"`
	TargetNamespace string            `json:"target_namespace"`
	TargetPod       string            `json:"target_pod"`
	TargetIP        string            `json:"target_ip"`
	TargetPort      uint16            `json:"target_port"`
	TargetLabels    map[string]string `json:"target_labels,omitempty"`
	TargetService   string            `json:"target_service,omitempty"`
	Protocol        string            `json:"protocol"`
	Direction       string            `json:"direction"`
	Verdict         string            `json:"verdict"`
	BytesSent       uint64            `json:"bytes_sent"`
	BytesReceived   uint64            `json:"bytes_received"`
	PacketsSent     uint64            `json:"packets_sent"`
	PacketsReceived uint64            `json:"packets_received"`
	Retransmits     uint32            `json:"retransmits"`
	RttMs           float32           `json:"rtt_ms"`
	HTTPStatusCode  uint16            `json:"http_status_code,omitempty"`
	DNSQuery        string            `json:"dns_query,omitempty"`
	IsExternal      bool              `json:"is_external"`
}

// NetworkFlowBatch is the payload sent to the Platform's POST /k8s/flows endpoint.
type NetworkFlowBatch struct {
	ClusterID string              `json:"cluster_id"`
	Flows     []NetworkFlowRecord `json:"flows"`
}

// NetworkFlowExporterConfig holds configuration for the network flow exporter.
type NetworkFlowExporterConfig struct {
	// ClusterID identifies which K8S cluster these flows belong to.
	ClusterID string

	// Endpoint is the TFO Platform API base URL (e.g., "https://api.telemetryflow.id").
	Endpoint string

	// APIKeyID and APIKeySecret authenticate with the Platform.
	APIKeyID     string
	APIKeySecret string

	// FlushInterval controls how often buffered flows are sent (default: 10s).
	FlushInterval time.Duration

	// MaxBatchSize is the maximum number of flows per POST request.
	MaxBatchSize int

	// Logger for diagnostic output.
	Logger *zap.Logger
}

// NetworkFlowExporter batches and sends pod-level network flow events
// to the TFO Platform's POST /api/v2/monitoring/network-map/k8s/flows endpoint.
//
// Flow records are buffered in memory and flushed at regular intervals
// or when the buffer reaches MaxBatchSize.
type NetworkFlowExporter struct {
	config NetworkFlowExporterConfig
	logger *zap.Logger
	client *http.Client

	mu       sync.Mutex
	buffer   []NetworkFlowRecord
	running  bool
	stopChan chan struct{}
}

// NewNetworkFlowExporter creates a new exporter with the given configuration.
func NewNetworkFlowExporter(cfg NetworkFlowExporterConfig) *NetworkFlowExporter {
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.MaxBatchSize == 0 {
		cfg.MaxBatchSize = 500
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	return &NetworkFlowExporter{
		config:   cfg,
		logger:   cfg.Logger.Named("network-flow-exporter"),
		client:   &http.Client{Timeout: 30 * time.Second},
		buffer:   make([]NetworkFlowRecord, 0, cfg.MaxBatchSize),
		stopChan: make(chan struct{}),
	}
}

// Record adds a flow record to the buffer. Thread-safe.
// If the buffer exceeds MaxBatchSize, an async flush is triggered.
func (e *NetworkFlowExporter) Record(flow NetworkFlowRecord) {
	e.mu.Lock()
	e.buffer = append(e.buffer, flow)
	shouldFlush := len(e.buffer) >= e.config.MaxBatchSize
	e.mu.Unlock()

	if shouldFlush {
		go e.flush()
	}
}

// RecordMany adds multiple flow records at once.
func (e *NetworkFlowExporter) RecordMany(flows []NetworkFlowRecord) {
	if len(flows) == 0 {
		return
	}
	e.mu.Lock()
	e.buffer = append(e.buffer, flows...)
	shouldFlush := len(e.buffer) >= e.config.MaxBatchSize
	e.mu.Unlock()

	if shouldFlush {
		go e.flush()
	}
}

// Start begins the periodic flush loop.
func (e *NetworkFlowExporter) Start() {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()

	if e.config.ClusterID == "" {
		e.logger.Warn("No cluster_id configured, network flow export disabled")
		return
	}

	e.logger.Info("Starting network flow exporter",
		zap.String("endpoint", e.config.Endpoint),
		zap.Duration("flush_interval", e.config.FlushInterval),
		zap.Int("max_batch", e.config.MaxBatchSize),
	)

	go e.flushLoop()
}

// Stop halts the flush loop and sends any remaining buffered flows.
func (e *NetworkFlowExporter) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	e.mu.Unlock()

	close(e.stopChan)
	e.flush() // Final flush
}

func (e *NetworkFlowExporter) flushLoop() {
	ticker := time.NewTicker(e.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.flush()
		case <-e.stopChan:
			return
		}
	}
}

func (e *NetworkFlowExporter) flush() {
	e.mu.Lock()
	if len(e.buffer) == 0 {
		e.mu.Unlock()
		return
	}
	batch := e.buffer
	e.buffer = make([]NetworkFlowRecord, 0, e.config.MaxBatchSize)
	e.mu.Unlock()

	payload := NetworkFlowBatch{
		ClusterID: e.config.ClusterID,
		Flows:     batch,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		e.logger.Error("Failed to marshal network flows", zap.Error(err))
		return
	}

	url := fmt.Sprintf("%s/api/v2/monitoring/network-map/k8s/flows", e.config.Endpoint)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		e.logger.Error("Failed to create flow export request", zap.Error(err))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if e.config.APIKeyID != "" {
		req.Header.Set("X-TelemetryFlow-Key-ID", e.config.APIKeyID)
	}
	if e.config.APIKeySecret != "" {
		req.Header.Set("X-TelemetryFlow-Key-Secret", e.config.APIKeySecret)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		e.logger.Warn("Failed to send network flows",
			zap.Error(err), zap.Int("flows", len(batch)))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		e.logger.Warn("Network flow export returned non-success status",
			zap.Int("status", resp.StatusCode), zap.Int("flows", len(batch)))
		return
	}

	e.logger.Debug("Network flows exported",
		zap.Int("flows", len(batch)), zap.Int("status", resp.StatusCode))
}
