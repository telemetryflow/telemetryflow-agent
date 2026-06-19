// Package remotewrite implements a Prometheus Remote Write receiver that
// accepts push-based metrics over HTTP and forwards them to the TelemetryFlow
// Agent export pipeline.
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
package remotewrite

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

const (
	defaultPort          = 9091
	defaultBufferSize    = 10000
	defaultFlushInterval = 5 * time.Second
	shutdownTimeout      = 5 * time.Second
)

// RemoteWriteReceiver implements collector.Collector.
// It runs an HTTP server and pushes received metrics into an internal channel.
type RemoteWriteReceiver struct {
	cfg     RemoteWriteReceiverConfig
	server  *http.Server
	metrics chan []collector.Metric
	logger  *zap.Logger
	running atomic.Bool
}

// NewRemoteWriteReceiver creates a new RemoteWriteReceiver with the given config and logger.
func NewRemoteWriteReceiver(cfg RemoteWriteReceiverConfig, logger *zap.Logger) *RemoteWriteReceiver {
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}
	return &RemoteWriteReceiver{
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the collector name.
func (r *RemoteWriteReceiver) Name() string {
	return "remote_write_receiver"
}

// Start creates the metrics channel, registers the HTTP handler, and starts the server.
func (r *RemoteWriteReceiver) Start(ctx context.Context) error {
	if r.running.Load() {
		return nil
	}

	r.metrics = make(chan []collector.Metric, r.cfg.BufferSize)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/write", writeHandler(r.cfg, r.metrics, defaultFlushInterval))

	r.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", r.cfg.Port),
		Handler: mux,
	}

	r.running.Store(true)

	go func() {
		r.logger.Info("remote write receiver listening", zap.Int("port", r.cfg.Port))
		if err := r.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			r.logger.Error("remote write receiver server error", zap.Error(err))
			r.running.Store(false)
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP server with a 5-second timeout.
func (r *RemoteWriteReceiver) Stop() error {
	if !r.running.Load() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	err := r.server.Shutdown(ctx)
	r.running.Store(false)
	return err
}

// Collect drains the internal metrics channel non-blockingly and returns all buffered metrics.
func (r *RemoteWriteReceiver) Collect(ctx context.Context) ([]collector.Metric, error) {
	var result []collector.Metric
	for {
		select {
		case batch, ok := <-r.metrics:
			if !ok {
				return result, nil
			}
			result = append(result, batch...)
		default:
			return result, nil
		}
	}
}

// IsRunning returns whether the receiver is currently running.
func (r *RemoteWriteReceiver) IsRunning() bool {
	return r.running.Load()
}
