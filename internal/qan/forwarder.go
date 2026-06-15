// Package qan provides the QANCollector interface and QANForwarder loop.
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

package qan

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// QANCollector is implemented by any collector that produces Query Analytics
// data buckets. This is a sibling interface to collector.Collector — a DB
// collector can implement both: Collect() for standard metrics via the
// MetricForwarder, and CollectQAN() for QAN buckets via the QANForwarder.
type QANCollector interface {
	// Name identifies the QAN collector (e.g. "qan-postgresql-pgstatements").
	Name() string

	// AgentType returns the PMM-compatible agent type identifier.
	AgentType() AgentType

	// CollectQAN queries the database, computes deltas from the previous
	// snapshot, and returns a batch of QANMetricsBucket for the period.
	CollectQAN(ctx context.Context) ([]QANMetricsBucket, error)

	// IsRunning returns whether the underlying collector is active.
	IsRunning() bool
}

// Starter is an optional interface that QAN collectors can implement to
// support explicit lifecycle management. The QANForwarder calls Start() on
// all collectors that implement this interface when the forwarder starts.
type Starter interface {
	Start(ctx context.Context) error
}

// QANSink is the interface for pushing QAN buckets to a backend.
type QANSink interface {
	Collect(ctx context.Context, buckets []QANMetricsBucket) error
}

// QANForwarder periodically collects QAN data from all QAN collectors and
// forwards buckets to the configured sink. It runs on its own interval
// (default 60s) separate from the MetricForwarder.
type QANForwarder struct {
	collectors []QANCollector
	sink       QANSink
	logger     *zap.Logger
	interval   time.Duration

	mu           sync.RWMutex
	running      bool
	stopChan     chan struct{}
	totalCollect atomic.Int64
	totalBuckets atomic.Int64
	totalErrors  atomic.Int64
}

// QANForwarderConfig holds configuration for the forwarder.
type QANForwarderConfig struct {
	Collectors []QANCollector
	Sink       QANSink
	Interval   time.Duration
	Logger     *zap.Logger
}

// NewQANForwarder creates a new QAN forwarder.
func NewQANForwarder(cfg QANForwarderConfig) *QANForwarder {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	return &QANForwarder{
		collectors: cfg.Collectors,
		sink:       cfg.Sink,
		logger:     logger.Named("qan-forwarder"),
		interval:   cfg.Interval,
		stopChan:   make(chan struct{}),
	}
}

// Start begins the periodic QAN collection loop.
func (f *QANForwarder) Start(ctx context.Context) error {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return nil
	}
	f.running = true
	f.stopChan = make(chan struct{})
	f.mu.Unlock()

	// Start all collectors that implement Starter.
	for _, c := range f.collectors {
		if s, ok := c.(Starter); ok {
			if err := s.Start(ctx); err != nil {
				f.logger.Warn("QAN collector start failed",
					zap.String("collector", c.Name()),
					zap.Error(err),
				)
			}
		}
	}

	f.logger.Info("QAN forwarder starting",
		zap.Int("collectors", len(f.collectors)),
		zap.Duration("interval", f.interval),
	)

	go f.loop(ctx)
	return nil
}

// Stop signals the forwarder to stop.
func (f *QANForwarder) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running {
		return nil
	}
	close(f.stopChan)
	f.running = false
	f.logger.Info("QAN forwarder stopped",
		zap.Int64("total_collects", f.totalCollect.Load()),
		zap.Int64("total_buckets", f.totalBuckets.Load()),
		zap.Int64("total_errors", f.totalErrors.Load()),
	)
	return nil
}

// IsRunning returns whether the forwarder is running.
func (f *QANForwarder) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}

// Stats returns forwarder statistics.
func (f *QANForwarder) Stats() QANForwarderStats {
	return QANForwarderStats{
		Running:       f.IsRunning(),
		TotalCollects: f.totalCollect.Load(),
		TotalBuckets:  f.totalBuckets.Load(),
		TotalErrors:   f.totalErrors.Load(),
	}
}

// QANForwarderStats contains forwarder statistics.
type QANForwarderStats struct {
	Running       bool  `json:"running"`
	TotalCollects int64 `json:"totalCollects"`
	TotalBuckets  int64 `json:"totalBuckets"`
	TotalErrors   int64 `json:"totalErrors"`
}

func (f *QANForwarder) loop(ctx context.Context) {
	f.collectAll(ctx)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-f.stopChan:
			return
		case <-ticker.C:
			f.collectAll(ctx)
		}
	}
}

func (f *QANForwarder) collectAll(ctx context.Context) {
	var allBuckets []QANMetricsBucket

	for _, c := range f.collectors {
		if !c.IsRunning() {
			continue
		}
		buckets, err := c.CollectQAN(ctx)
		if err != nil {
			f.totalErrors.Add(1)
			f.logger.Warn("QAN collect failed",
				zap.String("collector", c.Name()),
				zap.Error(err),
			)
			continue
		}
		if len(buckets) > 0 {
			allBuckets = append(allBuckets, buckets...)
		}
	}

	if len(allBuckets) == 0 {
		return
	}

	if f.sink != nil {
		if err := f.sink.Collect(ctx, allBuckets); err != nil {
			f.totalErrors.Add(1)
			f.logger.Warn("QAN export failed",
				zap.Int("buckets", len(allBuckets)),
				zap.Error(err),
			)
		} else {
			f.totalCollect.Add(1)
			f.totalBuckets.Add(int64(len(allBuckets)))
			f.logger.Debug("QAN buckets forwarded",
				zap.Int("buckets", len(allBuckets)),
			)
		}
	}
}
