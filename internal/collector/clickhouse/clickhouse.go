// Package clickhouse implements a TelemetryFlow Agent collector for external
// ClickHouse instances.  It periodically queries ClickHouse system tables via
// the HTTP interface (port 8123) and emits the results as OTLP metrics.
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
package clickhouse

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "clickhouse"

// instanceState holds the per-instance runtime state: connection, event counters,
// and query-log watermark.
type instanceState struct {
	inst config.ClickHouseInstanceConfig
	// mu guards conn and the reconnect/back-off fields against concurrent
	// access by the collection goroutine and Stop().
	mu                sync.Mutex
	conn              *connection
	prevEvents        map[string]float64
	queryLogWatermark time.Time

	// exponential back-off for reconnects
	backoffDuration time.Duration
	lastConnectErr  time.Time
}

// ClickHouseCollector monitors one or more external ClickHouse instances.
// It implements the collector.Collector interface.
type ClickHouseCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	// per-instance runtime state (keyed by instance index)
	states []*instanceState
}

// NewClickHouseCollector creates a new ClickHouseCollector.
// Connections are opened lazily on the first collection cycle so startup
// does not block if a ClickHouse instance is temporarily unavailable.
func NewClickHouseCollector(cfg config.ClickHouseCollectorConfig, logger *zap.Logger) *ClickHouseCollector {
	c := NewConfig(cfg)

	// Initialize watermark to 1 hour ago so the first collection cycle
	// doesn't scan the entire system.query_log table (which can have
	// millions of rows and cause HTTP timeouts).
	initialWatermark := time.Now().Add(-1 * time.Hour)

	states := make([]*instanceState, len(c.Instances))
	for i, inst := range c.Instances {
		states[i] = &instanceState{
			inst:              inst,
			prevEvents:        make(map[string]float64),
			queryLogWatermark: initialWatermark,
		}
	}

	return &ClickHouseCollector{
		cfg:    c,
		logger: logger.Named(collectorName),
		states: states,
	}
}

// Name returns the collector name.
func (c *ClickHouseCollector) Name() string {
	return collectorName
}

// IsRunning returns whether the collector is currently running.
func (c *ClickHouseCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start begins periodic metric collection.  It runs two tickers:
//   - system metrics ticker at cfg.CollectionInterval
//   - query log ticker at cfg.QueryLogInterval
//
// Start blocks until ctx is cancelled or Stop is called.
func (c *ClickHouseCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("clickhouse collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("ClickHouse collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("collection_interval", c.cfg.CollectionInterval),
		zap.Duration("query_log_interval", c.cfg.QueryLogInterval),
	)

	metricsTicker := time.NewTicker(c.cfg.CollectionInterval)
	queryLogTicker := time.NewTicker(c.cfg.QueryLogInterval)
	defer metricsTicker.Stop()
	defer queryLogTicker.Stop()

	// Initial collection at startup.
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial system metrics collection failed", zap.Error(err))
	}
	if _, err := c.CollectQueryLog(ctx); err != nil {
		c.logger.Warn("Initial query log collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return c.Stop()
		case <-c.stopChan:
			return nil
		case <-metricsTicker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("System metrics collection failed", zap.Error(err))
			}
		case <-queryLogTicker.C:
			if _, err := c.CollectQueryLog(ctx); err != nil {
				c.logger.Warn("Query log collection failed", zap.Error(err))
			}
		}
	}
}

// Stop gracefully shuts down the collector.
func (c *ClickHouseCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("ClickHouse collector stopping")
	c.running = false
	close(c.stopChan)

	// Close all connections. Take each instance lock so this cannot race with
	// an in-flight ensureConnection on the collection goroutine.
	for _, s := range c.states {
		s.mu.Lock()
		if s.conn != nil {
			s.conn.Close()
			s.conn = nil
		}
		s.mu.Unlock()
	}
	return nil
}

// Collect gathers system metrics from all configured instances concurrently.
func (c *ClickHouseCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.states) == 0 {
		return nil, nil
	}

	type result struct {
		metrics []collector.Metric
		err     error
	}

	results := make([]result, len(c.states))

	if len(c.states) == 1 {
		// Single instance — no goroutine overhead.
		m, err := c.collectInstance(ctx, c.states[0])
		results[0] = result{metrics: m, err: err}
	} else {
		var wg sync.WaitGroup
		for i, s := range c.states {
			wg.Add(1)
			go func(idx int, state *instanceState) {
				defer wg.Done()
				m, err := c.collectInstance(ctx, state)
				results[idx] = result{metrics: m, err: err}
			}(i, s)
		}
		wg.Wait()
	}

	var all []collector.Metric
	for i, r := range results {
		if r.err != nil {
			c.logger.Warn("Collection failed for instance",
				zap.String("instance", c.states[i].inst.Name),
				zap.Error(r.err),
			)
			continue
		}
		all = append(all, r.metrics...)
	}
	return all, nil
}

// CollectQueryLog gathers query log metrics from all configured instances concurrently.
func (c *ClickHouseCollector) CollectQueryLog(ctx context.Context) ([]collector.Metric, error) {
	if len(c.states) == 0 {
		return nil, nil
	}

	type result struct {
		metrics []collector.Metric
		err     error
	}

	results := make([]result, len(c.states))

	if len(c.states) == 1 {
		m, err := c.collectQueryLogInstance(ctx, c.states[0])
		results[0] = result{metrics: m, err: err}
	} else {
		var wg sync.WaitGroup
		for i, s := range c.states {
			wg.Add(1)
			go func(idx int, state *instanceState) {
				defer wg.Done()
				m, err := c.collectQueryLogInstance(ctx, state)
				results[idx] = result{metrics: m, err: err}
			}(i, s)
		}
		wg.Wait()
	}

	var all []collector.Metric
	for i, r := range results {
		if r.err != nil {
			c.logger.Warn("Query log collection failed for instance",
				zap.String("instance", c.states[i].inst.Name),
				zap.Error(r.err),
			)
			continue
		}
		all = append(all, r.metrics...)
	}
	return all, nil
}

// -------------------------------------------------------------------
// Private helpers
// -------------------------------------------------------------------

// ensureConnection returns (or lazily creates) a live connection for the state.
// It implements exponential back-off: 1s → 2s → 4s → 8s → 16s, capped at 60s.
func (c *ClickHouseCollector) ensureConnection(ctx context.Context, s *instanceState) (*connection, error) {
	// Guard conn/back-off state; Stop() may run concurrently with a collection
	// cycle. advanceBackoff (called below) intentionally does not re-lock.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		// Quick health check.
		if err := s.conn.Check(ctx); err == nil {
			return s.conn, nil
		}
		// Connection lost — close and reconnect.
		s.conn.Close()
		s.conn = nil
	}

	// Back-off check.
	if !s.lastConnectErr.IsZero() {
		wait := s.backoffDuration
		if wait == 0 {
			wait = time.Second
		}
		elapsed := time.Since(s.lastConnectErr)
		if elapsed < wait {
			return nil, fmt.Errorf("clickhouse %s: in back-off (retry in %s)",
				s.inst.Name, (wait - elapsed).Round(time.Millisecond))
		}
	}

	conn, err := newConnection(s.inst)
	if err != nil {
		c.advanceBackoff(s)
		return nil, fmt.Errorf("clickhouse %s: create connection: %w", s.inst.Name, err)
	}
	if err := conn.Check(ctx); err != nil {
		conn.Close()
		c.advanceBackoff(s)
		return nil, fmt.Errorf("clickhouse %s: health check: %w", s.inst.Name, err)
	}

	// Connected successfully — reset back-off.
	s.conn = conn
	s.backoffDuration = 0
	s.lastConnectErr = time.Time{}
	c.logger.Info("Connected to ClickHouse instance",
		zap.String("instance", s.inst.Name),
		zap.String("host", s.inst.Host),
		zap.Int("http_port", s.inst.HTTPPort),
	)
	return conn, nil
}

// advanceBackoff doubles the back-off duration up to 60 seconds.
func (c *ClickHouseCollector) advanceBackoff(s *instanceState) {
	s.lastConnectErr = time.Now()
	if s.backoffDuration == 0 {
		s.backoffDuration = time.Second
	} else {
		s.backoffDuration *= 2
		if s.backoffDuration > 60*time.Second {
			s.backoffDuration = 60 * time.Second
		}
	}
	c.logger.Warn("ClickHouse connection failed, next retry after back-off",
		zap.String("instance", s.inst.Name),
		zap.Duration("backoff", s.backoffDuration),
	)
}

// instanceLabels builds the common label set for a given instance state.
func instanceLabels(s *instanceState) map[string]string {
	return map[string]string{
		"clickhouse_instance": s.inst.Name,
		"clickhouse_cluster":  s.inst.ClusterName,
		"clickhouse_host":     s.inst.Host,
		"clickhouse_shard":    fmt.Sprintf("%d", s.inst.ShardNum),
		"clickhouse_replica":  s.inst.ReplicaName,
	}
}

// collectInstance runs all system-metric sub-collectors for a single instance.
func (c *ClickHouseCollector) collectInstance(ctx context.Context, s *instanceState) ([]collector.Metric, error) {
	conn, err := c.ensureConnection(ctx, s)
	if err != nil {
		return nil, err
	}

	labels := instanceLabels(s)
	var all []collector.Metric

	// System metrics (metrics, events, async_metrics)
	sysMetrics, newEvents, err := collectSystemMetrics(ctx, conn, labels, s.prevEvents, c.logger)
	if err != nil {
		c.logger.Warn("system metrics failed", zap.String("instance", s.inst.Name), zap.Error(err))
	} else {
		s.prevEvents = newEvents
		all = append(all, sysMetrics...)
	}

	// MergeTree: parts, merges, mutations
	mtMetrics, err := collectMergeTree(ctx, conn, labels, c.logger)
	if err != nil {
		c.logger.Warn("mergetree metrics failed", zap.String("instance", s.inst.Name), zap.Error(err))
	} else {
		all = append(all, mtMetrics...)
	}

	// Replication
	replMetrics, err := collectReplication(ctx, conn, labels, c.logger)
	if err != nil {
		c.logger.Warn("replication metrics failed", zap.String("instance", s.inst.Name), zap.Error(err))
	} else {
		all = append(all, replMetrics...)
	}

	// Storage
	storMetrics, err := collectStorage(ctx, conn, labels, c.logger)
	if err != nil {
		c.logger.Warn("storage metrics failed", zap.String("instance", s.inst.Name), zap.Error(err))
	} else {
		all = append(all, storMetrics...)
	}

	// Dictionaries
	dictMetrics, err := collectDictionaries(ctx, conn, labels, c.logger)
	if err != nil {
		c.logger.Warn("dictionaries metrics failed", zap.String("instance", s.inst.Name), zap.Error(err))
	} else {
		all = append(all, dictMetrics...)
	}

	c.logger.Debug("ClickHouse instance collected",
		zap.String("instance", s.inst.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

// collectQueryLogInstance runs the query-log collector for a single instance.
func (c *ClickHouseCollector) collectQueryLogInstance(ctx context.Context, s *instanceState) ([]collector.Metric, error) {
	conn, err := c.ensureConnection(ctx, s)
	if err != nil {
		return nil, err
	}

	labels := instanceLabels(s)
	metrics, newWatermark, err := collectQueryLog(
		ctx, conn, labels,
		s.queryLogWatermark, c.cfg.MaxQueryLogRows, c.logger,
	)
	if err != nil {
		return nil, err
	}
	s.queryLogWatermark = newWatermark
	return metrics, nil
}
