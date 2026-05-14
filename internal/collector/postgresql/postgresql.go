// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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

package postgresql

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "postgresql"

type PostgreSQLCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*pgInstance
}

func NewPostgreSQLCollector(cfg config.PostgreSQLCollectorConfig, logger *zap.Logger) *PostgreSQLCollector {
	c := NewConfig(cfg)

	instances := make([]*pgInstance, len(c.Instances))
	for i, inst := range c.Instances {
		instances[i] = &pgInstance{
			config:          inst,
			prevCounters:    make(map[string]uint64),
			topQueriesLimit: c.TopQueriesLimit,
			topTablesLimit:  c.TopTablesLimit,
		}
	}

	return &PostgreSQLCollector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		instances: instances,
	}
}

func (c *PostgreSQLCollector) Name() string { return collectorName }

func (c *PostgreSQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *PostgreSQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("postgresql collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("PostgreSQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("instance_interval", c.cfg.InstanceInterval),
		zap.Duration("query_interval", c.cfg.QueryInterval),
		zap.Duration("table_interval", c.cfg.TableInterval),
	)

	instanceTicker := time.NewTicker(c.cfg.InstanceInterval)
	queryTicker := time.NewTicker(c.cfg.QueryInterval)
	tableTicker := time.NewTicker(c.cfg.TableInterval)
	defer instanceTicker.Stop()
	defer queryTicker.Stop()
	defer tableTicker.Stop()

	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial instance collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return c.Stop()
		case <-c.stopChan:
			return nil
		case <-instanceTicker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("Instance collection failed", zap.Error(err))
			}
		case <-queryTicker.C:
			if metrics, err := c.collectAllQueryAnalytics(ctx); err != nil {
				c.logger.Warn("Query analytics collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Query analytics collected", zap.Int("metrics", len(metrics)))
			}
		case <-tableTicker.C:
			if metrics, err := c.collectAllSchema(ctx); err != nil {
				c.logger.Warn("Table stats collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Table stats collected", zap.Int("metrics", len(metrics)))
			}
		}
	}
}

func (c *PostgreSQLCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("PostgreSQL collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		c.closeConnection(inst)
	}
	return nil
}

func (c *PostgreSQLCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.instances) == 0 {
		return nil, nil
	}

	type result struct {
		metrics []collector.Metric
		err     error
		idx     int
	}

	results := make([]result, len(c.instances))
	var wg sync.WaitGroup

	for i, inst := range c.instances {
		wg.Add(1)
		go func(idx int, in *pgInstance) {
			defer wg.Done()
			m, err := c.collectInstance(ctx, in)
			results[idx] = result{metrics: m, err: err, idx: idx}
		}(i, inst)
	}
	wg.Wait()

	var all []collector.Metric
	for _, r := range results {
		if r.err != nil {
			c.logger.Warn("Collection failed for instance",
				zap.String("instance", c.instances[r.idx].config.Name),
				zap.Error(r.err),
			)
			continue
		}
		all = append(all, r.metrics...)
	}
	return all, nil
}

func (c *PostgreSQLCollector) collectInstance(ctx context.Context, inst *pgInstance) ([]collector.Metric, error) {
	pool, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	if inst.version == 0 {
		if err := detectVersion(ctx, inst); err != nil {
			c.logger.Debug("Version detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
	}

	labels := instanceLabels(inst)
	var all []collector.Metric

	instanceMetrics, err := collectInstanceMetrics(ctx, pool, inst, labels, c.logger)
	if err != nil {
		c.logger.Warn("Instance metrics collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, instanceMetrics...)
	}

	replicationMetrics, err := collectReplicationMetrics(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("Replication metrics collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, replicationMetrics...)
	}

	lockMetrics, err := collectLockMetrics(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("Lock metrics collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, lockMetrics...)
	}

	vacuumMetrics, err := collectVacuumMetrics(ctx, pool, inst, labels, c.logger)
	if err != nil {
		c.logger.Debug("Vacuum metrics collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, vacuumMetrics...)
	}

	c.logger.Debug("PostgreSQL instance collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *PostgreSQLCollector) collectAllQueryAnalytics(ctx context.Context) ([]collector.Metric, error) {
	if !c.cfg.CollectPgStatStatements {
		return nil, nil
	}

	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectQueryAnalytics(ctx, pool, inst, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Query analytics failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *PostgreSQLCollector) collectAllSchema(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectTableStats(ctx, pool, inst, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Table stats failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *PostgreSQLCollector) advanceBackoff(inst *pgInstance) {
	inst.lastConnErr = time.Now()
	if inst.backoff == 0 {
		inst.backoff = time.Second
	} else {
		inst.backoff *= 2
		if inst.backoff > 60*time.Second {
			inst.backoff = 60 * time.Second
		}
	}
}
