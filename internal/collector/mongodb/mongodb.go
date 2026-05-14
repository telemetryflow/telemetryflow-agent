package mongodb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "mongodb_community"

type MongoDBCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*mongoInstance
}

func NewMongoDBCollector(cfg config.MongoDBCommunityCollectorConfig, logger *zap.Logger) *MongoDBCollector {
	c := NewConfig(cfg)

	instances := make([]*mongoInstance, len(c.Instances))
	for i, inst := range c.Instances {
		instances[i] = &mongoInstance{
			config:       inst,
			prevCounters: make(map[string]float64),
		}
	}

	return &MongoDBCollector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		instances: instances,
	}
}

func (c *MongoDBCollector) Name() string { return collectorName }

func (c *MongoDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *MongoDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("mongodb_community collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("MongoDB Community collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("interval", c.cfg.Interval),
		zap.Duration("collstats_interval", c.cfg.CollStatsInterval),
	)

	mainTicker := time.NewTicker(c.cfg.Interval)
	collStatsTicker := time.NewTicker(c.cfg.CollStatsInterval)
	queryTicker := time.NewTicker(c.cfg.QueryInterval)
	defer mainTicker.Stop()
	defer collStatsTicker.Stop()
	defer queryTicker.Stop()

	// Initial collection
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return c.Stop()
		case <-c.stopChan:
			return nil
		case <-mainTicker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("Collection cycle failed", zap.Error(err))
			}
		case <-collStatsTicker.C:
			if metrics, err := c.collectAllCollStats(ctx); err != nil {
				c.logger.Warn("CollStats collection failed", zap.Error(err))
			} else {
				c.logger.Debug("CollStats collected", zap.Int("metrics", len(metrics)))
			}
		case <-queryTicker.C:
			if metrics, err := c.collectAllQueryMetrics(ctx); err != nil {
				c.logger.Warn("Query metrics collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Query metrics collected", zap.Int("metrics", len(metrics)))
			}
		}
	}
}

func (c *MongoDBCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("MongoDB Community collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		c.closeConnection(inst)
	}
	return nil
}

func (c *MongoDBCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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
		go func(idx int, in *mongoInstance) {
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

func (c *MongoDBCollector) collectInstance(ctx context.Context, inst *mongoInstance) ([]collector.Metric, error) {
	client, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	labels := instanceLabels(inst)
	var all []collector.Metric

	// serverStatus metrics
	if m, err := collectServerStatus(ctx, client, labels, c.logger); err != nil {
		c.logger.Debug("serverStatus collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// WiredTiger detail metrics
	if m, err := collectWiredTiger(ctx, client, labels, c.logger); err != nil {
		c.logger.Debug("WiredTiger collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// Replication metrics (only for replica sets)
	if inst.isReplicaSet {
		if m, err := collectReplication(ctx, client, labels, c.logger); err != nil {
			c.logger.Debug("Replication collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, m...)
		}
	}

	// Sharding metrics (only for mongos)
	if inst.isSharded {
		if m, err := collectSharding(ctx, client, labels, c.logger); err != nil {
			c.logger.Debug("Sharding collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, m...)
		}
	}

	// Current operations (db.currentOp)
	if m, err := collectCurrentOp(ctx, client, labels, c.logger); err != nil {
		c.logger.Debug("currentOp collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// Slow query profiler (system.profile)
	if m, err := collectSlowQueries(ctx, client, inst, labels, c.logger); err != nil {
		c.logger.Debug("Slow query profiler skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// Compute rate-based metrics from counters
	now := time.Now()
	if !inst.prevTime.IsZero() {
		elapsed := now.Sub(inst.prevTime).Seconds()
		all = append(all, computeRates(inst, elapsed, labels)...)
	}
	inst.prevTime = now

	c.logger.Debug("MongoDB instance collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *MongoDBCollector) collectAllQueryMetrics(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		client, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectQueryMetrics(ctx, client, inst, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Query metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *MongoDBCollector) collectAllCollStats(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		client, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectCollStats(ctx, client, inst, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("CollStats failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}
