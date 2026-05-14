package cockroachdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "cockroachdb"

type CockroachDBCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*crdbInstance
}

func NewCockroachDBCollector(cfg config.CockroachDBCollectorConfig, logger *zap.Logger) *CockroachDBCollector {
	c := NewConfig(cfg)

	instances := make([]*crdbInstance, len(c.Instances))
	for i, inst := range c.Instances {
		instances[i] = &crdbInstance{
			config:        inst,
			prevCounters:  make(map[string]uint64),
			topStmtsLimit: c.TopStatementsLimit,
		}
	}

	return &CockroachDBCollector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		instances: instances,
	}
}

func (c *CockroachDBCollector) Name() string { return collectorName }

func (c *CockroachDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *CockroachDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("cockroachdb collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("CockroachDB collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("instance_interval", c.cfg.InstanceInterval),
		zap.Duration("query_interval", c.cfg.QueryInterval),
		zap.Duration("range_interval", c.cfg.RangeInterval),
	)

	instanceTicker := time.NewTicker(c.cfg.InstanceInterval)
	queryTicker := time.NewTicker(c.cfg.QueryInterval)
	rangeTicker := time.NewTicker(c.cfg.RangeInterval)
	defer instanceTicker.Stop()
	defer queryTicker.Stop()
	defer rangeTicker.Stop()

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
			if metrics, err := c.collectAllQueries(ctx); err != nil {
				c.logger.Warn("Query analytics collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Query analytics collected", zap.Int("metrics", len(metrics)))
			}
		case <-rangeTicker.C:
			if metrics, err := c.collectAllRanges(ctx); err != nil {
				c.logger.Warn("Range metrics collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Range metrics collected", zap.Int("metrics", len(metrics)))
			}
		}
	}
}

func (c *CockroachDBCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("CockroachDB collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		c.closeConnection(inst)
	}
	return nil
}

func (c *CockroachDBCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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
		go func(idx int, in *crdbInstance) {
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

func (c *CockroachDBCollector) collectInstance(ctx context.Context, inst *crdbInstance) ([]collector.Metric, error) {
	pool, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	if inst.version == "" {
		if err := detectVersion(ctx, pool, inst, c.logger); err != nil {
			c.logger.Debug("Version detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
	}

	labels := instanceLabels(inst)
	var all []collector.Metric

	nodeMetrics, err := collectNodeMetrics(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Warn("Node metrics collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, nodeMetrics...)
	}

	sqlMetrics, err := collectSQLMetrics(ctx, pool, inst, labels, c.logger)
	if err != nil {
		c.logger.Warn("SQL metrics collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, sqlMetrics...)
	}

	storeMetrics, err := collectStoreMetrics(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("Store metrics collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, storeMetrics...)
	}

	c.logger.Debug("CockroachDB instance collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *CockroachDBCollector) collectAllQueries(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectStatementStats(ctx, pool, inst, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Statement stats failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *CockroachDBCollector) collectAllRanges(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectRangeMetrics(ctx, pool, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Range metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}
