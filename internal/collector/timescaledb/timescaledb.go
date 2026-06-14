package timescaledb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "timescaledb"

type TimescaleDBCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*tsdbInstance
}

func NewTimescaleDBCollector(cfg config.TimescaleDBCollectorConfig, logger *zap.Logger) *TimescaleDBCollector {
	c := NewConfig(cfg)

	instances := make([]*tsdbInstance, len(c.Instances))
	for i, inst := range c.Instances {
		instances[i] = &tsdbInstance{
			config: inst,
		}
	}

	return &TimescaleDBCollector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		instances: instances,
	}
}

func (c *TimescaleDBCollector) Name() string { return collectorName }

func (c *TimescaleDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *TimescaleDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("timescaledb collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("TimescaleDB collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)

	select {
	case <-c.stopChan:
		return nil
	case <-ctx.Done():
		return c.Stop()
	}
}

func (c *TimescaleDBCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("TimescaleDB collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		c.closeConnection(inst)
	}
	return nil
}

func (c *TimescaleDBCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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
		go func(idx int, in *tsdbInstance) {
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

	if cm, err := c.collectAllChunks(ctx); err != nil {
		c.logger.Warn("Chunk collection failed", zap.Error(err))
	} else {
		all = append(all, cm...)
	}

	if jm, err := c.collectAllJobs(ctx); err != nil {
		c.logger.Warn("Job collection failed", zap.Error(err))
	} else {
		all = append(all, jm...)
	}

	return all, nil
}

func (c *TimescaleDBCollector) collectInstance(ctx context.Context, inst *tsdbInstance) ([]collector.Metric, error) {
	pool, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	if inst.pgVersion == 0 {
		if err := detectPGVersion(ctx, inst); err != nil {
			c.logger.Debug("PG version detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
	}

	if inst.tsdbVer == "" {
		if err := detectTimescaleDB(ctx, inst); err != nil {
			c.logger.Debug("TimescaleDB detection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
		}
	}

	labels := instanceLabels(inst)
	var all []collector.Metric

	pgMetrics, err := collectPGBaseMetrics(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Warn("PG base metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, pgMetrics...)
	}

	htMetrics, err := collectHypertables(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("Hypertable metrics skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, htMetrics...)
	}

	compMetrics, err := collectCompression(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("Compression metrics skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, compMetrics...)
	}

	caggMetrics, err := collectContinuousAggregates(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("CAGG metrics skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, caggMetrics...)
	}

	retMetrics, err := collectRetention(ctx, pool, labels, c.logger)
	if err != nil {
		c.logger.Debug("Retention metrics skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, retMetrics...)
	}

	c.logger.Debug("TimescaleDB instance collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *TimescaleDBCollector) collectAllChunks(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectChunks(ctx, pool, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Chunk metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *TimescaleDBCollector) collectAllJobs(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectJobs(ctx, pool, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Job metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func detectPGVersion(ctx context.Context, inst *tsdbInstance) error {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var versionNum int
	err := inst.pool.QueryRow(ctx2, "SHOW server_version_num").Scan(&versionNum)
	if err != nil {
		return fmt.Errorf("timescaledb %s: detect PG version: %w", inst.config.Name, err)
	}
	inst.pgVersion = versionNum

	var versionStr string
	if err := inst.pool.QueryRow(ctx2, "SHOW server_version").Scan(&versionStr); err == nil {
		inst.pgVersionS = strings.TrimSpace(versionStr)
	} else {
		inst.pgVersionS = strconv.Itoa(versionNum)
	}
	return nil
}

func detectTimescaleDB(ctx context.Context, inst *tsdbInstance) error {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var version string
	err := inst.pool.QueryRow(ctx2,
		"SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'",
	).Scan(&version)
	if err != nil {
		return fmt.Errorf("timescaledb %s: extension not found: %w", inst.config.Name, err)
	}
	inst.tsdbVer = strings.TrimSpace(version)
	return nil
}
