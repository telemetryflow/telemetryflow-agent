package mssql

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "mssql"

type MSSQLCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*mssqlInstance
}

func NewMSSQLCollector(cfg config.MSSQLCollectorConfig, logger *zap.Logger) *MSSQLCollector {
	c := NewConfig(cfg)

	instances := make([]*mssqlInstance, len(c.Instances))
	for i, inst := range c.Instances {
		instances[i] = &mssqlInstance{
			config:       inst,
			prevCounters: make(map[string]float64),
		}
	}

	return &MSSQLCollector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		instances: instances,
	}
}

func (c *MSSQLCollector) Name() string { return collectorName }

func (c *MSSQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *MSSQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("mssql collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("MSSQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("metrics_interval", c.cfg.MetricsInterval),
		zap.Duration("query_interval", c.cfg.QueryInterval),
		zap.Duration("index_interval", c.cfg.IndexInterval),
	)

	metricsTicker := time.NewTicker(c.cfg.MetricsInterval)
	queryTicker := time.NewTicker(c.cfg.QueryInterval)
	indexTicker := time.NewTicker(c.cfg.IndexInterval)
	defer metricsTicker.Stop()
	defer queryTicker.Stop()
	defer indexTicker.Stop()

	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial metrics collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return c.Stop()
		case <-c.stopChan:
			return nil
		case <-metricsTicker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("Metrics collection failed", zap.Error(err))
			}
		case <-queryTicker.C:
			if metrics, err := c.collectAllQueries(ctx); err != nil {
				c.logger.Warn("Query analytics collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Query analytics collected", zap.Int("metrics", len(metrics)))
			}
		case <-indexTicker.C:
			if metrics, err := c.collectAllIndexes(ctx); err != nil {
				c.logger.Warn("Index stats collection failed", zap.Error(err))
			} else {
				c.logger.Debug("Index stats collected", zap.Int("metrics", len(metrics)))
			}
		}
	}
}

func (c *MSSQLCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("MSSQL collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		c.closeConnection(inst)
	}
	return nil
}

func (c *MSSQLCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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
		go func(idx int, in *mssqlInstance) {
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

func (c *MSSQLCollector) collectInstance(ctx context.Context, inst *mssqlInstance) ([]collector.Metric, error) {
	db, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	if inst.version == "" {
		if err := detectVersion(ctx, db, inst, c.logger); err != nil {
			c.logger.Debug("Version detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
	}

	labels := instanceLabels(inst)
	var all []collector.Metric

	perfMetrics, err := collectPerfCounters(ctx, db, inst, labels, c.logger)
	if err != nil {
		c.logger.Warn("Perf counter collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, perfMetrics...)
	}

	waitMetrics, err := collectWaitStats(ctx, db, labels, c.logger)
	if err != nil {
		c.logger.Warn("Wait stats collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, waitMetrics...)
	}

	ioMetrics, err := collectFileIO(ctx, db, inst, labels, c.logger)
	if err != nil {
		c.logger.Warn("File I/O collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, ioMetrics...)
	}

	tempDBMetrics, err := collectTempDB(ctx, db, labels, c.logger)
	if err != nil {
		c.logger.Debug("TempDB collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, tempDBMetrics...)
	}

	if c.cfg.CollectAGStatus {
		agMetrics, err := collectAGStatus(ctx, db, labels, c.logger)
		if err != nil {
			c.logger.Debug("AG status collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, agMetrics...)
		}
	}

	if c.cfg.CollectAgentJobs {
		jobMetrics, err := collectAgentJobs(ctx, db, labels, c.logger)
		if err != nil {
			c.logger.Debug("Agent jobs collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, jobMetrics...)
		}
	}

	c.logger.Debug("MSSQL instance collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *MSSQLCollector) collectAllQueries(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		db, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		labels := instanceLabels(inst)

		queryMetrics, err := collectQueryStats(ctx, db, labels, c.logger)
		if err != nil {
			c.logger.Warn("Query stats failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, queryMetrics...)
		}

		if c.cfg.CollectQueryStore {
			qsMetrics, err := collectQueryStore(ctx, db, labels, c.logger)
			if err != nil {
				c.logger.Debug("Query Store collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
			} else {
				all = append(all, qsMetrics...)
			}
		}

		if inst.engineEdition == 5 || inst.engineEdition == 6 {
			azureMetrics, err := collectAzureSQLDBMetrics(ctx, db, labels, c.logger)
			if err != nil {
				c.logger.Debug("Azure SQL metrics skipped", zap.String("instance", inst.config.Name), zap.Error(err))
			} else {
				all = append(all, azureMetrics...)
			}
		}
	}
	return all, nil
}

func (c *MSSQLCollector) collectAllIndexes(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		db, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}

		if !c.cfg.CollectIndexStats {
			continue
		}

		idxMetrics, err := collectIndexStats(ctx, db, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Index stats failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, idxMetrics...)
	}
	return all, nil
}
