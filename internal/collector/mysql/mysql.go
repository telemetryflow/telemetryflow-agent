// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
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

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "mysql"

type MySQLCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*mysqlInstance
}

func NewMySQLCollector(cfg config.MySQLCollectorConfig, logger *zap.Logger) *MySQLCollector {
	c := NewConfig(cfg)

	instances := make([]*mysqlInstance, len(c.Instances))
	for i, inst := range c.Instances {
		instances[i] = &mysqlInstance{
			config:      inst,
			prevStatus:  make(map[string]uint64),
			prevDigests: make(map[string]*digestSnapshot),
		}
	}

	return &MySQLCollector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		instances: instances,
	}
}

func (c *MySQLCollector) Name() string { return collectorName }

func (c *MySQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *MySQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("mysql collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("MySQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)

	select {
	case <-c.stopChan:
		return nil
	case <-ctx.Done():
		return c.Stop()
	}
}

func (c *MySQLCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("MySQL collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		if inst.db != nil {
			_ = inst.db.Close()
			inst.db = nil
		}
	}
	return nil
}

func (c *MySQLCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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
		go func(idx int, in *mysqlInstance) {
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

	if qm, err := c.collectAllQueryAnalytics(ctx); err != nil {
		c.logger.Warn("Query analytics collection failed", zap.Error(err))
	} else {
		all = append(all, qm...)
	}

	if sm, err := c.collectAllSchema(ctx); err != nil {
		c.logger.Warn("Schema collection failed", zap.Error(err))
	} else {
		all = append(all, sm...)
	}

	return all, nil
}

func (c *MySQLCollector) collectInstance(ctx context.Context, inst *mysqlInstance) ([]collector.Metric, error) {
	db, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	if err := c.detectFlavor(ctx, inst, db); err != nil {
		c.logger.Debug("Flavor detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	}

	labels := instanceLabels(inst)
	var all []collector.Metric

	now := time.Now()
	elapsed := now.Sub(inst.prevTimestamp)
	if elapsed <= 0 {
		elapsed = c.cfg.StatusInterval
	}

	status, rawStatus, err := collectGlobalStatus(ctx, db)
	if err != nil {
		c.logger.Warn("SHOW GLOBAL STATUS failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		if len(inst.prevStatus) > 0 {
			rateMetrics := computeRates(inst.prevStatus, rawStatus, elapsed.Seconds(), labels)
			all = append(all, rateMetrics...)
		}
		all = append(all, emitGaugeMetrics(rawStatus, status, labels)...)
		inst.prevStatus = rawStatus
	}

	vars, err := collectGlobalVariables(ctx, db)
	if err != nil {
		c.logger.Warn("SHOW GLOBAL VARIABLES failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, emitVariableMetrics(vars, labels)...)
	}

	innodbMetrics, err := collectInnoDBStatus(ctx, db, labels)
	if err != nil {
		c.logger.Warn("SHOW ENGINE INNODB STATUS failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, innodbMetrics...)
	}

	replMetrics, err := collectReplicationStatus(ctx, db, labels)
	if err != nil {
		c.logger.Debug("SHOW SLAVE/REPLICA STATUS failed (may not be a replica)", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, replMetrics...)
	}

	galeraMetrics, err := collectGaleraStatus(ctx, db, labels)
	if err != nil {
		c.logger.Debug("Galera status collection skipped", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, galeraMetrics...)
	}

	derivedMetrics := computeDerivedMetrics(rawStatus, vars, labels)
	all = append(all, derivedMetrics...)

	if inst.flavor == "mariadb" {
		mariaMetrics := c.collectMariaDB(ctx, inst, db, labels, vars)
		all = append(all, mariaMetrics...)
	}

	if inst.flavor == "percona" {
		perconaMetrics := c.collectPercona(ctx, inst, db, labels, vars, rawStatus)
		all = append(all, perconaMetrics...)
	}

	inst.prevTimestamp = now

	c.logger.Debug("MySQL instance collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *MySQLCollector) collectAllQueryAnalytics(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		db, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectQueryAnalytics(ctx, db, inst, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Query analytics failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *MySQLCollector) collectAllSchema(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		db, err := c.ensureConnection(ctx, inst)
		if err != nil {
			continue
		}
		metrics, err := collectSchema(ctx, db, inst.config, instanceLabels(inst), c.logger)
		if err != nil {
			c.logger.Warn("Schema collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *MySQLCollector) collectMariaDB(ctx context.Context, inst *mysqlInstance, db *sql.DB, labels map[string]string, vars map[string]string) []collector.Metric {
	if inst.mariadb == nil {
		inst.mariadb = initMariaDBExtension()
		if err := detectMariaDBEngines(ctx, db, inst.mariadb); err != nil {
			c.logger.Debug("MariaDB engine detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
		if err := detectMariaDBPlugins(ctx, db, inst.mariadb, vars); err != nil {
			c.logger.Debug("MariaDB plugin detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
	}

	var all []collector.Metric

	if inst.mariadb.queryCacheEnabled {
		if metrics, err := collectMariaDBQueryCache(ctx, db, labels); err != nil {
			c.logger.Debug("MariaDB query cache collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.mariadb.ariaStatsEnabled {
		if metrics, err := collectMariaDBAria(ctx, db, labels); err != nil {
			c.logger.Debug("MariaDB Aria collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.mariadb.columnStoreStatsEnabled {
		if metrics, err := collectMariaDBColumnStore(ctx, db, labels); err != nil {
			c.logger.Debug("MariaDB ColumnStore collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.mariadb.spiderStatsEnabled {
		if metrics, err := collectMariaDBSpider(ctx, db, labels); err != nil {
			c.logger.Debug("MariaDB Spider collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.mariadb.threadPoolStatsEnabled {
		if metrics, err := collectMariaDBThreadPool(ctx, db, labels); err != nil {
			c.logger.Debug("MariaDB thread pool collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if metrics, err := collectMariaDBMultiSourceReplication(ctx, db, labels); err != nil {
		c.logger.Debug("MariaDB multi-source replication collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, metrics...)
	}

	if inst.mariadb.userStatsEnabled {
		if metrics, err := collectMariaDBUserStats(ctx, db, labels); err != nil {
			c.logger.Debug("MariaDB user stats collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	return all
}

func (c *MySQLCollector) ensureConnection(ctx context.Context, inst *mysqlInstance) (*sql.DB, error) {
	if inst.db != nil {
		if err := inst.db.PingContext(ctx); err == nil {
			return inst.db, nil
		}
		_ = inst.db.Close()
		inst.db = nil
	}

	if !inst.lastConnErr.IsZero() {
		wait := inst.backoff
		if wait == 0 {
			wait = time.Second
		}
		if time.Since(inst.lastConnErr) < wait {
			return nil, fmt.Errorf("mysql %s: in back-off (retry in %s)",
				inst.config.Name, (wait - time.Since(inst.lastConnErr)).Round(time.Millisecond))
		}
	}

	dsn := buildDSN(inst.config)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("mysql %s: open: %w", inst.config.Name, err)
	}

	db.SetMaxOpenConns(inst.config.MaxOpenConns)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx2); err != nil {
		_ = db.Close()
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("mysql %s: ping: %w", inst.config.Name, err)
	}

	inst.db = db
	inst.backoff = 0
	inst.lastConnErr = time.Time{}
	c.logger.Info("Connected to MySQL instance",
		zap.String("instance", inst.config.Name),
		zap.String("host", inst.config.Host),
		zap.Int("port", inst.config.Port),
	)
	return db, nil
}

func (c *MySQLCollector) advanceBackoff(inst *mysqlInstance) {
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

func (c *MySQLCollector) detectFlavor(ctx context.Context, inst *mysqlInstance, db *sql.DB) error {
	var versionStr string
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.QueryRowContext(ctx2, "SELECT VERSION()").Scan(&versionStr); err != nil {
		return err
	}
	inst.version = versionStr
	vLower := strings.ToLower(versionStr)
	switch {
	case strings.Contains(vLower, "mariadb"):
		inst.flavor = "mariadb"
	case strings.Contains(vLower, "percona"):
		inst.flavor = "percona"
	default:
		inst.flavor = "mysql"
	}
	return nil
}

func buildDSN(cfg config.MySQLInstanceConfig) string {
	host := cfg.Host
	port := cfg.Port
	if port == 0 {
		port = 3306
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)", cfg.Username, cfg.Password, host, port)
	if cfg.Database != "" {
		dsn += "/" + cfg.Database
	} else {
		dsn += "/"
	}
	params := []string{"parseTime=true", "timeout=10s"}
	if cfg.TLSEnabled {
		if cfg.TLSSkipVerify {
			params = append(params, "tls=skip-verify")
		} else {
			params = append(params, "tls=true")
		}
	}
	dsn += "?" + strings.Join(params, "&")
	return dsn
}

func instanceLabels(inst *mysqlInstance) map[string]string {
	labels := map[string]string{
		"mysql_instance": inst.config.Name,
		"mysql_host":     inst.config.Host,
	}
	if inst.flavor != "" {
		labels["mysql_flavor"] = inst.flavor
	}
	if inst.version != "" {
		labels["mysql_version"] = inst.version
	}
	for k, v := range inst.config.Tags {
		labels[k] = v
	}
	return labels
}

func makeMetric(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	m := collector.Metric{
		Name:      name,
		Type:      mtype,
		Value:     value,
		Timestamp: time.Now(),
		Labels:    make(map[string]string, len(labels)),
	}
	for k, v := range labels {
		m.Labels[k] = v
	}
	return m
}

func safeDiv(num, denom float64) float64 {
	if denom == 0 {
		return 0
	}
	return num / denom
}

type nilStr struct{}

func (nilStr) Scan(interface{}) error { return nil }

func parseUint(val string) uint64 {
	var n uint64
	for _, ch := range val {
		if ch >= '0' && ch <= '9' {
			n = n*10 + uint64(ch-'0')
		} else {
			break
		}
	}
	return n
}

func parseFloat(val string) float64 {
	var f float64
	_, _ = fmt.Sscanf(val, "%f", &f)
	return f
}

func emitCounterRate(name string, rate float64, labels map[string]string) collector.Metric {
	if math.IsNaN(rate) || math.IsInf(rate, 0) {
		rate = 0
	}
	return makeMetric(name, rate, collector.MetricTypeGauge, labels)
}
