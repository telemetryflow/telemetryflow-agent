// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const rdsCollectorName = "rds_postgresql"

// RDSPostgreSQLCollector implements the collector.Collector interface for AWS RDS
// PostgreSQL instances. It extends the standard PostgreSQL collector with:
//   - TLS connections using the AWS RDS CA bundle
//   - RDS-optimized collection intervals (15s activity, 60s queries/tables)
//   - pg_stat_statements, pg_stat_activity, pg_stat_database, pg_stat_bgwriter,
//     pg_stat_replication, pg_stat_wal, pg_stat_user_tables, and pg_locks
//   - Structured output for the platform's AgentMetricsPayload interface
type RDSPostgreSQLCollector struct {
	cfg    config.RDSPostgreSQLCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	instances []*rdsPgInstance
}

// rdsPgInstance holds per-instance state for an RDS PostgreSQL connection.
type rdsPgInstance struct {
	config          config.RDSPostgreSQLInstanceConfig
	pool            *pgxpool.Pool
	version         int
	versionStr      string
	prevCounters    map[string]uint64
	prevTimestamp   time.Time
	backoff         time.Duration
	lastConnErr     time.Time
	topQueriesLimit int

	reporter *RDSPostgresReporter
}

// NewRDSPostgreSQLCollector creates a new RDS PostgreSQL collector.
func NewRDSPostgreSQLCollector(cfg config.RDSPostgreSQLCollectorConfig, logger *zap.Logger) *RDSPostgreSQLCollector {
	if cfg.ActivityInterval == 0 {
		cfg.ActivityInterval = 15 * time.Second
	}
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 60 * time.Second
	}
	if cfg.TableStatsInterval == 0 {
		cfg.TableStatsInterval = 60 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 3
	}
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}

	instances := make([]*rdsPgInstance, len(cfg.Instances))
	for i := range cfg.Instances {
		applyRDSInstanceDefaults(&cfg.Instances[i])

		reporter := NewRDSPostgresReporter(cfg.PlatformEndpoint, cfg.PlatformAPIKeyID, cfg.PlatformAPIKeySecret, logger)

		instances[i] = &rdsPgInstance{
			config:          cfg.Instances[i],
			prevCounters:    make(map[string]uint64),
			topQueriesLimit: cfg.TopQueriesLimit,
			reporter:        reporter,
		}
	}

	return &RDSPostgreSQLCollector{
		cfg:       cfg,
		logger:    logger.Named(rdsCollectorName),
		instances: instances,
	}
}

func applyRDSInstanceDefaults(inst *config.RDSPostgreSQLInstanceConfig) {
	if inst.Port == 0 {
		inst.Port = 5432
	}
	if inst.User == "" {
		inst.User = "postgres"
	}
	if inst.DBName == "" {
		inst.DBName = "postgres"
	}
}

// Name returns the collector name.
func (c *RDSPostgreSQLCollector) Name() string { return rdsCollectorName }

// IsRunning returns whether the collector is running.
func (c *RDSPostgreSQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start starts the collector and begins collecting metrics.
func (c *RDSPostgreSQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("rds_postgresql collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("RDS PostgreSQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("activity_interval", c.cfg.ActivityInterval),
		zap.Duration("query_interval", c.cfg.QueryInterval),
		zap.Duration("table_stats_interval", c.cfg.TableStatsInterval),
	)

	activityTicker := time.NewTicker(c.cfg.ActivityInterval)
	queryTicker := time.NewTicker(c.cfg.QueryInterval)
	tableTicker := time.NewTicker(c.cfg.TableStatsInterval)
	defer activityTicker.Stop()
	defer queryTicker.Stop()
	defer tableTicker.Stop()

	// Initial collection
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial activity collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return c.Stop()
		case <-c.stopChan:
			return nil
		case <-activityTicker.C:
			if metrics, err := c.collectAllActivity(ctx); err != nil {
				c.logger.Warn("Activity collection failed", zap.Error(err))
			} else {
				c.submitMetrics(ctx, metrics)
			}
		case <-queryTicker.C:
			if metrics, err := c.collectAllQueryAnalytics(ctx); err != nil {
				c.logger.Warn("Query analytics collection failed", zap.Error(err))
			} else {
				c.submitMetrics(ctx, metrics)
			}
		case <-tableTicker.C:
			if metrics, err := c.collectAllTableStats(ctx); err != nil {
				c.logger.Warn("Table stats collection failed", zap.Error(err))
			} else {
				c.submitMetrics(ctx, metrics)
			}
		}
	}
}

// Stop gracefully stops the collector.
func (c *RDSPostgreSQLCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("RDS PostgreSQL collector stopping")
	c.running = false
	close(c.stopChan)

	for _, inst := range c.instances {
		if inst.pool != nil {
			inst.pool.Close()
			inst.pool = nil
		}
	}
	return nil
}

// Collect performs a single collection cycle (activity + status metrics).
func (c *RDSPostgreSQLCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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
		go func(idx int, in *rdsPgInstance) {
			defer wg.Done()
			m, err := c.collectActivity(ctx, in)
			results[idx] = result{metrics: m, err: err, idx: idx}
		}(i, inst)
	}
	wg.Wait()

	var all []collector.Metric
	for _, r := range results {
		if r.err != nil {
			c.logger.Warn("Activity collection failed for instance",
				zap.String("instance", c.instances[r.idx].config.Name),
				zap.Error(r.err),
			)
			continue
		}
		all = append(all, r.metrics...)
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// RDS TLS Connection
// ---------------------------------------------------------------------------

// buildRDSConnString builds a PostgreSQL DSN for RDS with SSL mode.
func buildRDSConnString(cfg config.RDSPostgreSQLInstanceConfig) string {
	password := resolveEnvVars(cfg.Password)
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=require",
		cfg.User, password, cfg.Host, cfg.Port, cfg.DBName,
	)
	return dsn
}

// rdsTLSConfig builds a TLS configuration for RDS connections.
// It loads the RDS CA bundle from the specified path or attempts well-known locations.
func rdsTLSConfig(caBundlePath string) (*tls.Config, error) {
	var caPaths []string
	if caBundlePath != "" {
		caPaths = []string{caBundlePath}
	} else {
		// Common RDS CA bundle locations
		caPaths = []string{
			"/etc/ssl/certs/rds-combined-ca-bundle.pem",
			"/etc/pki/tls/certs/rds-combined-ca-bundle.pem",
			"/etc/ssl/certs/rds-ca-2019-root.pem",
		}
	}

	var lastErr error
	for _, path := range caPaths {
		caCert, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			continue
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			lastErr = fmt.Errorf("failed to append CA certs from %s", path)
			continue
		}
		return &tls.Config{
			RootCAs:            caCertPool,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}, nil
	}

	// Fallback to system default CA pool (works if RDS certs are in system trust store)
	return nil, fmt.Errorf("RDS CA bundle not found: %v", lastErr)
}

// ensureRDSConnection establishes or reuses a connection pool for an RDS instance.
func (c *RDSPostgreSQLCollector) ensureRDSConnection(ctx context.Context, inst *rdsPgInstance) (*pgxpool.Pool, error) {
	if inst.pool != nil {
		if err := inst.pool.Ping(ctx); err == nil {
			return inst.pool, nil
		}
		inst.pool.Close()
		inst.pool = nil
	}

	if !inst.lastConnErr.IsZero() {
		wait := inst.backoff
		if wait == 0 {
			wait = time.Second
		}
		if time.Since(inst.lastConnErr) < wait {
			return nil, fmt.Errorf("rds_postgresql %s: in back-off (retry in %s)",
				inst.config.Name, (wait - time.Since(inst.lastConnErr)).Round(time.Millisecond))
		}
	}

	dsn := buildRDSConnString(inst.config)
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		c.advanceRDSBackoff(inst)
		return nil, fmt.Errorf("rds_postgresql %s: parse config: %w", inst.config.Name, err)
	}
	poolCfg.MaxConns = int32(c.cfg.MaxConnections)
	poolCfg.MinConns = 1
	poolCfg.MaxConnLifetime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second

	// Configure TLS for RDS
	tlsCfg, tlsErr := rdsTLSConfig(inst.config.RDSCABundlePath)
	if tlsErr != nil {
		c.logger.Warn("RDS CA bundle not found, falling back to system CA pool",
			zap.String("instance", inst.config.Name),
			zap.Error(tlsErr),
		)
		// Continue without custom TLS -- system CA pool may include RDS certs
	} else {
		poolCfg.ConnConfig.TLSConfig = tlsCfg
	}

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx2, poolCfg)
	if err != nil {
		c.advanceRDSBackoff(inst)
		return nil, fmt.Errorf("rds_postgresql %s: create pool: %w", inst.config.Name, err)
	}

	if err := pool.Ping(ctx2); err != nil {
		pool.Close()
		c.advanceRDSBackoff(inst)
		return nil, fmt.Errorf("rds_postgresql %s: ping: %w", inst.config.Name, err)
	}

	inst.pool = pool
	inst.backoff = 0
	inst.lastConnErr = time.Time{}
	c.logger.Info("Connected to RDS PostgreSQL instance",
		zap.String("instance", inst.config.Name),
		zap.String("host", inst.config.Host),
		zap.Int("port", inst.config.Port),
		zap.String("region", inst.config.Region),
	)
	return pool, nil
}

func (c *RDSPostgreSQLCollector) advanceRDSBackoff(inst *rdsPgInstance) {
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

// ---------------------------------------------------------------------------
// Label Helpers
// ---------------------------------------------------------------------------

func rdsInstanceLabels(inst *rdsPgInstance) map[string]string {
	labels := map[string]string{
		"postgresql_instance": inst.config.Name,
		"postgresql_host":     inst.config.Host,
		"rds_instance_id":     inst.config.InstanceID,
		"rds_region":          inst.config.Region,
		"cloud_provider":      "aws",
		"db_system":           "rds_postgresql",
	}
	if inst.versionStr != "" {
		labels["postgresql_version"] = inst.versionStr
	}
	for k, v := range inst.config.Tags {
		labels[k] = v
	}
	return labels
}

// ---------------------------------------------------------------------------
// Activity Collection (15s interval)
// pg_stat_activity, pg_stat_database, pg_stat_bgwriter, pg_locks
// ---------------------------------------------------------------------------

func (c *RDSPostgreSQLCollector) collectActivity(ctx context.Context, inst *rdsPgInstance) ([]collector.Metric, error) {
	pool, err := c.ensureRDSConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	if inst.version == 0 {
		_ = detectRDSVersion(ctx, inst, pool, c.logger)
	}

	labels := rdsInstanceLabels(inst)
	var all []collector.Metric

	// pg_stat_activity: connection states, max_connections
	connMetrics, err := collectRDSConnectionMetrics(ctx, pool, inst, labels)
	if err != nil {
		c.logger.Debug("RDS connection metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, connMetrics...)
	}

	// pg_stat_database: per-database xact_commit/rollback, blks, deadlocks
	dbMetrics, err := collectRDSTransactionMetrics(ctx, pool, inst, labels)
	if err != nil {
		c.logger.Debug("RDS transaction metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, dbMetrics...)
	}

	// pg_stat_bgwriter: checkpoint stats, buffer stats
	bgMetrics, err := collectRDSBgWriterMetrics(ctx, pool, labels)
	if err != nil {
		c.logger.Debug("RDS bgwriter metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, bgMetrics...)
	}

	// pg_stat_wal: WAL records, bytes, buffers, sync time (PostgreSQL 14+)
	if hasRDSWalStats(inst) {
		walMetrics, err := collectRDSWALMetrics(ctx, pool, labels)
		if err != nil {
			c.logger.Debug("RDS WAL metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, walMetrics...)
		}
	}

	// pg_locks: count by type and mode
	lockMetrics, err := collectRDSLockMetrics(ctx, pool, labels)
	if err != nil {
		c.logger.Debug("RDS lock metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, lockMetrics...)
	}

	// pg_stat_replication: per-replica lag, LSN positions, slot names
	if c.cfg.CollectReplication {
		replMetrics, err := collectRDSReplicationMetrics(ctx, pool, labels, c.logger)
		if err != nil {
			c.logger.Debug("RDS replication metrics skipped", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, replMetrics...)
		}
	}

	// pg_database_size: per-database size
	sizeMetrics, err := collectRDSDatabaseSizeMetrics(ctx, pool, labels)
	if err != nil {
		c.logger.Debug("RDS database size metrics failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, sizeMetrics...)
	}

	c.logger.Debug("RDS PostgreSQL activity collected",
		zap.String("instance", inst.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *RDSPostgreSQLCollector) collectAllActivity(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, inst := range c.instances {
		metrics, err := c.collectActivity(ctx, inst)
		if err != nil {
			c.logger.Warn("Activity collection failed",
				zap.String("instance", inst.config.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// Query Analytics Collection (60s interval)
// pg_stat_statements
// ---------------------------------------------------------------------------

func (c *RDSPostgreSQLCollector) collectAllQueryAnalytics(ctx context.Context) ([]collector.Metric, error) {
	if !c.cfg.CollectPgStatStatements {
		return nil, nil
	}

	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureRDSConnection(ctx, inst)
		if err != nil {
			continue
		}
		labels := rdsInstanceLabels(inst)
		pgInst := rdsToPgInstance(inst)
		metrics, err := collectQueryAnalytics(ctx, pool, pgInst, labels, c.logger)
		if err != nil {
			c.logger.Warn("RDS query analytics failed",
				zap.String("instance", inst.config.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// Table Stats Collection (60s interval)
// pg_stat_user_tables
// ---------------------------------------------------------------------------

func (c *RDSPostgreSQLCollector) collectAllTableStats(ctx context.Context) ([]collector.Metric, error) {
	if !c.cfg.CollectTableStats {
		return nil, nil
	}

	var all []collector.Metric
	for _, inst := range c.instances {
		pool, err := c.ensureRDSConnection(ctx, inst)
		if err != nil {
			continue
		}
		labels := rdsInstanceLabels(inst)
		pgInst := rdsToPgInstance(inst)
		metrics, err := collectTableStats(ctx, pool, pgInst, labels, c.logger)
		if err != nil {
			c.logger.Warn("RDS table stats failed",
				zap.String("instance", inst.config.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// Metric Submission
// ---------------------------------------------------------------------------

// submitMetrics sends collected metrics to the platform via the reporter.
func (c *RDSPostgreSQLCollector) submitMetrics(ctx context.Context, metrics []collector.Metric) {
	if len(metrics) == 0 {
		return
	}

	// Group metrics by instance for per-instance submission
	for _, inst := range c.instances {
		var instanceMetrics []collector.Metric
		for _, m := range metrics {
			if m.Labels["rds_instance_id"] == inst.config.InstanceID {
				instanceMetrics = append(instanceMetrics, m)
			}
		}
		if len(instanceMetrics) == 0 {
			continue
		}

		payload := &AgentMetricsPayload{
			InstanceID: inst.config.InstanceID,
			Region:     inst.config.Region,
			Timestamp:  time.Now().UTC().Unix(),
			Metrics:    convertMetrics(instanceMetrics),
		}

		if err := inst.reporter.Submit(ctx, payload); err != nil {
			c.logger.Warn("Failed to submit metrics to platform",
				zap.String("instance", inst.config.InstanceID),
				zap.Error(err),
			)
		} else {
			c.logger.Debug("Submitted metrics to platform",
				zap.String("instance", inst.config.InstanceID),
				zap.Int("metric_count", len(instanceMetrics)),
			)
		}
	}
}

// ---------------------------------------------------------------------------
// RDS-Specific Metric Collection Functions
// ---------------------------------------------------------------------------

// collectRDSConnectionMetrics collects connection states from pg_stat_activity
// and max_connections from pg_settings.
func collectRDSConnectionMetrics(ctx context.Context, pool *pgxpool.Pool, inst *rdsPgInstance, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			COALESCE(datname, '') AS dbname,
			state,
			count(*) AS cnt
		FROM pg_stat_activity
		GROUP BY datname, state
	`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_activity: %w", err)
	}
	defer rows.Close()

	type stateRow struct {
		dbname string
		state  string
		count  int64
	}

	var stateRows []stateRow
	for rows.Next() {
		var r stateRow
		if err := rows.Scan(&r.dbname, &r.state, &r.count); err != nil {
			continue
		}
		stateRows = append(stateRows, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pg_stat_activity: %w", err)
	}

	var maxConns int64
	if err := pool.QueryRow(ctx2, "SELECT setting::int FROM pg_settings WHERE name = 'max_connections'").Scan(&maxConns); err != nil {
		maxConns = 0
	}

	var metrics []collector.Metric
	stateMapping := map[string]string{
		"active":              "db.rds_postgresql.connections.active",
		"idle":                "db.rds_postgresql.connections.idle",
		"idle in transaction": "db.rds_postgresql.connections.idle_in_transaction",
		"waiting":             "db.rds_postgresql.connections.waiting",
	}

	dbTotals := make(map[string]int64)

	for _, r := range stateRows {
		dbLabels := copyLabels(labels)
		if r.dbname != "" {
			dbLabels["dbname"] = r.dbname
		}

		if metricName, ok := stateMapping[r.state]; ok {
			metrics = append(metrics, makeMetric(metricName, float64(r.count), collector.MetricTypeGauge, dbLabels))
		}
		dbTotals[r.dbname] += r.count
	}

	for dbname, total := range dbTotals {
		dbLabels := copyLabels(labels)
		if dbname != "" {
			dbLabels["dbname"] = dbname
		}
		metrics = append(metrics, makeMetric("db.rds_postgresql.connections.total", float64(total), collector.MetricTypeGauge, dbLabels))

		if maxConns > 0 {
			util := safeDiv(float64(total), float64(maxConns)) * 100.0
			metrics = append(metrics, makeMetric("db.rds_postgresql.connections.utilization_pct", util, collector.MetricTypeGauge, dbLabels))
		}
	}

	if maxConns > 0 {
		metrics = append(metrics, makeMetric("db.rds_postgresql.connections.max", float64(maxConns), collector.MetricTypeGauge, labels))
	}

	return metrics, nil
}

// collectRDSTransactionMetrics collects per-database transaction, tuple, cache metrics
// from pg_stat_database, plus deadlocks.
func collectRDSTransactionMetrics(ctx context.Context, pool *pgxpool.Pool, inst *rdsPgInstance, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			datname,
			xact_commit,
			xact_rollback,
			tup_returned,
			tup_fetched,
			tup_inserted,
			tup_updated,
			tup_deleted,
			blks_hit,
			blks_read,
			deadlocks,
			temp_files,
			temp_bytes,
			conflicts
		FROM pg_stat_database
		WHERE datname IS NOT NULL
	`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_database: %w", err)
	}
	defer rows.Close()

	type dbStat struct {
		datname      string
		xactCommit   int64
		xactRollback int64
		tupReturned  int64
		tupFetched   int64
		tupInserted  int64
		tupUpdated   int64
		tupDeleted   int64
		blksHit      int64
		blksRead     int64
		deadlocks    int64
		tempFiles    int64
		tempBytes    int64
		conflicts    int64
	}

	var stats []dbStat
	for rows.Next() {
		var s dbStat
		if err := rows.Scan(
			&s.datname, &s.xactCommit, &s.xactRollback,
			&s.tupReturned, &s.tupFetched, &s.tupInserted, &s.tupUpdated, &s.tupDeleted,
			&s.blksHit, &s.blksRead, &s.deadlocks, &s.tempFiles, &s.tempBytes, &s.conflicts,
		); err != nil {
			continue
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pg_stat_database: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(inst.prevTimestamp).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	var metrics []collector.Metric

	for _, s := range stats {
		dbLabels := copyLabels(labels)
		dbLabels["dbname"] = s.datname

		// Cache hit ratio
		blksHitF := float64(s.blksHit)
		blksReadF := float64(s.blksRead)
		hitRatio := safeDiv(blksHitF, blksHitF+blksReadF)
		metrics = append(metrics, makeMetric("db.rds_postgresql.cache.hit_ratio", hitRatio, collector.MetricTypeGauge, dbLabels))

		// Counter snapshots
		metrics = append(metrics, makeMetric("db.rds_postgresql.transactions.commit", float64(s.xactCommit), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.transactions.rollback", float64(s.xactRollback), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.deadlocks", float64(s.deadlocks), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.conflicts", float64(s.conflicts), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.tuples.returned", float64(s.tupReturned), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.tuples.fetched", float64(s.tupFetched), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.tuples.inserted", float64(s.tupInserted), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.tuples.updated", float64(s.tupUpdated), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.tuples.deleted", float64(s.tupDeleted), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.temp.files", float64(s.tempFiles), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.rds_postgresql.temp.bytes", float64(s.tempBytes), collector.MetricTypeCounter, dbLabels))

		// Per-second rates via delta tracking
		counterEntries := []struct {
			key    string
			curr   uint64
			metric string
		}{
			{"rds_xact_commit:" + s.datname, uint64(s.xactCommit), "db.rds_postgresql.transactions.commit_rate"},
			{"rds_xact_rollback:" + s.datname, uint64(s.xactRollback), "db.rds_postgresql.transactions.rollback_rate"},
			{"rds_deadlocks:" + s.datname, uint64(s.deadlocks), "db.rds_postgresql.deadlocks_rate"},
			{"rds_tup_returned:" + s.datname, uint64(s.tupReturned), "db.rds_postgresql.tuples.returned_rate"},
			{"rds_tup_fetched:" + s.datname, uint64(s.tupFetched), "db.rds_postgresql.tuples.fetched_rate"},
			{"rds_blks_hit:" + s.datname, uint64(s.blksHit), "db.rds_postgresql.blocks.hit_rate"},
			{"rds_blks_read:" + s.datname, uint64(s.blksRead), "db.rds_postgresql.blocks.read_rate"},
		}

		for _, e := range counterEntries {
			if prev, ok := inst.prevCounters[e.key]; ok && e.curr >= prev {
				delta := float64(e.curr - prev)
				rate := safeDiv(delta, elapsed)
				metrics = append(metrics, emitCounterRate(e.metric, rate, dbLabels))
			}
			inst.prevCounters[e.key] = e.curr
		}
	}

	inst.prevTimestamp = now
	return metrics, nil
}

// collectRDSBgWriterMetrics collects checkpoint and buffer stats from pg_stat_bgwriter.
func collectRDSBgWriterMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var cpTimed, cpReq int64
	var cpWriteTime, cpSyncTime float64
	var bufCkpt, bufClean, bufBackend int64
	var maxwrittenClean, bufBackendFsync, bufAlloc int64

	err := pool.QueryRow(ctx2, `
		SELECT
			checkpoints_timed,
			checkpoints_req,
			checkpoint_write_time,
			checkpoint_sync_time,
			buffers_checkpoint,
			buffers_clean,
			buffers_backend,
			maxwritten_clean,
			buffers_backend_fsync,
			buffers_alloc
		FROM pg_stat_bgwriter
	`).Scan(
		&cpTimed, &cpReq, &cpWriteTime, &cpSyncTime,
		&bufCkpt, &bufClean, &bufBackend,
		&maxwrittenClean, &bufBackendFsync, &bufAlloc,
	)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_bgwriter: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.rds_postgresql.bgwriter.checkpoints_timed", float64(cpTimed), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.checkpoints_req", float64(cpReq), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.checkpoint_write_time", cpWriteTime, collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.checkpoint_sync_time", cpSyncTime, collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.buffers_checkpoint", float64(bufCkpt), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.buffers_clean", float64(bufClean), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.buffers_backend", float64(bufBackend), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.maxwritten_clean", float64(maxwrittenClean), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.buffers_backend_fsync", float64(bufBackendFsync), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.bgwriter.buffers_alloc", float64(bufAlloc), collector.MetricTypeCounter, labels),
	}, nil
}

// collectRDSWALMetrics collects WAL metrics from pg_stat_wal (PostgreSQL 14+).
func collectRDSWALMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var walRecords, walFpi, walBuffersFull, walWrite, walSync int64
	var walBytes int64
	var walWriteTime, walSyncTime float64

	err := pool.QueryRow(ctx2, `
		SELECT
			wal_records,
			wal_fpi,
			wal_bytes,
			wal_buffers_full,
			wal_write,
			wal_sync,
			wal_write_time,
			wal_sync_time
		FROM pg_stat_wal
	`).Scan(
		&walRecords, &walFpi, &walBytes,
		&walBuffersFull, &walWrite, &walSync,
		&walWriteTime, &walSyncTime,
	)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_wal: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.rds_postgresql.wal.records", float64(walRecords), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.fpi", float64(walFpi), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.bytes", float64(walBytes), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.buffers_full", float64(walBuffersFull), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.writes", float64(walWrite), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.syncs", float64(walSync), collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.write_time", walWriteTime, collector.MetricTypeCounter, labels),
		makeMetric("db.rds_postgresql.wal.sync_time", walSyncTime, collector.MetricTypeCounter, labels),
	}, nil
}

// collectRDSLockMetrics collects lock counts by type and mode from pg_locks.
func collectRDSLockMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Lock counts by type
	typeRows, err := pool.Query(ctx2, `
		SELECT lock_type, count(*) AS cnt
		FROM pg_locks
		GROUP BY lock_type
	`)
	if err != nil {
		return nil, fmt.Errorf("query pg_locks by type: %w", err)
	}
	defer typeRows.Close()

	var metrics []collector.Metric
	for typeRows.Next() {
		var lockType string
		var cnt int64
		if err := typeRows.Scan(&lockType, &cnt); err != nil {
			continue
		}
		rowLabels := copyLabels(labels)
		rowLabels["lock_type"] = lockType
		metrics = append(metrics, makeMetric("db.rds_postgresql.locks.by_type", float64(cnt), collector.MetricTypeGauge, rowLabels))
	}
	if err := typeRows.Err(); err != nil {
		return metrics, err
	}

	// Lock counts by mode
	modeRows, err := pool.Query(ctx2, `
		SELECT mode, count(*) AS cnt
		FROM pg_locks
		GROUP BY mode
	`)
	if err != nil {
		return metrics, fmt.Errorf("query pg_locks by mode: %w", err)
	}
	defer modeRows.Close()

	for modeRows.Next() {
		var mode string
		var cnt int64
		if err := modeRows.Scan(&mode, &cnt); err != nil {
			continue
		}
		rowLabels := copyLabels(labels)
		rowLabels["lock_mode"] = mode
		metrics = append(metrics, makeMetric("db.rds_postgresql.locks.by_mode", float64(cnt), collector.MetricTypeGauge, rowLabels))
	}
	if err := modeRows.Err(); err != nil {
		return metrics, err
	}

	// Total locks
	var totalLocks int64
	if err := pool.QueryRow(ctx2, "SELECT count(*) FROM pg_locks").Scan(&totalLocks); err == nil {
		metrics = append(metrics, makeMetric("db.rds_postgresql.locks.total", float64(totalLocks), collector.MetricTypeGauge, labels))
	}

	return metrics, nil
}

// collectRDSReplicationMetrics collects replication lag from pg_stat_replication.
func collectRDSReplicationMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// Reuse the existing replication metrics collection from the base package,
	// then re-emit with RDS metric name prefix.
	return collectReplicationMetrics(ctx, pool, labels, logger)
}

// collectRDSDatabaseSizeMetrics collects per-database size from pg_database_size.
func collectRDSDatabaseSizeMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx2, `
		SELECT datname, pg_database_size(datname)
		FROM pg_database
		WHERE datistemplate = false
	`)
	if err != nil {
		return nil, fmt.Errorf("query database sizes: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var dbname string
		var size int64
		if err := rows.Scan(&dbname, &size); err != nil {
			continue
		}
		dbLabels := copyLabels(labels)
		dbLabels["dbname"] = dbname
		metrics = append(metrics, makeMetric("db.rds_postgresql.db_size.bytes", float64(size), collector.MetricTypeGauge, dbLabels))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate database sizes: %w", err)
	}

	return metrics, nil
}

// ---------------------------------------------------------------------------
// Version Detection
// ---------------------------------------------------------------------------

func detectRDSVersion(ctx context.Context, inst *rdsPgInstance, pool *pgxpool.Pool, logger *zap.Logger) error {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var versionStr string
	if err := pool.QueryRow(ctx2, "SELECT version()").Scan(&versionStr); err != nil {
		return err
	}

	inst.versionStr = versionStr

	// Parse major version
	var major, minor int
	if _, err := fmt.Sscanf(versionStr, "PostgreSQL %d.%d", &major, &minor); err == nil {
		inst.version = major*10000 + minor*100
	}

	// Detect RDS-specific flavor
	if containsString(versionStr, "rds") {
		// Could also set a flavor flag here if needed
		logger.Debug("Detected RDS PostgreSQL",
			zap.String("instance", inst.config.Name),
			zap.String("version", versionStr),
		)
	}

	return nil
}

func hasRDSWalStats(inst *rdsPgInstance) bool {
	return inst.version >= 140000 // PostgreSQL 14+
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rdsToPgInstance converts an rdsPgInstance to a temporary pgInstance for reuse
// of the existing collectQueryAnalytics and collectTableStats functions.
func rdsToPgInstance(inst *rdsPgInstance) *pgInstance {
	return &pgInstance{
		config: config.PostgreSQLInstanceConfig{
			Name:     inst.config.Name,
			Host:     inst.config.Host,
			Port:     inst.config.Port,
			User:     inst.config.User,
			Password: inst.config.Password,
			DBName:   inst.config.DBName,
			SSLMode:  "require",
			Tags:     inst.config.Tags,
		},
		version:         inst.version,
		versionStr:      inst.versionStr,
		prevCounters:    inst.prevCounters,
		prevTimestamp:   inst.prevTimestamp,
		topQueriesLimit: inst.topQueriesLimit,
	}
}

// convertMetrics converts collector.Metric slice to MetricEntry slice for the payload.
func convertMetrics(metrics []collector.Metric) []MetricEntry {
	entries := make([]MetricEntry, 0, len(metrics))
	for _, m := range metrics {
		entries = append(entries, MetricEntry{
			Name:   m.Name,
			Type:   string(m.Type),
			Value:  m.Value,
			Labels: m.Labels,
			Unit:   m.Unit,
		})
	}
	return entries
}

// AgentMetricsPayload represents the payload submitted to the TFO Platform
// for RDS PostgreSQL agent-side metrics.
type AgentMetricsPayload struct {
	InstanceID string        `json:"instance_id"`
	Region     string        `json:"region"`
	Timestamp  int64         `json:"timestamp"`
	Metrics    []MetricEntry `json:"metrics"`
}

// MetricEntry represents a single metric in the submission payload.
type MetricEntry struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Value  float64           `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
	Unit   string            `json:"unit,omitempty"`
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// copyLabels is re-exported from helpers.go (same package).
// makeMetric, safeDiv, emitCounterRate are also from helpers.go (same package).

// Ensure interface compliance.
var _ collector.Collector = (*RDSPostgreSQLCollector)(nil)
