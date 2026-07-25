// Package pgbouncer implements a TelemetryFlow Agent collector for PgBouncer
// connection poolers. It connects over the PostgreSQL wire protocol using pgx
// and queries the PgBouncer admin database (SHOW STATS / SHOW POOLS).
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package pgbouncer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "pgbouncer"

// Rows is the minimal row-iteration surface the collect functions depend on.
// Both pgx.Rows (production) and a hand-written fake (tests) satisfy this
// interface, which lets the query paths be exercised without a live database.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
}

// Querier is the minimal query surface the collect functions depend on.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	Close()
}

// ConnectorFactory creates a Querier for a given PgBouncer instance. It is the
// seam used by tests to inject a fake connector without touching the network.
type ConnectorFactory func(ctx context.Context, cfg config.PgBouncerInstance) (Querier, error)

// connectorFactory is the active factory; defaults to the pgx implementation
// and may be overridden via SetConnectorFactoryExported from tests.
var connectorFactory ConnectorFactory = pgxConnector

// PgBouncerCollector monitors one or more PgBouncer admin endpoints.
type PgBouncerCollector struct {
	cfg    config.PgBouncerCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewPgBouncerCollector constructs a collector with default intervals applied.
func NewPgBouncerCollector(cfg config.PgBouncerCollectorConfig, logger *zap.Logger) *PgBouncerCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return &PgBouncerCollector{
		cfg:       cfg,
		logger:    logger.Named(collectorName),
		stopChan:  make(chan struct{}),
	}
}

func applyInstanceDefaults(inst *config.PgBouncerInstance) {
	if inst.Port == 0 {
		inst.Port = 6432
	}
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.Database == "" {
		inst.Database = "pgbouncer"
	}
	if inst.User == "" {
		inst.User = "pgbouncer"
	}
	if inst.SSLMode == "" {
		inst.SSLMode = "disable"
	}
	if inst.Timeout == 0 {
		inst.Timeout = 5 * time.Second
	}
}

func (c *PgBouncerCollector) Name() string { return collectorName }

func (c *PgBouncerCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *PgBouncerCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("pgbouncer collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("PgBouncer collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *PgBouncerCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances.
func (c *PgBouncerCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		m, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("PgBouncer collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, m...)
	}
	return all, nil
}

func (c *PgBouncerCollector) collectInstance(ctx context.Context, inst config.PgBouncerInstance) ([]collector.Metric, error) {
	q, err := connectorFactory(ctx, inst)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", inst.Name, err)
	}
	defer q.Close()

	labels := instanceLabels(c.cfg, inst)
	var all []collector.Metric

	if m, err := collectStats(ctx, q, labels); err != nil {
		c.logger.Debug("SHOW STATS skipped", zap.String("instance", inst.Name), zap.Error(err))
	} else {
		all = append(all, m...)
	}

	if m, err := collectPools(ctx, q, labels); err != nil {
		c.logger.Debug("SHOW POOLS skipped", zap.String("instance", inst.Name), zap.Error(err))
	} else {
		all = append(all, m...)
	}

	c.logger.Debug("PgBouncer instance collected",
		zap.String("instance", inst.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

// collectStats queries SHOW STATS and emits per-database counters and gauges.
func collectStats(ctx context.Context, q Querier, labels map[string]string) ([]collector.Metric, error) {
	rows, err := q.Query(ctx, "SHOW STATS")
	if err != nil {
		return nil, fmt.Errorf("query SHOW STATS: %w", err)
	}
	defer rows.Close()

	var out []collector.Metric
	for rows.Next() {
		var (
			database       string
			totalXactCount int64
			totalQueryCnt  int64
			totalReceived  int64
			totalSent      int64
			totalXactTime  int64
			totalQueryTime int64
			totalWaitTime  int64
			avgXactCount   int64
			avgQueryCount  int64
			avgRecv        int64
			avgSent        int64
			avgXactTime    int64
			avgQueryTime   int64
			avgWaitTime    int64
		)
		if err := rows.Scan(
			&database,
			&totalXactCount, &totalQueryCnt, &totalReceived, &totalSent,
			&totalXactTime, &totalQueryTime, &totalWaitTime,
			&avgXactCount, &avgQueryCount, &avgRecv, &avgSent,
			&avgXactTime, &avgQueryTime, &avgWaitTime,
		); err != nil {
			continue
		}
		rowLabels := withRowLabels(labels, database, "")
		out = append(out,
			makeMetric("db.pgbouncer.total_transactions", float64(totalXactCount), collector.MetricTypeCounter, rowLabels),
			makeMetric("db.pgbouncer.total_queries", float64(totalQueryCnt), collector.MetricTypeCounter, rowLabels),
			makeMetric("db.pgbouncer.total_bytes_received", float64(totalReceived), collector.MetricTypeCounter, rowLabels),
			makeMetric("db.pgbouncer.total_bytes_sent", float64(totalSent), collector.MetricTypeCounter, rowLabels),
			makeMetric("db.pgbouncer.avg_query_time_ms", float64(avgQueryTime)/1000.0, collector.MetricTypeGauge, rowLabels),
			makeMetric("db.pgbouncer.avg_wait_time_ms", float64(avgWaitTime)/1000.0, collector.MetricTypeGauge, rowLabels),
		)
	}
	return out, nil
}

// collectPools queries SHOW POOLS and emits per-database/user pool gauges.
func collectPools(ctx context.Context, q Querier, labels map[string]string) ([]collector.Metric, error) {
	rows, err := q.Query(ctx, "SHOW POOLS")
	if err != nil {
		return nil, fmt.Errorf("query SHOW POOLS: %w", err)
	}
	defer rows.Close()

	var out []collector.Metric
	for rows.Next() {
		var (
			database               string
			user                   string
			clActive               int64
			clWaiting              int64
			clActiveCancelReq      int64
			clWaitingCancelReq     int64
			svActive               int64
			svActiveCancel         int64
			svBeingCanceled        int64
			svIdle                 int64
			svUsed                 int64
			svTested               int64
			svLogin                int64
			maxwait                int64
			maxwaitUs              int64
			poolMode               string
		)
		if err := rows.Scan(
			&database, &user,
			&clActive, &clWaiting, &clActiveCancelReq, &clWaitingCancelReq,
			&svActive, &svActiveCancel, &svBeingCanceled, &svIdle, &svUsed, &svTested, &svLogin,
			&maxwait, &maxwaitUs, &poolMode,
		); err != nil {
			continue
		}
		rowLabels := withRowLabels(labels, database, user)
		maxwaitMs := float64(maxwait)*1000 + float64(maxwaitUs)/1000.0
		out = append(out,
			makeMetric("db.pgbouncer.client_connections_active", float64(clActive), collector.MetricTypeGauge, rowLabels),
			makeMetric("db.pgbouncer.client_connections_waiting", float64(clWaiting), collector.MetricTypeGauge, rowLabels),
			makeMetric("db.pgbouncer.server_connections_active", float64(svActive), collector.MetricTypeGauge, rowLabels),
			makeMetric("db.pgbouncer.server_connections_idle", float64(svIdle), collector.MetricTypeGauge, rowLabels),
			makeMetric("db.pgbouncer.server_connections_used", float64(svUsed), collector.MetricTypeGauge, rowLabels),
			makeMetric("db.pgbouncer.maxwait_ms", maxwaitMs, collector.MetricTypeGauge, rowLabels),
		)
	}
	return out, nil
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

func instanceLabels(cfg config.PgBouncerCollectorConfig, inst config.PgBouncerInstance) map[string]string {
	labels := map[string]string{
		"pgbouncer_instance": inst.Name,
		"pgbouncer_host":     inst.Host,
	}
	for k, v := range cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	return labels
}

// withRowLabels copies the base labels and adds the per-row database and (for
// pools) user dimensions.
func withRowLabels(base map[string]string, database, user string) map[string]string {
	out := make(map[string]string, len(base)+2)
	for k, v := range base {
		out[k] = v
	}
	out["database"] = database
	if user != "" {
		out["user"] = user
	}
	return out
}

// pgxConnector is the production ConnectorFactory backed by a pgx connection
// pool. It opens a short-lived pool per collection cycle; PgBouncer admin
// sessions are cheap and this keeps connection lifecycle management simple.
func pgxConnector(ctx context.Context, cfg config.PgBouncerInstance) (Querier, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database, cfg.SSLMode,
	)
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	poolCfg.MaxConns = 1
	poolCfg.MaxConnLifetime = cfg.Timeout
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx2, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx2); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &pgxQuerier{pool: pool}, nil
}

// pgxQuerier adapts *pgxpool.Pool to the Querier interface.
type pgxQuerier struct {
	pool *pgxpool.Pool
}

func (q *pgxQuerier) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := q.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (q *pgxQuerier) Close() { q.pool.Close() }
