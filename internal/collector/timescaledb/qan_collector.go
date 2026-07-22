// Package timescaledb implements the TimescaleDB QAN collector.
// Since TimescaleDB is PostgreSQL, it reuses pg_stat_statements with
// delta calculation — identical to the PostgreSQL QAN collector.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package timescaledb

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

type QANTimescaleDBCollector struct {
	cfg       QANTimescaleDBConfig
	logger    *zap.Logger
	mu        sync.RWMutex
	running   bool
	instances []*qanTsInstance
}

type QANTimescaleDBConfig struct {
	Instances       []config.TimescaleDBInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

type qanTsInstance struct {
	config       config.TimescaleDBInstanceConfig
	pool         *pgxpool.Pool
	prevSnapshot map[string]*tsSnapshot
	prevTime     time.Time
}

type tsSnapshot struct {
	queryID        uint64
	query          string
	calls          uint64
	totalExecTime  float64
	minExecTime    float64
	maxExecTime    float64
	rows           uint64
	sharedBlksHit  uint64
	sharedBlksRead uint64
}

func NewQANTimescaleDBCollector(cfg QANTimescaleDBConfig, logger *zap.Logger) *QANTimescaleDBCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanTsInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanTsInstance{config: inst, prevSnapshot: make(map[string]*tsSnapshot)}
	}
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return &QANTimescaleDBCollector{cfg: cfg, logger: logger.Named("qan-timescaledb"), instances: instances}
}

func (c *QANTimescaleDBCollector) Name() string { return "qan-timescaledb-pgstatements" }
func (c *QANTimescaleDBCollector) AgentType() qan.AgentType {
	return qan.AgentTypeTimescaleDBPgStatements
}
func (c *QANTimescaleDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *QANTimescaleDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("already running")
	}
	c.running = true
	c.mu.Unlock()
	c.logger.Info("QAN TimescaleDB collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *QANTimescaleDBCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	for _, inst := range c.instances {
		if inst.pool != nil {
			inst.pool.Close()
			inst.pool = nil
		}
	}
	return nil
}

func (c *QANTimescaleDBCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
	if len(c.instances) == 0 {
		return nil, nil
	}
	var allBuckets []qan.QANMetricsBucket
	for _, inst := range c.instances {
		buckets, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("QAN collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
			continue
		}
		allBuckets = append(allBuckets, buckets...)
	}
	return allBuckets, nil
}

func (c *QANTimescaleDBCollector) collectInstance(ctx context.Context, inst *qanTsInstance) ([]qan.QANMetricsBucket, error) {
	pool, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}
	return collectQANBuckets(ctx, pool, inst, c.cfg.TopQueriesLimit, c.cfg.Labels)
}

// collectQANBuckets runs the pg_stat_statements delta calculation against an
// already-established querier. Split from collectInstance so it can be tested
// without a live connection.
func collectQANBuckets(ctx context.Context, q PgxQuerier, inst *qanTsInstance, topQueriesLimit int, globalLabels map[string]string) ([]qan.QANMetricsBucket, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var extExists bool
	if err := q.QueryRow(ctx2, "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')").Scan(&extExists); err != nil || !extExists {
		return nil, nil
	}

	limit := topQueriesLimit
	candidatePool := limit * 3
	if candidatePool > 1000 {
		candidatePool = 1000
	}
	if candidatePool < limit {
		candidatePool = limit
	}

	rows, err := q.Query(ctx2, `
		SELECT queryid, query, calls, total_exec_time, min_exec_time, max_exec_time,
		       rows, shared_blks_hit, shared_blks_read
		FROM pg_stat_statements
		WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
		ORDER BY total_exec_time DESC LIMIT $1`, candidatePool)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_statements: %w", err)
	}
	defer rows.Close()

	now := time.Now()
	var periodLength time.Duration
	if inst.prevTime.IsZero() {
		periodLength = 60 * time.Second
	} else {
		periodLength = now.Sub(inst.prevTime)
		if periodLength <= 0 {
			periodLength = 60 * time.Second
		}
	}

	currentSnapshot := make(map[string]*tsSnapshot)
	var buckets []qan.QANMetricsBucket
	labels := qanInstanceLabels(inst, globalLabels)

	for rows.Next() {
		var s tsSnapshot
		if err := rows.Scan(&s.queryID, &s.query, &s.calls, &s.totalExecTime, &s.minExecTime, &s.maxExecTime, &s.rows, &s.sharedBlksHit, &s.sharedBlksRead); err != nil {
			continue
		}

		qidStr := strconv.FormatUint(s.queryID, 10)
		currentSnapshot[qidStr] = &s

		prev, hasPrev := inst.prevSnapshot[qidStr]
		if !hasPrev {
			continue
		}

		deltaCalls := int64(s.calls) - int64(prev.calls)
		if deltaCalls <= 0 {
			continue
		}

		deltaTime := s.totalExecTime - prev.totalExecTime
		deltaRows := int64(s.rows) - int64(prev.rows)
		deltaSharedHit := int64(s.sharedBlksHit) - int64(prev.sharedBlksHit)
		deltaSharedRead := int64(s.sharedBlksRead) - int64(prev.sharedBlksRead)

		example := s.query
		truncated := false
		if len(example) > 2000 {
			example = example[:2000]
			truncated = true
		}

		buckets = append(buckets, qan.QANMetricsBucket{
			AgentType:        qan.AgentTypeTimescaleDBPgStatements,
			QueryID:          qidStr,
			Fingerprint:      qidStr,
			Example:          example,
			ExampleTruncated: truncated,
			PeriodStartSec:   inst.prevTime.Unix(),
			PeriodLengthSec:  int64(periodLength.Seconds()),
			Database:         inst.config.DBName,
			Username:         inst.config.User,
			Labels:           labels,
			NumQueries:       float64(deltaCalls),
			QueryTimeCnt:     float64(deltaCalls),
			QueryTimeSum:     deltaTime / 1000.0,
			QueryTimeMin:     s.minExecTime / 1000.0,
			QueryTimeMax:     s.maxExecTime / 1000.0,
			// p99 approximated by max (upper bound); pg_stat_statements has no histogram.
			QueryTimeP99: s.maxExecTime / 1000.0,
			PostgreSQL: &qan.PostgreSQLQANMetrics{
				RowsCnt:           float64(deltaCalls),
				RowsSum:           float64(deltaRows),
				SharedBlksHitCnt:  float64(deltaCalls),
				SharedBlksHitSum:  float64(deltaSharedHit),
				SharedBlksReadCnt: float64(deltaCalls),
				SharedBlksReadSum: float64(deltaSharedRead),
			},
		})
	}

	inst.prevSnapshot = currentSnapshot
	inst.prevTime = now

	if len(buckets) > limit {
		sort.Slice(buckets, func(i, j int) bool {
			return buckets[i].QueryTimeSum > buckets[j].QueryTimeSum
		})
		buckets = buckets[:limit]
	}

	return buckets, nil
}

func (c *QANTimescaleDBCollector) ensureConnection(ctx context.Context, inst *qanTsInstance) (*pgxpool.Pool, error) {
	if inst.pool != nil {
		return inst.pool, nil
	}
	sslMode := inst.config.SSLMode
	if sslMode == "" {
		sslMode = "prefer"
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=10",
		inst.config.User, inst.config.Password, inst.config.Host, inst.config.Port, inst.config.DBName, sslMode)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.MaxConns = 3
	cfg.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	inst.pool = pool
	return pool, nil
}

func qanInstanceLabels(inst *qanTsInstance, globalLabels map[string]string) map[string]string {
	labels := make(map[string]string)
	for k, v := range globalLabels {
		labels[k] = v
	}
	labels["timescaledb_instance"] = inst.config.Name
	labels["timescaledb_host"] = inst.config.Host
	labels["db_system"] = "timescaledb"
	return labels
}
