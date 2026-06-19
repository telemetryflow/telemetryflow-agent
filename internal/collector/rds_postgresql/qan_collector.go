// Package rds_postgresql implements the RDS PostgreSQL QAN collector.
// Since RDS PostgreSQL is PostgreSQL, it reuses pg_stat_statements with
// delta calculation — identical to the PostgreSQL QAN collector but with
// RDS-specific connection defaults (verify-full SSL, RDS CA cert).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package rds_postgresql

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

// QANRDSPostgreSQLCollector collects query analytics from pg_stat_statements
// on Amazon RDS PostgreSQL with delta calculation.
type QANRDSPostgreSQLCollector struct {
	cfg       QANRDSPostgreSQLConfig
	logger    *zap.Logger
	mu        sync.RWMutex
	running   bool
	instances []*qanRdsPgInstance
}

// QANRDSPostgreSQLConfig holds configuration for the RDS PostgreSQL QAN collector.
type QANRDSPostgreSQLConfig struct {
	Instances       []config.RDSPostgreSQLInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

type qanRdsPgInstance struct {
	config       config.RDSPostgreSQLInstanceConfig
	pool         *pgxpool.Pool
	prevSnapshot map[string]*rdsPgSnapshot
	prevTime     time.Time
}

type rdsPgSnapshot struct {
	queryID         uint64
	calls           uint64
	totalExecTime   float64
	minExecTime     float64
	maxExecTime     float64
	rows            uint64
	sharedBlksHit   uint64
	sharedBlksRead  uint64
	sharedBlksDirty uint64
	sharedBlksWrite uint64
}

func NewQANRDSPostgreSQLCollector(cfg QANRDSPostgreSQLConfig, logger *zap.Logger) *QANRDSPostgreSQLCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanRdsPgInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanRdsPgInstance{
			config:       inst,
			prevSnapshot: make(map[string]*rdsPgSnapshot),
		}
	}
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return &QANRDSPostgreSQLCollector{
		cfg:       cfg,
		logger:    logger.Named("qan-rds-postgresql-pgstatements"),
		instances: instances,
	}
}

func (c *QANRDSPostgreSQLCollector) Name() string { return "qan-rds-postgresql-pgstatements" }
func (c *QANRDSPostgreSQLCollector) AgentType() qan.AgentType {
	return qan.AgentTypeRDSPostgreSQLPgStmt
}
func (c *QANRDSPostgreSQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *QANRDSPostgreSQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("qan-rds-postgresql collector already running")
	}
	c.running = true
	c.mu.Unlock()
	c.logger.Info("QAN RDS PostgreSQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)
	return nil
}

func (c *QANRDSPostgreSQLCollector) Stop() error {
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

func (c *QANRDSPostgreSQLCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
	if len(c.instances) == 0 {
		return nil, nil
	}
	var allBuckets []qan.QANMetricsBucket
	for _, inst := range c.instances {
		buckets, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("QAN collection failed for instance",
				zap.String("instance", inst.config.Name),
				zap.Error(err),
			)
			continue
		}
		allBuckets = append(allBuckets, buckets...)
	}
	return allBuckets, nil
}

func (c *QANRDSPostgreSQLCollector) collectInstance(ctx context.Context, inst *qanRdsPgInstance) ([]qan.QANMetricsBucket, error) {
	pool, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var extExists bool
	if err := pool.QueryRow(ctx2,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')",
	).Scan(&extExists); err != nil || !extExists {
		return nil, nil
	}

	limit := c.cfg.TopQueriesLimit
	candidatePool := limit * 3
	if candidatePool > 1000 {
		candidatePool = 1000
	}
	if candidatePool < limit {
		candidatePool = limit
	}

	query := `
		SELECT queryid, query, calls, total_exec_time, min_exec_time, max_exec_time,
		       rows, shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written
		FROM pg_stat_statements
		WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
		ORDER BY total_exec_time DESC
		LIMIT $1`

	rows, err := pool.Query(ctx2, query, candidatePool)
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

	currentSnapshot := make(map[string]*rdsPgSnapshot)
	var buckets []qan.QANMetricsBucket
	labels := c.instanceLabels(inst)

	for rows.Next() {
		var s rdsPgSnapshot
		var queryText string
		if err := rows.Scan(
			&s.queryID, &queryText, &s.calls,
			&s.totalExecTime, &s.minExecTime, &s.maxExecTime,
			&s.rows, &s.sharedBlksHit, &s.sharedBlksRead, &s.sharedBlksDirty, &s.sharedBlksWrite,
		); err != nil {
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
		deltaSharedDirty := int64(s.sharedBlksDirty) - int64(prev.sharedBlksDirty)
		deltaSharedWrite := int64(s.sharedBlksWrite) - int64(prev.sharedBlksWrite)

		example := queryText
		truncated := false
		if len(example) > 2000 {
			example = example[:2000]
			truncated = true
		}

		buckets = append(buckets, qan.QANMetricsBucket{
			AgentType:        qan.AgentTypeRDSPostgreSQLPgStmt,
			QueryID:          qidStr,
			Fingerprint:      qidStr,
			Example:          example,
			ExampleTruncated: truncated,
			PeriodStartSec:   inst.prevTime.Unix(),
			PeriodLengthSec:  int64(periodLength.Seconds()),
			Database:         c.databaseName(inst),
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
				RowsCnt:              float64(deltaCalls),
				RowsSum:              float64(deltaRows),
				SharedBlksHitCnt:     float64(deltaCalls),
				SharedBlksHitSum:     float64(deltaSharedHit),
				SharedBlksReadCnt:    float64(deltaCalls),
				SharedBlksReadSum:    float64(deltaSharedRead),
				SharedBlksDirtiedCnt: float64(deltaCalls),
				SharedBlksDirtiedSum: float64(deltaSharedDirty),
				SharedBlksWrittenCnt: float64(deltaCalls),
				SharedBlksWrittenSum: float64(deltaSharedWrite),
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

func (c *QANRDSPostgreSQLCollector) ensureConnection(ctx context.Context, inst *qanRdsPgInstance) (*pgxpool.Pool, error) {
	if inst.pool != nil {
		return inst.pool, nil
	}

	dbName := "postgres"
	if inst.config.DBName != "" {
		dbName = inst.config.DBName
	}
	port := 5432
	if inst.config.Port != 0 {
		port = inst.config.Port
	}

	// RDS requires SSL — default to verify-full with RDS CA bundle
	sslMode := "verify-full"
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=10",
		inst.config.User, inst.config.Password,
		inst.config.Host, port, dbName, sslMode)

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

func (c *QANRDSPostgreSQLCollector) databaseName(inst *qanRdsPgInstance) string {
	if inst.config.DBName != "" {
		return inst.config.DBName
	}
	return "postgres"
}

func (c *QANRDSPostgreSQLCollector) instanceLabels(inst *qanRdsPgInstance) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	labels["rds_postgresql_instance"] = inst.config.Name
	labels["rds_postgresql_instance_id"] = inst.config.InstanceID
	labels["rds_postgresql_host"] = inst.config.Host
	labels["rds_postgresql_region"] = inst.config.Region
	labels["db_system"] = "rds_postgresql"
	return labels
}
