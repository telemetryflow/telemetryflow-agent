// Package cockroachdb implements the CockroachDB QAN collector using
// crdb_internal.node_statement_statistics with delta calculation.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package cockroachdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

type QANCockroachDBCollector struct {
	cfg       QANCockroachDBConfig
	logger    *zap.Logger
	mu        sync.RWMutex
	running   bool
	instances []*qanCrdbInstance
}

type QANCockroachDBConfig struct {
	Instances       []config.CockroachDBInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

type qanCrdbInstance struct {
	config       config.CockroachDBInstanceConfig
	pool         *pgxpool.Pool
	prevSnapshot map[string]*crdbSnapshot
	prevTime     time.Time
}

type crdbSnapshot struct {
	fingerprintID   string
	anonymizedQuery string
	count           float64
	firstAttempt    float64
	maxRetries      float64
	avgLatency      float64
	maxLatency      float64
	rowsRead        float64
	rowsWritten     float64
	bytesRead       float64
	networkBytes    float64
	appName         string
}

func NewQANCockroachDBCollector(cfg QANCockroachDBConfig, logger *zap.Logger) *QANCockroachDBCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanCrdbInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanCrdbInstance{config: inst, prevSnapshot: make(map[string]*crdbSnapshot)}
	}
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return &QANCockroachDBCollector{cfg: cfg, logger: logger.Named("qan-cockroachdb"), instances: instances}
}

func (c *QANCockroachDBCollector) Name() string             { return "qan-cockroachdb-stmtstats" }
func (c *QANCockroachDBCollector) AgentType() qan.AgentType { return qan.AgentTypeCockroachDBStmtStats }
func (c *QANCockroachDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *QANCockroachDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("already running")
	}
	c.running = true
	c.mu.Unlock()
	c.logger.Info("QAN CockroachDB collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *QANCockroachDBCollector) Stop() error {
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

func (c *QANCockroachDBCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
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

func (c *QANCockroachDBCollector) collectInstance(ctx context.Context, inst *qanCrdbInstance) ([]qan.QANMetricsBucket, error) {
	pool, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx2, `
		SELECT fingerprint_id::TEXT, anonymized_query, count, first_attempt_count,
		       max_retries, avg_latency::FLOAT8, max_latency::FLOAT8,
		       rows_read, rows_written, bytes_read, network_bytes, app_name
		FROM crdb_internal.node_statement_statistics
		ORDER BY avg_latency DESC LIMIT $1`, c.cfg.TopQueriesLimit)
	if err != nil {
		return nil, fmt.Errorf("query statement_statistics: %w", err)
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

	currentSnapshot := make(map[string]*crdbSnapshot)
	var buckets []qan.QANMetricsBucket
	labels := c.instanceLabels(inst)

	for rows.Next() {
		var s crdbSnapshot
		if err := rows.Scan(&s.fingerprintID, &s.anonymizedQuery, &s.count, &s.firstAttempt,
			&s.maxRetries, &s.avgLatency, &s.maxLatency, &s.rowsRead, &s.rowsWritten,
			&s.bytesRead, &s.networkBytes, &s.appName); err != nil {
			continue
		}

		currentSnapshot[s.fingerprintID] = &s

		prev, hasPrev := inst.prevSnapshot[s.fingerprintID]
		if !hasPrev {
			continue
		}

		deltaCount := s.count - prev.count
		if deltaCount <= 0 {
			continue
		}

		deltaRowsRead := s.rowsRead - prev.rowsRead
		deltaRowsWritten := s.rowsWritten - prev.rowsWritten
		deltaBytesRead := s.bytesRead - prev.bytesRead
		deltaNetworkBytes := s.networkBytes - prev.networkBytes
		deltaRetries := s.maxRetries - prev.maxRetries
		deltaFirstAttempt := s.firstAttempt - prev.firstAttempt

		avgLatencySec := s.avgLatency / 1e9

		example := s.anonymizedQuery
		truncated := false
		if len(example) > 2000 {
			example = example[:2000]
			truncated = true
		}

		buckets = append(buckets, qan.QANMetricsBucket{
			AgentType:        qan.AgentTypeCockroachDBStmtStats,
			QueryID:          s.fingerprintID,
			Fingerprint:      s.fingerprintID,
			Example:          example,
			ExampleTruncated: truncated,
			PeriodStartSec:   inst.prevTime.Unix(),
			PeriodLengthSec:  int64(periodLength.Seconds()),
			Database:         c.databaseName(inst),
			Labels:           labels,
			NumQueries:       deltaCount,
			QueryTimeCnt:     deltaCount,
			QueryTimeSum:     avgLatencySec * deltaCount,
			QueryTimeMax:     s.maxLatency / 1e9,
			// p99 approximated by max (upper bound); crdb_internal node_statement_statistics has no histogram.
			QueryTimeP99: s.maxLatency / 1e9,
			CockroachDB: &qan.CockroachDBQANMetrics{
				RowsReadCnt:     deltaCount,
				RowsReadSum:     deltaRowsRead,
				RowsWrittenCnt:  deltaCount,
				RowsWrittenSum:  deltaRowsWritten,
				BytesReadCnt:    deltaCount,
				BytesReadSum:    deltaBytesRead,
				NetworkBytesCnt: deltaCount,
				NetworkBytesSum: deltaNetworkBytes,
				MaxRetriesCnt:   deltaCount,
				MaxRetriesSum:   deltaRetries,
				FirstAttemptCnt: deltaCount,
				FirstAttemptSum: deltaFirstAttempt,
				ApplicationName: s.appName,
			},
		})
	}

	inst.prevSnapshot = currentSnapshot
	inst.prevTime = now
	return buckets, nil
}

func (c *QANCockroachDBCollector) ensureConnection(ctx context.Context, inst *qanCrdbInstance) (*pgxpool.Pool, error) {
	if inst.pool != nil {
		return inst.pool, nil
	}
	port := inst.config.SQLPort
	if port == 0 {
		port = 26257
	}
	dbName := inst.config.Database
	if dbName == "" {
		dbName = "system"
	}
	sslMode := inst.config.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=10",
		inst.config.User, inst.config.Password, inst.config.Host, port, dbName, sslMode)
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

func (c *QANCockroachDBCollector) databaseName(inst *qanCrdbInstance) string {
	if inst.config.Database != "" {
		return inst.config.Database
	}
	return "system"
}

func (c *QANCockroachDBCollector) instanceLabels(inst *qanCrdbInstance) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	labels["cockroachdb_instance"] = inst.config.Name
	labels["cockroachdb_host"] = inst.config.Host
	labels["db_system"] = "cockroachdb"
	return labels
}
