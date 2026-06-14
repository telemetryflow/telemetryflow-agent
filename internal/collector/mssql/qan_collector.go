// Package mssql implements the SQL Server QAN collector using
// sys.dm_exec_query_stats with delta calculation from previous snapshot.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// QANMSSQLCollector collects query analytics from sys.dm_exec_query_stats
// with delta calculation. It implements qan.QANCollector.
type QANMSSQLCollector struct {
	cfg       QANMSSQLConfig
	logger    *zap.Logger
	mu        sync.RWMutex
	running   bool
	instances []*qanMssqlInstance
}

// QANMSSQLConfig holds configuration for the MSSQL QAN collector.
type QANMSSQLConfig struct {
	Instances       []config.MSSQLInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

type qanMssqlInstance struct {
	config       config.MSSQLInstanceConfig
	db           *sql.DB
	prevSnapshot map[string]*mssqlSnapshot
	prevTime     time.Time
}

type mssqlSnapshot struct {
	queryHash          string
	executionCount     int64
	totalWorkerTime    int64
	totalElapsedTime   int64
	totalLogicalReads  int64
	totalPhysicalReads int64
	totalLogicalWrites int64
	rowCounts          int64
	maxDOP             int64
	maxGrantKB         float64
}

func NewQANMSSQLCollector(cfg QANMSSQLConfig, logger *zap.Logger) *QANMSSQLCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanMssqlInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanMssqlInstance{
			config:       inst,
			prevSnapshot: make(map[string]*mssqlSnapshot),
		}
	}
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return &QANMSSQLCollector{
		cfg:       cfg,
		logger:    logger.Named("qan-mssql-querystats"),
		instances: instances,
	}
}

func (c *QANMSSQLCollector) Name() string             { return "qan-mssql-querystats" }
func (c *QANMSSQLCollector) AgentType() qan.AgentType { return qan.AgentTypeMSSQLQueryStats }
func (c *QANMSSQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *QANMSSQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("qan-mssql collector already running")
	}
	c.running = true
	c.mu.Unlock()
	c.logger.Info("QAN MSSQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)
	return nil
}

func (c *QANMSSQLCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	for _, inst := range c.instances {
		if inst.db != nil {
			_ = inst.db.Close()
			inst.db = nil
		}
	}
	return nil
}

func (c *QANMSSQLCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
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

func (c *QANMSSQLCollector) collectInstance(ctx context.Context, inst *qanMssqlInstance) ([]qan.QANMetricsBucket, error) {
	db, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	limit := c.cfg.TopQueriesLimit
	if limit <= 0 {
		limit = 200
	}

	query := fmt.Sprintf(`
		SELECT TOP %d
			LOWER(CONVERT(VARCHAR(64), qs.query_hash, 2)) AS query_hash,
			SUM(qs.execution_count) AS execution_count,
			SUM(qs.total_worker_time) AS total_worker_time,
			SUM(qs.total_elapsed_time) AS total_elapsed_time,
			SUM(qs.total_logical_reads) AS total_logical_reads,
			SUM(qs.total_physical_reads) AS total_physical_reads,
			SUM(qs.total_logical_writes) AS total_logical_writes,
			SUM(qs.row_count) AS row_count,
			MAX(qs.max_dop) AS max_dop,
			MAX(qs.max_grant_kb) AS max_grant_kb
		FROM sys.dm_exec_query_stats qs WITH (NOLOCK)
		GROUP BY qs.query_hash
		ORDER BY SUM(qs.total_elapsed_time) DESC`, limit)

	rows, err := db.QueryContext(ctx2, query)
	if err != nil {
		return nil, fmt.Errorf("query dm_exec_query_stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

	currentSnapshot := make(map[string]*mssqlSnapshot)
	var buckets []qan.QANMetricsBucket
	labels := c.instanceLabels(inst)

	for rows.Next() {
		var s mssqlSnapshot
		var maxGrantKB sql.NullFloat64
		if err := rows.Scan(
			&s.queryHash,
			&s.executionCount,
			&s.totalWorkerTime,
			&s.totalElapsedTime,
			&s.totalLogicalReads,
			&s.totalPhysicalReads,
			&s.totalLogicalWrites,
			&s.rowCounts,
			&s.maxDOP,
			&maxGrantKB,
		); err != nil {
			continue
		}
		if maxGrantKB.Valid {
			s.maxGrantKB = maxGrantKB.Float64
		}

		currentSnapshot[s.queryHash] = &s

		prev, hasPrev := inst.prevSnapshot[s.queryHash]
		if !hasPrev {
			continue
		}

		deltaExecs := s.executionCount - prev.executionCount
		if deltaExecs <= 0 {
			continue
		}

		deltaWorkerTime := float64(s.totalWorkerTime-prev.totalWorkerTime) / 1e6
		deltaElapsedTime := float64(s.totalElapsedTime-prev.totalElapsedTime) / 1e6
		deltaLogicalReads := s.totalLogicalReads - prev.totalLogicalReads
		deltaPhysicalReads := s.totalPhysicalReads - prev.totalPhysicalReads
		deltaLogicalWrites := s.totalLogicalWrites - prev.totalLogicalWrites
		deltaRows := s.rowCounts - prev.rowCounts

		buckets = append(buckets, qan.QANMetricsBucket{
			AgentType:       qan.AgentTypeMSSQLQueryStats,
			QueryID:         s.queryHash,
			Fingerprint:     s.queryHash,
			PeriodStartSec:  inst.prevTime.Unix(),
			PeriodLengthSec: int64(periodLength.Seconds()),
			Database:        inst.config.Database,
			Username:        inst.config.Username,
			Labels:          labels,
			NumQueries:      float64(deltaExecs),
			QueryTimeCnt:    float64(deltaExecs),
			QueryTimeSum:    deltaElapsedTime,
			QueryTimeMax:    deltaElapsedTime,
			MSSQL: &qan.MSSQLQANMetrics{
				ExecutionCount:     float64(deltaExecs),
				TotalWorkerTime:    deltaWorkerTime,
				TotalCPUTime:       deltaWorkerTime,
				TotalElapsedTime:   deltaElapsedTime,
				TotalLogicalReads:  float64(deltaLogicalReads),
				TotalLogicalWrites: float64(deltaLogicalWrites),
				TotalPhysicalReads: float64(deltaPhysicalReads),
				RowCounts:          float64(deltaRows),
				MaxDOP:             float64(s.maxDOP),
				MaxGrantKB:         s.maxGrantKB,
			},
		})
	}

	inst.prevSnapshot = currentSnapshot
	inst.prevTime = now
	return buckets, nil
}

func (c *QANMSSQLCollector) ensureConnection(ctx context.Context, inst *qanMssqlInstance) (*sql.DB, error) {
	if inst.db != nil {
		if err := inst.db.PingContext(ctx); err == nil {
			return inst.db, nil
		}
		_ = inst.db.Close()
		inst.db = nil
	}

	dsn := buildQANConnString(inst.config)
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return nil, fmt.Errorf("mssql %s: open: %w", inst.config.Name, err)
	}
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx2); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mssql %s: ping: %w", inst.config.Name, err)
	}

	inst.db = db
	return db, nil
}

func buildQANConnString(cfg config.MSSQLInstanceConfig) string {
	password := resolveEnvVars(cfg.Password)
	encrypt := cfg.Encrypt
	if encrypt == "" {
		encrypt = "disable"
	}
	if cfg.InstanceName != "" {
		return fmt.Sprintf("sqlserver://%s:%s@%s:%d?instanceName=%s&database=%s&encrypt=%s&trustServerCertificate=%t",
			cfg.Username, password, cfg.Host, cfg.Port,
			cfg.InstanceName, cfg.Database,
			encrypt, cfg.TrustServerCertificate)
	}
	return fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s&encrypt=%s&trustServerCertificate=%t",
		cfg.Username, password, cfg.Host, cfg.Port,
		cfg.Database,
		encrypt, cfg.TrustServerCertificate)
}

func (c *QANMSSQLCollector) instanceLabels(inst *qanMssqlInstance) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	labels["mssql_instance"] = inst.config.Name
	labels["mssql_host"] = inst.config.Host
	labels["db_system"] = "mssql"
	return labels
}
