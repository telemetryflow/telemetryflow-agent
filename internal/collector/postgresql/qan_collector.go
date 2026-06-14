// Package postgresql implements the PostgreSQL QAN collector using
// pg_stat_statements with delta calculation from previous snapshot.
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

package postgresql

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// QANPostgreSQLCollector collects query analytics from pg_stat_statements
// with delta calculation. It implements qan.QANCollector.
type QANPostgreSQLCollector struct {
	cfg    QANConfig
	logger *zap.Logger

	mu        sync.RWMutex
	running   bool
	instances []*qanPgInstance
}

// QANConfig holds configuration for the PostgreSQL QAN collector.
type QANConfig struct {
	Instances       []config.PostgreSQLInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

// qanPgInstance holds per-instance state including the delta cache.
type qanPgInstance struct {
	config       config.PostgreSQLInstanceConfig
	pool         *pgxpool.Pool
	prevSnapshot map[string]*pgStatStatementsSnapshot // keyed by queryid
	prevTime     time.Time
}

// pgStatStatementsSnapshot captures raw counter values for delta calculation.
type pgStatStatementsSnapshot struct {
	queryID         uint64
	query           string
	calls           uint64
	totalExecTime   float64
	minExecTime     float64
	maxExecTime     float64
	rows            uint64
	sharedBlksHit   uint64
	sharedBlksRead  uint64
	sharedBlksDirty uint64
	sharedBlksWrite uint64
	tempBlksRead    uint64
	tempBlksWritten uint64
	blkReadTime     float64
	blkWriteTime    float64
}

// Regex patterns for query fingerprinting (shared with standard collector).
var (
	qanReQuotedString = regexp.MustCompile(`'[^']*'`)
	qanReDollarString = regexp.MustCompile(`\$\$.*?\$\$`)
	qanReNumberLit    = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	qanReInList       = regexp.MustCompile(`\bIN\s*\([^)]+\)`)
	qanReWhitespace   = regexp.MustCompile(`\s+`)
)

// NewQANPostgreSQLCollector creates a new PostgreSQL QAN collector.
func NewQANPostgreSQLCollector(cfg QANConfig, logger *zap.Logger) *QANPostgreSQLCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanPgInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanPgInstance{
			config:       inst,
			prevSnapshot: make(map[string]*pgStatStatementsSnapshot),
		}
	}

	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &QANPostgreSQLCollector{
		cfg:       cfg,
		logger:    logger.Named("qan-postgresql-pgstatements"),
		instances: instances,
	}
}

// Name returns the collector name.
func (c *QANPostgreSQLCollector) Name() string { return "qan-postgresql-pgstatements" }

// AgentType returns the PMM-compatible agent type.
func (c *QANPostgreSQLCollector) AgentType() qan.AgentType {
	return qan.AgentTypePostgreSQLPgStatements
}

// IsRunning returns whether the collector is active.
func (c *QANPostgreSQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start initializes database connections.
func (c *QANPostgreSQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("qan-postgresql collector already running")
	}
	c.running = true
	c.mu.Unlock()

	c.logger.Info("QAN PostgreSQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Int("top_queries_limit", c.cfg.TopQueriesLimit),
	)
	return nil
}

// Stop closes database connections.
func (c *QANPostgreSQLCollector) Stop() error {
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

// CollectQAN queries pg_stat_statements, computes deltas, and returns buckets.
func (c *QANPostgreSQLCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
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

func (c *QANPostgreSQLCollector) collectInstance(ctx context.Context, inst *qanPgInstance) ([]qan.QANMetricsBucket, error) {
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

	query := `
		SELECT queryid, query, calls, total_exec_time, min_exec_time, max_exec_time,
		       rows, shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written,
		       temp_blks_read, temp_blks_written, blk_read_time, blk_write_time
		FROM pg_stat_statements
		ORDER BY total_exec_time DESC
		LIMIT $1`

	rows, err := pool.Query(ctx2, query, limit)
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

	currentSnapshot := make(map[string]*pgStatStatementsSnapshot)
	var buckets []qan.QANMetricsBucket

	labels := c.instanceLabels(inst)

	for rows.Next() {
		var s pgStatStatementsSnapshot
		if err := rows.Scan(
			&s.queryID, &s.query, &s.calls,
			&s.totalExecTime, &s.minExecTime, &s.maxExecTime,
			&s.rows, &s.sharedBlksHit, &s.sharedBlksRead, &s.sharedBlksDirty, &s.sharedBlksWrite,
			&s.tempBlksRead, &s.tempBlksWritten, &s.blkReadTime, &s.blkWriteTime,
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
		deltaTempRead := int64(s.tempBlksRead) - int64(prev.tempBlksRead)
		deltaTempWritten := int64(s.tempBlksWritten) - int64(prev.tempBlksWritten)
		deltaBlkReadTime := s.blkReadTime - prev.blkReadTime
		deltaBlkWriteTime := s.blkWriteTime - prev.blkWriteTime

		minTime := s.minExecTime
		if prev.minExecTime > 0 && prev.minExecTime < minTime {
			minTime = prev.minExecTime
		}

		fp := fingerprintQueryQAN(s.query)
		example := s.query
		const maxExampleLen = 2000
		truncated := false
		if len(example) > maxExampleLen {
			example = example[:maxExampleLen]
			truncated = true
		}

		bucket := qan.QANMetricsBucket{
			AgentType:        qan.AgentTypePostgreSQLPgStatements,
			QueryID:          qidStr,
			Fingerprint:      fp,
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
			QueryTimeMin:     minTime / 1000.0,
			QueryTimeMax:     s.maxExecTime / 1000.0,
			PostgreSQL: &qan.PostgreSQLQANMetrics{
				RowsCnt: float64(deltaCalls),
				RowsSum: float64(deltaRows),

				SharedBlksHitCnt:     float64(deltaCalls),
				SharedBlksHitSum:     float64(deltaSharedHit),
				SharedBlksReadCnt:    float64(deltaCalls),
				SharedBlksReadSum:    float64(deltaSharedRead),
				SharedBlksDirtiedCnt: float64(deltaCalls),
				SharedBlksDirtiedSum: float64(deltaSharedDirty),
				SharedBlksWrittenCnt: float64(deltaCalls),
				SharedBlksWrittenSum: float64(deltaSharedWrite),

				TempBlksReadCnt:    float64(deltaCalls),
				TempBlksReadSum:    float64(deltaTempRead),
				TempBlksWrittenCnt: float64(deltaCalls),
				TempBlksWrittenSum: float64(deltaTempWritten),

				BlkReadTimeCnt:  float64(deltaCalls),
				BlkReadTimeSum:  deltaBlkReadTime / 1000.0,
				BlkWriteTimeCnt: float64(deltaCalls),
				BlkWriteTimeSum: deltaBlkWriteTime / 1000.0,
			},
		}

		buckets = append(buckets, bucket)
	}

	inst.prevSnapshot = currentSnapshot
	inst.prevTime = now

	return buckets, nil
}

func (c *QANPostgreSQLCollector) ensureConnection(ctx context.Context, inst *qanPgInstance) (*pgxpool.Pool, error) {
	if inst.pool != nil {
		return inst.pool, nil
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=10",
		inst.config.User, inst.config.Password,
		inst.config.Host, inst.config.Port,
		inst.config.DBName, inst.config.SSLMode,
	)

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

func (c *QANPostgreSQLCollector) instanceLabels(inst *qanPgInstance) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	labels["postgresql_instance"] = inst.config.Name
	labels["postgresql_host"] = inst.config.Host
	labels["db_system"] = "postgresql"
	return labels
}

func fingerprintQueryQAN(query string) string {
	normalised := query
	normalised = qanReDollarString.ReplaceAllString(normalised, "$$1$$")
	normalised = qanReQuotedString.ReplaceAllString(normalised, "'$1'")
	normalised = qanReInList.ReplaceAllString(normalised, "IN ($3)")
	normalised = qanReNumberLit.ReplaceAllString(normalised, "$2")
	normalised = strings.TrimSpace(normalised)
	normalised = qanReWhitespace.ReplaceAllString(normalised, " ")

	h := sha256.Sum256([]byte(normalised))
	return fmt.Sprintf("%x", h[:16])
}
