// Package mysql implements the MySQL/MariaDB/Percona QAN collector using
// performance_schema.events_statements_summary_by_digest with delta calculation.
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
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// QANMySQLCollector collects query analytics from performance_schema with
// delta calculation. It implements qan.QANCollector.
type QANMySQLCollector struct {
	cfg    QANMySQLConfig
	logger *zap.Logger

	mu        sync.RWMutex
	running   bool
	instances []*qanMySQLInstance
}

// QANMySQLConfig holds configuration for the MySQL QAN collector.
type QANMySQLConfig struct {
	Instances       []config.MySQLInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

// qanMySQLInstance holds per-instance state including delta cache.
type qanMySQLInstance struct {
	config       config.MySQLInstanceConfig
	db           *sql.DB
	prevSnapshot map[string]*perfSchemaSnapshot // keyed by digest
	prevTime     time.Time
}

// perfSchemaSnapshot captures raw counter values from
// performance_schema.events_statements_summary_by_digest.
type perfSchemaSnapshot struct {
	digestText              string
	countStar               uint64
	sumTimerWait            uint64
	minTimerWait            uint64
	maxTimerWait            uint64
	sumLockTime             uint64
	sumRowsSent             uint64
	sumRowsExamined         uint64
	sumRowsAffected         uint64
	sumCreatedTmpTables     uint64
	sumCreatedTmpDiskTables uint64
	sumMergePasses          uint64
	sumNoIndexUsed          uint64
	sumNoGoodIndexUsed      uint64
}

// NewQANMySQLCollector creates a new MySQL QAN collector.
func NewQANMySQLCollector(cfg QANMySQLConfig, logger *zap.Logger) *QANMySQLCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanMySQLInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanMySQLInstance{
			config:       inst,
			prevSnapshot: make(map[string]*perfSchemaSnapshot),
		}
	}

	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &QANMySQLCollector{
		cfg:       cfg,
		logger:    logger.Named("qan-mysql-perfschema"),
		instances: instances,
	}
}

// Name returns the collector name.
func (c *QANMySQLCollector) Name() string { return "qan-mysql-perfschema" }

// AgentType returns the PMM-compatible agent type.
func (c *QANMySQLCollector) AgentType() qan.AgentType {
	return qan.AgentTypeMySQLPerfSchema
}

// IsRunning returns whether the collector is active.
func (c *QANMySQLCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start initializes database connections.
func (c *QANMySQLCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("qan-mysql collector already running")
	}
	c.running = true
	c.mu.Unlock()

	c.logger.Info("QAN MySQL collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)
	return nil
}

// Stop closes database connections.
func (c *QANMySQLCollector) Stop() error {
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

// CollectQAN queries performance_schema, computes deltas, and returns buckets.
func (c *QANMySQLCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
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

func (c *QANMySQLCollector) collectInstance(ctx context.Context, inst *qanMySQLInstance) ([]qan.QANMetricsBucket, error) {
	db, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT DIGEST_TEXT, COUNT_STAR,
		       SUM_TIMER_WAIT, MIN_TIMER_WAIT, MAX_TIMER_WAIT,
		       SUM_LOCK_TIME, SUM_ROWS_SENT, SUM_ROWS_EXAMINED, SUM_ROWS_AFFECTED,
		       SUM_CREATED_TMP_TABLES, SUM_CREATED_TMP_DISK_TABLES,
		       SUM_MERGE_PASSES, SUM_NO_INDEX_USED, SUM_NO_GOOD_INDEX_USED
		FROM performance_schema.events_statements_summary_by_digest
		WHERE DIGEST_TEXT IS NOT NULL
		ORDER BY SUM_TIMER_WAIT DESC
		LIMIT ?`

	rows, err := db.QueryContext(ctx2, query, c.cfg.TopQueriesLimit)
	if err != nil {
		return nil, fmt.Errorf("query performance_schema: %w", err)
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

	currentSnapshot := make(map[string]*perfSchemaSnapshot)
	var buckets []qan.QANMetricsBucket
	labels := c.instanceLabels(inst)
	const picosPerSecond = 1e12

	for rows.Next() {
		var s perfSchemaSnapshot
		if err := rows.Scan(
			&s.digestText, &s.countStar,
			&s.sumTimerWait, &s.minTimerWait, &s.maxTimerWait,
			&s.sumLockTime, &s.sumRowsSent, &s.sumRowsExamined, &s.sumRowsAffected,
			&s.sumCreatedTmpTables, &s.sumCreatedTmpDiskTables,
			&s.sumMergePasses, &s.sumNoIndexUsed, &s.sumNoGoodIndexUsed,
		); err != nil {
			continue
		}

		digestKey := s.digestText
		currentSnapshot[digestKey] = &s

		prev, hasPrev := inst.prevSnapshot[digestKey]
		if !hasPrev {
			continue
		}

		deltaCount := int64(s.countStar) - int64(prev.countStar)
		if deltaCount <= 0 {
			continue
		}

		deltaTimerWait := float64(int64(s.sumTimerWait) - int64(prev.sumTimerWait))
		deltaLockTime := int64(s.sumLockTime) - int64(prev.sumLockTime)
		deltaRowsSent := int64(s.sumRowsSent) - int64(prev.sumRowsSent)
		deltaRowsExamined := int64(s.sumRowsExamined) - int64(prev.sumRowsExamined)
		deltaRowsAffected := int64(s.sumRowsAffected) - int64(prev.sumRowsAffected)
		deltaTmpTables := int64(s.sumCreatedTmpTables) - int64(prev.sumCreatedTmpTables)
		deltaTmpDiskTables := int64(s.sumCreatedTmpDiskTables) - int64(prev.sumCreatedTmpDiskTables)
		deltaMergePasses := int64(s.sumMergePasses) - int64(prev.sumMergePasses)
		deltaNoIndex := int64(s.sumNoIndexUsed) - int64(prev.sumNoIndexUsed)

		fp := fingerprintMySQL(s.digestText)
		example := s.digestText
		const maxExampleLen = 2000
		truncated := false
		if len(example) > maxExampleLen {
			example = example[:maxExampleLen]
			truncated = true
		}

		bucket := qan.QANMetricsBucket{
			AgentType:        qan.AgentTypeMySQLPerfSchema,
			QueryID:          fp,
			Fingerprint:      fp,
			Example:          example,
			ExampleTruncated: truncated,
			PeriodStartSec:   inst.prevTime.Unix(),
			PeriodLengthSec:  int64(periodLength.Seconds()),
			Database:         inst.config.Database,
			Username:         inst.config.Username,
			Labels:           labels,
			NumQueries:       float64(deltaCount),
			QueryTimeCnt:     float64(deltaCount),
			QueryTimeSum:     deltaTimerWait / picosPerSecond,
			QueryTimeMin:     float64(s.minTimerWait) / picosPerSecond,
			QueryTimeMax:     float64(s.maxTimerWait) / picosPerSecond,
			MySQL: &qan.MySQLQANMetrics{
				LockTimeCnt: float64(deltaCount),
				LockTimeSum: float64(deltaLockTime) / 1e9,
				LockTimeMin: 0,
				LockTimeMax: float64(s.sumLockTime) / 1e9,

				RowsSentCnt:     float64(deltaCount),
				RowsSentSum:     float64(deltaRowsSent),
				RowsExaminedCnt: float64(deltaCount),
				RowsExaminedSum: float64(deltaRowsExamined),
				RowsAffectedCnt: float64(deltaCount),
				RowsAffectedSum: float64(deltaRowsAffected),

				BytesSentCnt: float64(deltaCount),
				BytesSentSum: 0,

				TmpTablesCnt:     float64(deltaCount),
				TmpTablesSum:     float64(deltaTmpTables),
				TmpDiskTablesCnt: float64(deltaCount),
				TmpDiskTablesSum: float64(deltaTmpDiskTables),

				MergePassesCnt: float64(deltaCount),
				MergePassesSum: float64(deltaMergePasses),

				NoIndexUsedCnt: float64(deltaCount),
				NoIndexUsedSum: float64(deltaNoIndex),
			},
		}

		buckets = append(buckets, bucket)
	}

	inst.prevSnapshot = currentSnapshot
	inst.prevTime = now

	return buckets, nil
}

func (c *QANMySQLCollector) ensureConnection(ctx context.Context, inst *qanMySQLInstance) (*sql.DB, error) {
	if inst.db != nil {
		return inst.db, nil
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=10s&parseTime=true",
		inst.config.Username, inst.config.Password,
		inst.config.Host, inst.config.Port,
		inst.config.Database,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	inst.db = db
	return db, nil
}

func (c *QANMySQLCollector) instanceLabels(inst *qanMySQLInstance) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	labels["mysql_instance"] = inst.config.Name
	labels["mysql_host"] = inst.config.Host
	labels["db_system"] = "mysql"
	return labels
}

func fingerprintMySQL(digestText string) string {
	normalised := strings.ToUpper(strings.TrimSpace(digestText))
	normalised = strings.Join(strings.Fields(normalised), " ")
	h := sha256.Sum256([]byte(normalised))
	return fmt.Sprintf("%x", h[:16])
}
