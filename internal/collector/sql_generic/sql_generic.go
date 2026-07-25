// Package sql_generic implements a generic SQL collector that runs user-defined
// queries against any database/sql driver and emits the results as metrics.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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
package sql_generic

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "sql_generic"

// DBFactory opens a *sql.DB for a given driver/dsn pair. The default
// implementation is sql.Open; tests may inject a fake via SetDBFactory.
type DBFactory func(driverName, dsn string) (*sql.DB, error)

// SQLGenericCollector runs user-defined SQL queries against any database/sql
// driver and emits one metric per result row. It implements collector.Collector.
type SQLGenericCollector struct {
	cfg    config.SQLGenericCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	dbs       map[string]*sql.DB // keyed by instance name
	dbFactory DBFactory
}

// NewSQLGenericCollector creates a new collector and opens every configured
// instance connection up front (fail-fast on a bad driver/DSN).
func NewSQLGenericCollector(cfg config.SQLGenericCollectorConfig, logger *zap.Logger) (*SQLGenericCollector, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	c := &SQLGenericCollector{
		cfg:       cfg,
		logger:    logger.Named(collectorName),
		stopChan:  make(chan struct{}),
		dbs:       make(map[string]*sql.DB),
		dbFactory: sql.Open,
	}
	if err := c.openInstances(); err != nil {
		for _, db := range c.dbs {
			_ = db.Close()
		}
		return nil, err
	}
	return c, nil
}

func (c *SQLGenericCollector) openInstances() error {
	for _, inst := range c.cfg.Instances {
		if inst.Name == "" {
			return fmt.Errorf("sql_generic: instance with empty name")
		}
		if _, ok := c.dbs[inst.Name]; ok {
			continue
		}
		db, err := c.dbFactory(inst.Driver, inst.DSN)
		if err != nil {
			return fmt.Errorf("instance %q: %w", inst.Name, err)
		}
		c.dbs[inst.Name] = db
	}
	return nil
}

// SetDBFactory replaces the DB factory used to open connections and reopens
// every configured instance. It is exported as a test seam for injecting fake
// *sql.DB instances; production code does not need to call it.
func (c *SQLGenericCollector) SetDBFactory(f DBFactory) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.dbFactory = f
	for name, db := range c.dbs {
		_ = db.Close()
		delete(c.dbs, name)
	}
	for _, inst := range c.cfg.Instances {
		db, err := f(inst.Driver, inst.DSN)
		if err != nil {
			c.logger.Warn("SetDBFactory: failed to open instance",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		c.dbs[inst.Name] = db
	}
}

// Name returns the collector name.
func (c *SQLGenericCollector) Name() string { return collectorName }

// IsRunning reports whether the collector is running.
func (c *SQLGenericCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start marks the collector as running and blocks until Stop is called or the
// context is cancelled.
func (c *SQLGenericCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("sql_generic collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("sql_generic collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)

	select {
	case <-c.stopChan:
		return nil
	case <-ctx.Done():
		return c.Stop()
	}
}

// Stop gracefully stops the collector and closes all database connections.
func (c *SQLGenericCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("sql_generic collector stopping")
	c.running = false
	close(c.stopChan)

	for _, db := range c.dbs {
		_ = db.Close()
	}
	c.dbs = make(map[string]*sql.DB)
	return nil
}

// Collect runs every configured query across all instances and returns the
// emitted metrics. Per-query and per-instance errors are logged and skipped;
// Collect itself only fails when no work can be done.
func (c *SQLGenericCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}

	var all []collector.Metric
	now := time.Now()

	for _, inst := range c.cfg.Instances {
		c.mu.RLock()
		db := c.dbs[inst.Name]
		c.mu.RUnlock()
		if db == nil {
			c.logger.Warn("no database connection for instance",
				zap.String("instance", inst.Name),
			)
			continue
		}

		for _, q := range inst.Queries {
			metrics, err := c.collectQuery(ctx, db, inst, q, now)
			if err != nil {
				c.logger.Warn("query failed",
					zap.String("instance", inst.Name),
					zap.String("metric", q.Metric),
					zap.Error(err),
				)
				continue
			}
			all = append(all, metrics...)
		}
	}

	return all, nil
}

func (c *SQLGenericCollector) collectQuery(
	ctx context.Context,
	db *sql.DB,
	inst config.SQLGenericInstance,
	q config.SQLQuery,
	now time.Time,
) ([]collector.Metric, error) {
	queryCtx := ctx
	if inst.Timeout > 0 {
		var cancel context.CancelFunc
		queryCtx, cancel = context.WithTimeout(ctx, inst.Timeout)
		defer cancel()
	}

	rows, err := db.QueryContext(queryCtx, q.SQL)
	if err != nil {
		return nil, fmt.Errorf("query %q: %w", q.Metric, err)
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("columns %q: %w", q.Metric, err)
	}

	mtype := metricType(q.Type)
	valueIdx, labelIdx := indexColumns(cols, q.ValueColumn, q.LabelColumns)

	var out []collector.Metric
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			c.logger.Warn("row scan failed",
				zap.String("instance", inst.Name),
				zap.String("metric", q.Metric),
				zap.Error(err),
			)
			continue
		}

		m := collector.Metric{
			Name:      q.Metric,
			Type:      mtype,
			Timestamp: now,
			Unit:      q.Unit,
			Labels:    make(map[string]string, len(labelIdx)+1),
		}
		m.Labels["sql_instance"] = inst.Name

		if valueIdx >= 0 {
			m.Value = toFloat(vals[valueIdx])
		}
		for col, idx := range labelIdx {
			m.Labels[col] = toString(vals[idx])
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("rows %q: %w", q.Metric, err)
	}
	return out, nil
}

// indexColumns resolves the index of the value column and the indices of the
// label columns within the result set. Missing columns are silently ignored.
func indexColumns(cols []string, valueColumn string, labelColumns []string) (int, map[string]int) {
	valueIdx := -1
	for i, c := range cols {
		if c == valueColumn {
			valueIdx = i
			break
		}
	}

	labels := make(map[string]int)
	for _, lc := range labelColumns {
		for i, c := range cols {
			if c == lc {
				labels[lc] = i
				break
			}
		}
	}
	return valueIdx, labels
}

func metricType(t string) collector.MetricType {
	switch strings.ToLower(t) {
	case "counter":
		return collector.MetricTypeCounter
	case "histogram":
		return collector.MetricTypeHistogram
	case "summary":
		return collector.MetricTypeSummary
	default: // "", "gauge"
		return collector.MetricTypeGauge
	}
}

func toFloat(v interface{}) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case int:
		return float64(x)
	case int8:
		return float64(x)
	case int16:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case uint:
		return float64(x)
	case uint8:
		return float64(x)
	case uint16:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case float32:
		return float64(x)
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	case []byte:
		f, _ := strconv.ParseFloat(string(x), 64)
		return f
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func toString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}
