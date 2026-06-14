package sqlite3

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "sqlite3"

type SQLite3Collector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	databases []*sqliteDatabase
}

func NewSQLite3Collector(cfg config.SQLite3CollectorConfig, logger *zap.Logger) *SQLite3Collector {
	c := NewConfig(cfg)

	databases := make([]*sqliteDatabase, 0)
	for _, db := range c.Databases {
		databases = append(databases, &sqliteDatabase{
			config:     db,
			prevPragma: make(map[string]string),
		})
	}

	return &SQLite3Collector{
		cfg:       c,
		logger:    logger.Named(collectorName),
		databases: databases,
	}
}

func (c *SQLite3Collector) Name() string { return collectorName }

func (c *SQLite3Collector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *SQLite3Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("sqlite3 collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("SQLite3 collector starting",
		zap.Int("databases", len(c.cfg.Databases)),
	)

	select {
	case <-c.stopChan:
		return nil
	case <-ctx.Done():
		return c.Stop()
	}
}

func (c *SQLite3Collector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("SQLite3 collector stopping")
	c.running = false
	close(c.stopChan)

	for _, db := range c.databases {
		if db.db != nil {
			_ = db.db.Close()
			db.db = nil
		}
	}
	return nil
}

func (c *SQLite3Collector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.databases) == 0 {
		return nil, nil
	}

	type result struct {
		metrics []collector.Metric
		err     error
		idx     int
	}

	results := make([]result, len(c.databases))
	var wg sync.WaitGroup

	for i, db := range c.databases {
		wg.Add(1)
		go func(idx int, d *sqliteDatabase) {
			defer wg.Done()
			m, err := c.collectDatabase(ctx, d)
			results[idx] = result{metrics: m, err: err, idx: idx}
		}(i, db)
	}
	wg.Wait()

	var all []collector.Metric
	for _, r := range results {
		if r.err != nil {
			c.logger.Warn("Collection failed for database",
				zap.String("database", c.databases[r.idx].config.Name),
				zap.Error(r.err),
			)
			continue
		}
		all = append(all, r.metrics...)
	}

	if ts, err := c.collectAllTableStats(ctx); err != nil {
		c.logger.Warn("Table stats collection failed", zap.Error(err))
	} else {
		all = append(all, ts...)
	}

	if ps, err := c.collectAllProcesses(ctx); err != nil {
		c.logger.Warn("Process collection failed", zap.Error(err))
	} else {
		all = append(all, ps...)
	}

	if c.cfg.IntegrityInterval > 0 {
		if im, err := c.collectAllIntegrity(ctx); err != nil {
			c.logger.Warn("Integrity check failed", zap.Error(err))
		} else {
			all = append(all, im...)
		}
	}

	return all, nil
}

func (c *SQLite3Collector) collectDatabase(ctx context.Context, sdb *sqliteDatabase) ([]collector.Metric, error) {
	db, err := c.ensureConnection(ctx, sdb)
	if err != nil {
		return nil, err
	}

	labels := instanceLabels(sdb)
	var all []collector.Metric

	fileMetrics, err := c.collectFileMetrics(sdb, labels)
	if err != nil {
		c.logger.Warn("File metrics failed", zap.String("database", sdb.config.Name), zap.Error(err))
	} else {
		all = append(all, fileMetrics...)
	}

	pragmaMetrics, pragmaVals, err := c.collectPragmaMetrics(ctx, db, sdb, labels)
	if err != nil {
		c.logger.Warn("PRAGMA metrics failed", zap.String("database", sdb.config.Name), zap.Error(err))
	} else {
		all = append(all, pragmaMetrics...)
	}

	cacheMetrics, err := c.collectCacheMetrics(ctx, db, labels)
	if err != nil {
		c.logger.Warn("Cache metrics failed", zap.String("database", sdb.config.Name), zap.Error(err))
	} else {
		all = append(all, cacheMetrics...)
	}

	lockMetrics, err := c.collectLockMetrics(ctx, db, sdb, labels)
	if err != nil {
		c.logger.Warn("Lock metrics failed", zap.String("database", sdb.config.Name), zap.Error(err))
	} else {
		all = append(all, lockMetrics...)
	}

	if pragmaVals != nil {
		utilization := safeDiv(float64(pragmaVals.PageCount-pragmaVals.FreelistCount), float64(pragmaVals.PageCount)) * 100
		all = append(all, makeMetric("db.sqlite3.utilization", utilization, collector.MetricTypeGauge, labels, "%"))
	}

	c.logger.Debug("SQLite3 database collected",
		zap.String("database", sdb.config.Name),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

func (c *SQLite3Collector) collectFileMetrics(sdb *sqliteDatabase, labels map[string]string) ([]collector.Metric, error) {
	var all []collector.Metric

	dbPath := sdb.config.Path
	if stat, err := os.Stat(dbPath); err == nil {
		all = append(all, makeMetric("db.sqlite3.file.size", float64(stat.Size()), collector.MetricTypeGauge, labels, "bytes"))
	}

	walPath := dbPath + "-wal"
	if stat, err := os.Stat(walPath); err == nil {
		all = append(all, makeMetric("db.sqlite3.file.wal_size", float64(stat.Size()), collector.MetricTypeGauge, labels, "bytes"))
	}

	shmPath := dbPath + "-shm"
	if stat, err := os.Stat(shmPath); err == nil {
		all = append(all, makeMetric("db.sqlite3.file.shm_size", float64(stat.Size()), collector.MetricTypeGauge, labels, "bytes"))
	}

	return all, nil
}

func (c *SQLite3Collector) collectPragmaMetrics(ctx context.Context, db *sql.DB, sdb *sqliteDatabase, labels map[string]string) ([]collector.Metric, *pragmaValues, error) {
	var all []collector.Metric
	pv := &pragmaValues{}

	pragmaIntQueries := map[string]*int64{
		"page_count":         &pv.PageCount,
		"page_size":          &pv.PageSize,
		"freelist_count":     &pv.FreelistCount,
		"auto_vacuum":        &pv.AutoVacuum,
		"schema_version":     &pv.SchemaVersion,
		"data_version":       &pv.DataVersion,
		"cache_size":         &pv.CacheSize,
		"mmap_size":          &pv.MmapSize,
		"wal_autocheckpoint": &pv.WalAutocheckpoint,
		"busy_timeout":       &pv.BusyTimeout,
	}

	for name, target := range pragmaIntQueries {
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := db.QueryRowContext(ctx2, fmt.Sprintf("PRAGMA %s", name)).Scan(target)
		cancel()
		if err != nil {
			c.logger.Debug("PRAGMA query failed", zap.String("pragma", name), zap.Error(err))
			continue
		}
		all = append(all, makeMetric(fmt.Sprintf("db.sqlite3.page.%s", name), float64(*target), collector.MetricTypeGauge, labels, ""))
	}

	pragmaStringQueries := map[string]*string{
		"journal_mode": &pv.JournalMode,
		"synchronous":  &pv.Synchronous,
		"locking_mode": &pv.LockingMode,
	}

	for name, target := range pragmaStringQueries {
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := db.QueryRowContext(ctx2, fmt.Sprintf("PRAGMA %s", name)).Scan(target)
		cancel()
		if err != nil {
			continue
		}
	}

	all = append(all,
		makeMetric("db.sqlite3.page.count", float64(pv.PageCount), collector.MetricTypeGauge, labels, ""),
		makeMetric("db.sqlite3.page.size", float64(pv.PageSize), collector.MetricTypeGauge, labels, "bytes"),
		makeMetric("db.sqlite3.freelist.count", float64(pv.FreelistCount), collector.MetricTypeGauge, labels, ""),
	)

	if pv.PageSize > 0 {
		effectiveSize := float64(pv.PageCount * pv.PageSize)
		all = append(all, makeMetric("db.sqlite3.file.effective_size", effectiveSize, collector.MetricTypeGauge, labels, "bytes"))
	}

	for k, v := range map[string]string{
		"journal_mode": pv.JournalMode,
		"synchronous":  pv.Synchronous,
		"locking_mode": pv.LockingMode,
	} {
		if v != "" && v != sdb.prevPragma[k] {
			if sdb.prevPragma[k] != "" {
				c.logger.Info("PRAGMA value changed",
					zap.String("database", sdb.config.Name),
					zap.String("pragma", k),
					zap.String("old", sdb.prevPragma[k]),
					zap.String("new", v),
				)
			}
			sdb.prevPragma[k] = v
		}
	}

	return all, pv, nil
}

func (c *SQLite3Collector) collectCacheMetrics(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	var all []collector.Metric

	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "PRAGMA cache_status")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var schema, status string
		if err := rows.Scan(&schema, &status); err != nil {
			continue
		}
		_ = schema
		_ = status
	}

	return all, nil
}

func (c *SQLite3Collector) collectLockMetrics(ctx context.Context, db *sql.DB, sdb *sqliteDatabase, labels map[string]string) ([]collector.Metric, error) {
	var all []collector.Metric

	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var busyCount uint64
	err := db.QueryRowContext(ctx2, "PRAGMA wal_checkpoint(PASSIVE)").Scan(nil, nil, nil)
	if err != nil {
		c.logger.Debug("WAL checkpoint query failed", zap.String("database", sdb.config.Name), zap.Error(err))
	}

	all = append(all, makeMetric("db.sqlite3.busy.count", float64(busyCount), collector.MetricTypeCounter, labels, ""))

	walPath := sdb.config.Path + "-wal"
	if stat, err := os.Stat(walPath); err == nil {
		all = append(all, makeMetric("db.sqlite3.wal.size", float64(stat.Size()), collector.MetricTypeGauge, labels, "bytes"))
	}

	sdb.prevBusy = busyCount
	return all, nil
}

func (c *SQLite3Collector) collectAllTableStats(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, sdb := range c.databases {
		db, err := c.ensureConnection(ctx, sdb)
		if err != nil {
			continue
		}
		metrics, err := c.collectTableStats(ctx, db, sdb, instanceLabels(sdb))
		if err != nil {
			c.logger.Warn("Table stats failed", zap.String("database", sdb.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *SQLite3Collector) collectTableStats(ctx context.Context, db *sql.DB, sdb *sqliteDatabase, labels map[string]string) ([]collector.Metric, error) {
	var all []collector.Metric

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name, tblType string
		if err := rows.Scan(&name, &tblType); err != nil {
			continue
		}

		tableLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			tableLabels[k] = v
		}
		tableLabels["table_name"] = name

		if tblType == "table" {
			var maxRowID int64
			ctx3, cancel2 := context.WithTimeout(ctx, 10*time.Second)
			err := db.QueryRowContext(ctx3, fmt.Sprintf("SELECT MAX(rowid) FROM \"%s\"", name)).Scan(&maxRowID)
			cancel2()
			if err == nil {
				all = append(all, makeMetric("db.sqlite3.table.approx_rows", float64(maxRowID), collector.MetricTypeGauge, tableLabels, ""))
			}
		}

		all = append(all, makeMetric("db.sqlite3.table.count", 1, collector.MetricTypeGauge, tableLabels, ""))
	}

	dbstatAvailable := false
	ctx3, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	var dummy int
	err = db.QueryRowContext(ctx3, "SELECT 1 FROM dbstat LIMIT 1").Scan(&dummy)
	cancel2()
	if err == nil {
		dbstatAvailable = true
	}

	if dbstatAvailable {
		ctx3, cancel2 := context.WithTimeout(ctx, 30*time.Second)
		rows, err := db.QueryContext(ctx3, "SELECT name, sum(pgcount) as page_count, sum(pgsize - used) as unused FROM dbstat GROUP BY name")
		cancel2()
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var tblName string
				var pageCount, unused int64
				if err := rows.Scan(&tblName, &pageCount, &unused); err != nil {
					continue
				}
				tableLabels := make(map[string]string, len(labels)+1)
				for k, v := range labels {
					tableLabels[k] = v
				}
				tableLabels["table_name"] = tblName
				all = append(all,
					makeMetric("db.sqlite3.table.page_count", float64(pageCount), collector.MetricTypeGauge, tableLabels, ""),
				)
				if pageCount > 0 {
					unusedPct := safeDiv(float64(unused), float64(pageCount)) * 100
					all = append(all, makeMetric("db.sqlite3.table.unused_pct", unusedPct, collector.MetricTypeGauge, tableLabels, "%"))
				}
			}
		}
	}

	return all, nil
}

func (c *SQLite3Collector) collectAllProcesses(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, sdb := range c.databases {
		metrics, err := c.collectProcessInfo(sdb, instanceLabels(sdb))
		if err != nil {
			c.logger.Debug("Process collection failed", zap.String("database", sdb.config.Name), zap.Error(err))
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *SQLite3Collector) collectProcessInfo(sdb *sqliteDatabase, labels map[string]string) ([]collector.Metric, error) {
	var all []collector.Metric
	var processCount int

	switch runtime.GOOS {
	case "linux":
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			fdDir := filepath.Join("/proc", entry.Name(), "fd")
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
				if err != nil {
					continue
				}
				if link == sdb.config.Path {
					processCount++
					break
				}
			}
		}
	case "darwin":
		processCount = 0
	default:
		return nil, fmt.Errorf("unsupported OS for process enumeration: %s", runtime.GOOS)
	}

	all = append(all, makeMetric("db.sqlite3.process.count", float64(processCount), collector.MetricTypeGauge, labels, ""))
	return all, nil
}

func (c *SQLite3Collector) collectAllIntegrity(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric
	for _, sdb := range c.databases {
		sdb.mu.Lock()
		if sdb.checking {
			sdb.mu.Unlock()
			continue
		}
		sdb.checking = true
		sdb.mu.Unlock()

		db, err := c.ensureConnection(ctx, sdb)
		if err != nil {
			sdb.mu.Lock()
			sdb.checking = false
			sdb.mu.Unlock()
			continue
		}

		labels := instanceLabels(sdb)
		integrityLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			integrityLabels[k] = v
		}
		integrityLabels["check_type"] = "integrity_check"

		start := time.Now()
		ctx2, cancel := context.WithTimeout(ctx, c.cfg.IntegrityTimeout)
		var result string
		err = db.QueryRowContext(ctx2, "PRAGMA integrity_check").Scan(&result)
		cancel()
		duration := time.Since(start)

		sdb.mu.Lock()
		sdb.checking = false
		sdb.mu.Unlock()

		if err != nil {
			integrityLabels["status"] = "ERROR"
			all = append(all,
				makeMetric("db.sqlite3.integrity", 1, collector.MetricTypeGauge, integrityLabels, ""),
				makeMetric("db.sqlite3.integrity.duration_ms", float64(duration.Milliseconds()), collector.MetricTypeGauge, integrityLabels, "ms"),
			)
			continue
		}

		status := "PASS"
		if result != "ok" {
			status = "FAIL"
		}
		integrityLabels["status"] = status

		all = append(all,
			makeMetric("db.sqlite3.integrity", 1, collector.MetricTypeGauge, integrityLabels, ""),
			makeMetric("db.sqlite3.integrity.duration_ms", float64(duration.Milliseconds()), collector.MetricTypeGauge, integrityLabels, "ms"),
		)
	}
	return all, nil
}

func (c *SQLite3Collector) ensureConnection(ctx context.Context, sdb *sqliteDatabase) (*sql.DB, error) {
	if sdb.db != nil {
		if err := sdb.db.PingContext(ctx); err == nil {
			return sdb.db, nil
		}
		_ = sdb.db.Close()
		sdb.db = nil
	}

	db, err := sql.Open("sqlite3", sdb.config.Path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("sqlite3 %s: open: %w", sdb.config.Name, err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx2); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite3 %s: ping: %w", sdb.config.Name, err)
	}

	sdb.db = db
	c.logger.Info("Connected to SQLite3 database",
		zap.String("database", sdb.config.Name),
		zap.String("path", sdb.config.Path),
	)
	return db, nil
}

func instanceLabels(sdb *sqliteDatabase) map[string]string {
	labels := map[string]string{
		"sqlite3_database": sdb.config.Name,
		"sqlite3_path":     sdb.config.Path,
	}
	for k, v := range sdb.config.Tags {
		labels[k] = v
	}
	return labels
}

func makeMetric(name string, value float64, mtype collector.MetricType, labels map[string]string, unit string) collector.Metric {
	m := collector.Metric{
		Name:      name,
		Type:      mtype,
		Value:     value,
		Timestamp: time.Now(),
		Labels:    make(map[string]string, len(labels)),
		Unit:      unit,
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
