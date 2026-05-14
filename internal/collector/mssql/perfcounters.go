package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

var perfCounterQueries = map[string]string{
	"buffer_cache_hit_ratio": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Buffer cache hit ratio'`,
	"buffer_cache_hit_ratio_base": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Buffer cache hit ratio base'`,
	"page_life_expectancy": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Page life expectancy'`,
	"batch_requests_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%SQL Statistics%' AND counter_name = 'Batch Requests/sec'`,
	"sql_compilations_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%SQL Statistics%' AND counter_name = 'SQL Compilations/sec'`,
	"sql_recompilations_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%SQL Statistics%' AND counter_name = 'SQL Re-Compilations/sec'`,
	"user_connections": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%General Statistics%' AND counter_name = 'User Connections'`,
	"processes_blocked": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%General Statistics%' AND counter_name = 'Processes blocked'`,
	"deadlocks_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Locks%' AND counter_name = 'Number of Deadlocks/sec' AND instance_name = '_Total'`,
	"memory_grants_pending": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Memory Manager%' AND counter_name = 'Memory Grants Pending'`,
	"target_server_memory_kb": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Memory Manager%' AND counter_name = 'Target Server Memory (KB)'`,
	"total_server_memory_kb": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Memory Manager%' AND counter_name = 'Total Server Memory (KB)'`,
	"checkpoint_pages_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Checkpoint pages/sec'`,
	"lazy_writes_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Lazy writes/sec'`,
	"page_reads_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Page reads/sec'`,
	"page_writes_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Buffer Manager%' AND counter_name = 'Page writes/sec'`,
	"transactions_per_sec": `
		SELECT cntr_value FROM sys.dm_os_performance_counters
		WHERE object_name LIKE '%Databases%' AND counter_name = 'Transactions/sec' AND instance_name = '_Total'`,
}

func collectPerfCounters(ctx context.Context, db *sql.DB, inst *mssqlInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	now := time.Now()
	counters := make(map[string]float64)

	for name, query := range perfCounterQueries {
		var val float64
		if err := db.QueryRowContext(ctx, query).Scan(&val); err != nil {
			if err != sql.ErrNoRows {
				logger.Debug("Perf counter query failed", zap.String("counter", name), zap.Error(err))
			}
			continue
		}
		counters[name] = val
	}

	var all []collector.Metric

	bhr := safeDiv(counters["buffer_cache_hit_ratio"], counters["buffer_cache_hit_ratio_base"]) * 100
	all = append(all, makeMetric("mssql.buffer_cache_hit_ratio", bhr, collector.MetricTypeGauge, labels))

	rateCounters := []string{
		"batch_requests_per_sec", "sql_compilations_per_sec", "sql_recompilations_per_sec",
		"deadlocks_per_sec", "checkpoint_pages_per_sec", "lazy_writes_per_sec",
		"page_reads_per_sec", "page_writes_per_sec", "transactions_per_sec",
	}
	for _, name := range rateCounters {
		if val, ok := counters[name]; ok {
			if prev, ok := inst.prevCounters[name]; ok && !inst.prevTimestamp.IsZero() {
				elapsed := now.Sub(inst.prevTimestamp).Seconds()
				rate := safeDiv(val-prev, elapsed)
				all = append(all, emitCounterRate("mssql."+name, rate, labels))
			}
		}
	}

	gaugeCounters := []string{
		"page_life_expectancy", "user_connections", "processes_blocked",
		"memory_grants_pending", "target_server_memory_kb", "total_server_memory_kb",
	}
	for _, name := range gaugeCounters {
		if val, ok := counters[name]; ok {
			all = append(all, makeMetric("mssql."+name, val, collector.MetricTypeGauge, labels))
		}
	}

	inst.prevCounters = counters
	inst.prevTimestamp = now

	return all, nil
}

var _ = queryCounter

func queryCounter(ctx context.Context, db *sql.DB, query string) (float64, error) {
	var val float64
	err := db.QueryRowContext(ctx, query).Scan(&val)
	if err != nil {
		return 0, fmt.Errorf("query counter: %w", err)
	}
	return val, nil
}
