// Package mysql exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// Exported wrappers for unexported symbols, exposed for external test packages.

// Exported function wrappers.

func SafeDivExport(num, denom float64) float64 { return safeDiv(num, denom) }
func ParseFloatExport(val string) float64      { return parseFloat(val) }
func ParseUintExport(val string) uint64        { return parseUint(val) }
func MakeMetricExport(name string, value float64, mtype collector.MetricType, labels map[string]string) collector.Metric {
	return makeMetric(name, value, mtype, labels)
}
func EmitCounterRateExport(name string, rate float64, labels map[string]string) collector.Metric {
	return emitCounterRate(name, rate, labels)
}
func BuildDSNExport(cfg config.MySQLInstanceConfig) string { return buildDSN(cfg) }
func ComputeRatesExport(prev, curr map[string]uint64, elapsedSec float64, labels map[string]string) []collector.Metric {
	return computeRates(prev, curr, elapsedSec, labels)
}
func ComputeDerivedMetricsExport(status map[string]uint64, vars map[string]string, labels map[string]string) []collector.Metric {
	return computeDerivedMetrics(status, vars, labels)
}
func EmitGaugeMetricsExport(rawStatus map[string]uint64, rows []statusRow, labels map[string]string) []collector.Metric {
	return emitGaugeMetrics(rawStatus, rows, labels)
}
func EmitVariableMetricsExport(vars map[string]string, labels map[string]string) []collector.Metric {
	return emitVariableMetrics(vars, labels)
}
func ParseReplicationRowExport(colMap map[string]string, labels map[string]string) []collector.Metric {
	return parseReplicationRow(colMap, labels)
}
func ParseBucketUpperMsExport(s string) float64 { return parseBucketUpperMs(s) }
func ComputePercentilesFromBucketsExport(buckets []QrtBucketExport, totalCount float64) (p50, p95, p99, pctBelow1ms, pctAbove100ms float64) {
	internal := make([]qrtBucket, len(buckets))
	for i, b := range buckets {
		internal[i] = qrtBucket{timeRange: b.TimeRange, count: b.Count, total: b.Total}
	}
	return computePercentilesFromBuckets(internal, totalCount)
}
func InitMariaDBExtensionExport() *MariaDBExtensionExport {
	return (*MariaDBExtensionExport)(initMariaDBExtension())
}
func InitPerconaExtensionExport() *PerconaExtensionExport {
	return (*PerconaExtensionExport)(initPerconaExtension())
}
func InstanceLabelsExport(inst *MySQLInstanceExport) map[string]string {
	return instanceLabels((*mysqlInstance)(inst))
}
func NewConfigExport(cfg config.MySQLCollectorConfig) Config { return NewConfig(cfg) }

// Exported type wrappers for unexported types.
// These use exported struct fields so test code can construct and inspect them.

type MySQLInstanceExport mysqlInstance

type MariaDBExtensionExport mariaDBExtension

type PerconaExtensionExport perconaExtension

// QrtBucketExport is the exported equivalent of qrtBucket.
type QrtBucketExport struct {
	TimeRange string
	Count     uint64
	Total     float64
}

// StatusRowExport is the exported equivalent of statusRow.
type StatusRowExport struct {
	Name  string
	Value uint64
}

// NewMySQLInstanceExport creates a mysqlInstance with the given config, flavor, version.
func NewMySQLInstanceExport(cfg config.MySQLInstanceConfig, flavor, version string) *MySQLInstanceExport {
	return (*MySQLInstanceExport)(&mysqlInstance{config: cfg, flavor: flavor, version: version})
}

// NewStatusRowExport creates a StatusRowExport with the given name and value.
func NewStatusRowExport(name string, value uint64) StatusRowExport {
	return StatusRowExport{Name: name, Value: value}
}

// NewQrtBucketExport creates a QrtBucketExport with the given fields.
func NewQrtBucketExport(timeRange string, count uint64) QrtBucketExport {
	return QrtBucketExport{TimeRange: timeRange, Count: count}
}

// ToStatusRows converts exported status rows to internal status rows.
func ToStatusRows(rows []StatusRowExport) []statusRow {
	result := make([]statusRow, len(rows))
	for i, r := range rows {
		result[i] = statusRow{name: r.Name, value: r.Value}
	}
	return result
}

// GetCollectorInstances returns instance configs for testing.
func GetCollectorInstances(c *MySQLCollector) []config.MySQLInstanceConfig {
	result := make([]config.MySQLInstanceConfig, len(c.instances))
	for i, inst := range c.instances {
		result[i] = inst.config
	}
	return result
}

// MariaDBExtensionExport field accessors.

func (e *MariaDBExtensionExport) QueryCacheEnabled() bool {
	return (*mariaDBExtension)(e).queryCacheEnabled
}

func (e *MariaDBExtensionExport) DetectedEngines() map[string]bool {
	return (*mariaDBExtension)(e).detectedEngines
}

func (e *MariaDBExtensionExport) DetectedPlugins() map[string]bool {
	return (*mariaDBExtension)(e).detectedPlugins
}

// PerconaExtensionExport field accessors.

func (e *PerconaExtensionExport) DetectedPlugins() map[string]bool {
	return (*perconaExtension)(e).detectedPlugins
}

func (e *PerconaExtensionExport) QueryResponseTimeEnabled() bool {
	return (*perconaExtension)(e).queryResponseTimeEnabled
}

// ComputeMariaDBQueryCacheFromStatus reproduces the query-cache metric logic
// using exported types only, so external test packages can verify it without
// database access.
func ComputeMariaDBQueryCacheFromStatus(status map[string]float64, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	hits := status["Qcache_hits"]
	inserts := status["Qcache_inserts"]
	total := hits + inserts
	hitRatio := safeDiv(hits, total)
	metrics = append(metrics, makeMetric("db.mysql.qcache.hit_ratio", hitRatio, collector.MetricTypeGauge, labels))

	freeBlocks := status["Qcache_free_blocks"]
	totalBlocks := status["Qcache_total_blocks"]
	fragmentation := safeDiv(freeBlocks, totalBlocks)
	metrics = append(metrics, makeMetric("db.mysql.qcache.fragmentation", fragmentation, collector.MetricTypeGauge, labels))

	if val, ok := status["Qcache_free_memory"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.free_memory", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Qcache_queries_in_cache"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.queries_in_cache", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Qcache_lowmem_prunes"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.lowmem_prunes", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Qcache_not_cached"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.not_cached", val, collector.MetricTypeGauge, labels))
	}
	return metrics
}

// ComputeMariaDBAriaFromStatus reproduces the Aria pagecache metric logic.
func ComputeMariaDBAriaFromStatus(status map[string]float64, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	readReqs := status["read_requests"]
	reads := status["reads"]
	hitRatio := 1 - safeDiv(reads, readReqs)
	metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.hit_ratio", hitRatio, collector.MetricTypeGauge, labels))
	if val, ok := status["blocks_used"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.blocks_used", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["blocks_unused"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.blocks_unused", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["blocks_not_flushed"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.blocks_not_flushed", val, collector.MetricTypeGauge, labels))
	}
	return metrics
}

// ComputeMariaDBThreadPoolFromStatus reproduces the thread-pool metric logic.
func ComputeMariaDBThreadPoolFromStatus(status map[string]float64, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	threads := status["Threadpool_threads"]
	active := status["Threadpool_active_threads"]
	idle := status["Threadpool_idle_threads"]
	metrics = append(metrics, makeMetric("db.mysql.threadpool.threads", threads, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.threadpool.active_threads", active, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.threadpool.idle_threads", idle, collector.MetricTypeGauge, labels))
	if val, ok := status["Threadpool_overflows"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.overflows", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Threadpool_waits"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.waits", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Threadpool_queues"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.queues", val, collector.MetricTypeGauge, labels))
	}
	utilization := safeDiv(active, threads)
	metrics = append(metrics, makeMetric("db.mysql.threadpool.utilization", utilization, collector.MetricTypeGauge, labels))
	return metrics
}

// UserStatsRowExport is the exported row type for user-stats tests.
type UserStatsRowExport struct {
	User            string
	TotalConns      float64
	ConcurrentConns float64
	CPUTime         float64
	RowsRead        float64
	RowsSent        float64
	RowsInserted    float64
	RowsUpdated     float64
	RowsDeleted     float64
	BusyTime        float64
	SelectCmds      float64
	UpdateCmds      float64
	OtherCmds       float64
}

// ComputeUserStatsFromRows emits per-user metrics from exported row data.
func ComputeUserStatsFromRows(rows []UserStatsRowExport, labels map[string]string) []collector.Metric {
	var allMetrics []collector.Metric
	for _, r := range rows {
		userLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			userLabels[k] = v
		}
		userLabels["user"] = r.User
		allMetrics = append(allMetrics,
			makeMetric("db.mysql.userstats.total_connections", r.TotalConns, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.concurrent_connections", r.ConcurrentConns, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.cpu_time", r.CPUTime, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.rows_read", r.RowsRead, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.rows_written", r.RowsInserted+r.RowsUpdated+r.RowsDeleted, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.busy_time", r.BusyTime, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.select_commands", r.SelectCmds, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.update_commands", r.UpdateCmds, collector.MetricTypeGauge, userLabels),
		)
	}
	return allMetrics
}
