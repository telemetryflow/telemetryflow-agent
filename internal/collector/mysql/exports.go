// Package mysql exposes unexported symbols for external test packages.
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

package mysql

import (
	"context"
	"database/sql"

	"go.uber.org/zap"

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

// ----------------------------------------------------------------------------
// Database-backed test seams. These wrap unexported collect functions so that
// external test packages can drive them with github.com/DATA-DOG/go-sqlmock.
// ----------------------------------------------------------------------------

// CollectGlobalStatusExport wraps collectGlobalStatus.
func CollectGlobalStatusExport(ctx context.Context, db *sql.DB) ([]StatusRowExport, map[string]uint64, error) {
	rows, raw, err := collectGlobalStatus(ctx, db)
	out := make([]StatusRowExport, len(rows))
	for i, r := range rows {
		out[i] = StatusRowExport{Name: r.name, Value: r.value}
	}
	return out, raw, err
}

// CollectGlobalVariablesExport wraps collectGlobalVariables.
func CollectGlobalVariablesExport(ctx context.Context, db *sql.DB) (map[string]string, error) {
	return collectGlobalVariables(ctx, db)
}

// CollectInnoDBStatusExport wraps collectInnoDBStatus.
func CollectInnoDBStatusExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectInnoDBStatus(ctx, db, labels)
}

// ParseInnoDBStatusSectionsExport wraps parseInnoDBStatus for direct parsing tests.
func ParseInnoDBStatusSectionsExport(status string) map[string]string {
	return parseInnoDBStatus(status)
}

// ParseBufferPoolSectionExport wraps parseBufferPoolSection.
func ParseBufferPoolSectionExport(content string, labels map[string]string) []collector.Metric {
	return parseBufferPoolSection(content, labels)
}

// ParseRowOperationsSectionExport wraps parseRowOperationsSection.
func ParseRowOperationsSectionExport(content string, labels map[string]string) []collector.Metric {
	return parseRowOperationsSection(content, labels)
}

// ExtractNumberExport wraps extractNumber.
func ExtractNumberExport(line string) float64 { return extractNumber(line) }

// CollectReplicationStatusExport wraps collectReplicationStatus.
func CollectReplicationStatusExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectReplicationStatus(ctx, db, labels)
}

// ToStrExport wraps toStr.
func ToStrExport(v interface{}) string { return toStr(v) }

// CollectGaleraStatusExport wraps collectGaleraStatus.
func CollectGaleraStatusExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectGaleraStatus(ctx, db, labels)
}

// CollectSchemaExport wraps collectSchema.
func CollectSchemaExport(ctx context.Context, db *sql.DB, cfg config.MySQLInstanceConfig, labels map[string]string) ([]collector.Metric, error) {
	return collectSchema(ctx, db, cfg, labels, zap.NewNop())
}

// GetAutoIncrMaxExport wraps getAutoIncrMax.
func GetAutoIncrMaxExport(engine string) int64 { return getAutoIncrMax(engine) }

// CollectQueryAnalyticsExport wraps collectQueryAnalytics against an exported instance.
func CollectQueryAnalyticsExport(ctx context.Context, db *sql.DB, inst *MySQLInstanceExport, labels map[string]string) ([]collector.Metric, error) {
	return collectQueryAnalytics(ctx, db, (*mysqlInstance)(inst), labels, zap.NewNop())
}

// SetPrevDigestExport seeds a previous digest snapshot on the exported instance.
func SetPrevDigestExport(inst *MySQLInstanceExport, digest string, countStar, sumTimerWait, rowsSent, rowsExam uint64) {
	real := (*mysqlInstance)(inst)
	if real.prevDigests == nil {
		real.prevDigests = make(map[string]*digestSnapshot)
	}
	real.prevDigests[digest] = &digestSnapshot{
		CountStar:    countStar,
		SumTimerWait: sumTimerWait,
		SumRowsSent:  rowsSent,
		SumRowsExam:  rowsExam,
	}
}

// MariaDB collect wrappers.

func DetectMariaDBEnginesExport(ctx context.Context, db *sql.DB) (*MariaDBExtensionExport, error) {
	ext := initMariaDBExtension()
	err := detectMariaDBEngines(ctx, db, ext)
	return (*MariaDBExtensionExport)(ext), err
}

func DetectMariaDBPluginsExport(ctx context.Context, db *sql.DB, vars map[string]string) (*MariaDBExtensionExport, error) {
	ext := initMariaDBExtension()
	err := detectMariaDBPlugins(ctx, db, ext, vars)
	return (*MariaDBExtensionExport)(ext), err
}

func CollectMariaDBQueryCacheExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBQueryCache(ctx, db, labels)
}

func CollectMariaDBAriaExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBAria(ctx, db, labels)
}

func CollectMariaDBColumnStoreExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBColumnStore(ctx, db, labels)
}

func CollectMariaDBSpiderExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBSpider(ctx, db, labels)
}

func CollectMariaDBThreadPoolExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBThreadPool(ctx, db, labels)
}

func CollectMariaDBMultiSourceReplicationExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBMultiSourceReplication(ctx, db, labels)
}

func CollectMariaDBUserStatsExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectMariaDBUserStats(ctx, db, labels)
}

// Percona collect wrappers.

func DetectPerconaPluginsExport(ctx context.Context, db *sql.DB) (*PerconaExtensionExport, error) {
	ext := initPerconaExtension()
	err := detectPerconaPlugins(ctx, db, ext)
	return (*PerconaExtensionExport)(ext), err
}

func CollectPerconaQueryResponseTimeExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaQueryResponseTime(ctx, db, labels)
}

func CollectPerconaUserStatsExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaUserStats(ctx, db, labels)
}

func CollectPerconaThreadPoolExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaThreadPool(ctx, db, labels)
}

func CollectPerconaPXCExport(ctx context.Context, db *sql.DB, rawStatus map[string]uint64, vars, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaPXC(ctx, db, rawStatus, vars, labels)
}

func CollectPerconaXtraBackupExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaXtraBackup(ctx, db, labels)
}

func CollectPerconaAuditExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaAudit(ctx, db, labels)
}

func CollectPerconaEnhancedSlowQueryExport(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	return collectPerconaEnhancedSlowQuery(ctx, db, labels)
}

// DetectFlavorExport wraps detectFlavor on a collector's first instance and
// returns the detected flavor/version.
func DetectFlavorExport(c *MySQLCollector, ctx context.Context, db *sql.DB) (string, string, error) {
	inst := c.instances[0]
	err := c.detectFlavor(ctx, inst, db)
	return inst.flavor, inst.version, err
}

// SetInstanceDBExport injects a *sql.DB into the first instance.
func SetInstanceDBExport(c *MySQLCollector, db *sql.DB) { c.instances[0].db = db }

// SetInstanceFlavorExport sets the flavor of the first instance.
func SetInstanceFlavorExport(c *MySQLCollector, flavor string) { c.instances[0].flavor = flavor }

// PrimeMariaDBExport enables all MariaDB sub-collectors on the first instance.
func PrimeMariaDBExport(c *MySQLCollector) {
	ext := initMariaDBExtension()
	ext.queryCacheEnabled = true
	ext.ariaStatsEnabled = true
	ext.columnStoreStatsEnabled = true
	ext.spiderStatsEnabled = true
	ext.threadPoolStatsEnabled = true
	ext.userStatsEnabled = true
	c.instances[0].mariadb = ext
}

// PrimePerconaExport enables all Percona sub-collectors on the first instance.
func PrimePerconaExport(c *MySQLCollector) {
	ext := initPerconaExtension()
	ext.queryResponseTimeEnabled = true
	ext.userStatsEnabled = true
	ext.enhancedSlowQueryEnabled = true
	ext.auditMetricsEnabled = true
	c.instances[0].percona = ext
}

// CollectMariaDBExport wraps collectMariaDB for the first instance (detection runs).
func CollectMariaDBExport(c *MySQLCollector, ctx context.Context, db *sql.DB, labels, vars map[string]string) []collector.Metric {
	return c.collectMariaDB(ctx, c.instances[0], db, labels, vars)
}

// CollectPerconaExport wraps collectPercona for the first instance (detection runs).
func CollectPerconaExport(c *MySQLCollector, ctx context.Context, db *sql.DB, labels, vars map[string]string, rawStatus map[string]uint64) []collector.Metric {
	return c.collectPercona(ctx, c.instances[0], db, labels, vars, rawStatus)
}

// CollectInstanceExport wraps collectInstance for the first instance.
func CollectInstanceExport(c *MySQLCollector, ctx context.Context) ([]collector.Metric, error) {
	return c.collectInstance(ctx, c.instances[0])
}

// SetInstancePrevStatusExport seeds prevStatus so rate computation runs.
func SetInstancePrevStatusExport(c *MySQLCollector, prev map[string]uint64) {
	c.instances[0].prevStatus = prev
}

// EnsureConnectionErrExport exercises ensureConnection and returns the error.
func EnsureConnectionErrExport(c *MySQLCollector, ctx context.Context) error {
	_, err := c.ensureConnection(ctx, c.instances[0])
	return err
}

// AdvanceBackoffExport exercises advanceBackoff on the first instance.
func AdvanceBackoffExport(c *MySQLCollector) { c.advanceBackoff(c.instances[0]) }

// FingerprintMySQLExport wraps fingerprintMySQL.
func FingerprintMySQLExport(digestText string) string { return fingerprintMySQL(digestText) }

// SetQANInstanceDBExport injects a *sql.DB into the first QAN instance.
func SetQANInstanceDBExport(c *QANMySQLCollector, db *sql.DB) { c.instances[0].db = db }

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
