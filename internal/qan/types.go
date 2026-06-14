// Package qan provides Query Analytics data types and collection interfaces
// for the TelemetryFlow Agent. It implements a PMM-inspired QAN data path
// that is separate from the standard OTLP metric pipeline.
//
// QAN data flows: QANCollector → QANForwarder → QANExporter → TFO Platform QAN endpoint
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

package qan

import (
	"time"
)

// AgentType identifies the QAN collector implementation.
type AgentType string

const (
	AgentTypePostgreSQLPgStatements  AgentType = "qan-postgresql-pgstatements"
	AgentTypeMySQLPerfSchema         AgentType = "qan-mysql-perfschema"
	AgentTypeMySQLSlowLog            AgentType = "qan-mysql-slowlog"
	AgentTypeMongoDBProfiler         AgentType = "qan-mongodb-profiler"
	AgentTypeMongoDBMongolog         AgentType = "qan-mongodb-mongolog"
	AgentTypeMSSQLQueryStats         AgentType = "qan-mssql-querystats"
	AgentTypeMSSQLQueryStore         AgentType = "qan-mssql-querystore"
	AgentTypeCockroachDBStmtStats    AgentType = "qan-cockroachdb-stmtstats"
	AgentTypeTimescaleDBPgStatements AgentType = "qan-timescaledb-pgstatements"
	AgentTypeRDSPostgreSQLPgStmt     AgentType = "qan-rds-postgresql-pgstatements"
	AgentTypeAuroraPI                AgentType = "qan-aurora-pi"
)

// QANMetricsBucket represents a single query fingerprint's aggregated metrics
// for a collection period. The agent computes deltas from the previous
// snapshot before populating this struct.
//
// This is the wire format pushed to the TFO Platform QAN endpoint.
type QANMetricsBucket struct {
	// Query identity
	AgentType        AgentType `json:"agent_type"`
	QueryID          string    `json:"query_id"`
	Fingerprint      string    `json:"fingerprint"`
	Example          string    `json:"example,omitempty"`
	ExampleTruncated bool      `json:"example_truncated,omitempty"`
	Tables           []string  `json:"tables,omitempty"`

	// Period (the time window these metrics cover)
	PeriodStartSec  int64 `json:"period_start_unix_secs"`
	PeriodLengthSec int64 `json:"period_length_secs"`

	// Dimensions (used by ClickHouse ORDER BY for grouping/filtering)
	Database   string `json:"database,omitempty"`
	Schema     string `json:"schema,omitempty"`
	Username   string `json:"username,omitempty"`
	ClientHost string `json:"client_host,omitempty"`

	// Common metrics (all delta-from-previous-snapshot)
	NumQueries   float64 `json:"num_queries"`
	QueryTimeCnt float64 `json:"m_query_time_cnt"`
	QueryTimeSum float64 `json:"m_query_time_sum"`
	QueryTimeMin float64 `json:"m_query_time_min"`
	QueryTimeMax float64 `json:"m_query_time_max"`
	QueryTimeP99 float64 `json:"m_query_time_p99"`

	// Warning/error counts
	NumQueriesWithWarnings float64 `json:"num_queries_with_warnings,omitempty"`
	NumQueriesWithErrors   float64 `json:"num_queries_with_errors,omitempty"`

	// Resource attributes (filled by agent from SystemInfo / config)
	Labels map[string]string `json:"labels,omitempty"`

	// DB-specific metrics (only one populated per bucket)
	PostgreSQL  *PostgreSQLQANMetrics  `json:"postgresql,omitempty"`
	MySQL       *MySQLQANMetrics       `json:"mysql,omitempty"`
	MongoDB     *MongoDBQANMetrics     `json:"mongodb,omitempty"`
	MSSQL       *MSSQLQANMetrics       `json:"mssql,omitempty"`
	CockroachDB *CockroachDBQANMetrics `json:"cockroachdb,omitempty"`
}

// PostgreSQLQANMetrics holds PostgreSQL-specific query metrics from
// pg_stat_statements (delta from previous snapshot).
type PostgreSQLQANMetrics struct {
	// Row counts
	RowsCnt float64 `json:"m_rows_cnt"`
	RowsSum float64 `json:"m_rows_sum"`

	// Shared buffer access
	SharedBlksHitCnt     float64 `json:"m_shared_blks_hit_cnt"`
	SharedBlksHitSum     float64 `json:"m_shared_blks_hit_sum"`
	SharedBlksReadCnt    float64 `json:"m_shared_blks_read_cnt"`
	SharedBlksReadSum    float64 `json:"m_shared_blks_read_sum"`
	SharedBlksDirtiedCnt float64 `json:"m_shared_blks_dirtied_cnt"`
	SharedBlksDirtiedSum float64 `json:"m_shared_blks_dirtied_sum"`
	SharedBlksWrittenCnt float64 `json:"m_shared_blks_written_cnt"`
	SharedBlksWrittenSum float64 `json:"m_shared_blks_written_sum"`

	// Local buffer access
	LocalBlksHitCnt     float64 `json:"m_local_blks_hit_cnt"`
	LocalBlksHitSum     float64 `json:"m_local_blks_hit_sum"`
	LocalBlksReadCnt    float64 `json:"m_local_blks_read_cnt"`
	LocalBlksReadSum    float64 `json:"m_local_blks_read_sum"`
	LocalBlksDirtiedCnt float64 `json:"m_local_blks_dirtied_cnt"`
	LocalBlksDirtiedSum float64 `json:"m_local_blks_dirtied_sum"`
	LocalBlksWrittenCnt float64 `json:"m_local_blks_written_cnt"`
	LocalBlksWrittenSum float64 `json:"m_local_blks_written_sum"`

	// Temp buffer access
	TempBlksReadCnt    float64 `json:"m_temp_blks_read_cnt"`
	TempBlksReadSum    float64 `json:"m_temp_blks_read_sum"`
	TempBlksWrittenCnt float64 `json:"m_temp_blks_written_cnt"`
	TempBlksWrittenSum float64 `json:"m_temp_blks_written_sum"`

	// Block I/O time (milliseconds → seconds)
	BlkReadTimeCnt  float64 `json:"m_blk_read_time_cnt"`
	BlkReadTimeSum  float64 `json:"m_blk_read_time_sum"`
	BlkWriteTimeCnt float64 `json:"m_blk_write_time_cnt"`
	BlkWriteTimeSum float64 `json:"m_blk_write_time_sum"`

	// CPU time (pg_stat_statements extension — PG13+)
	CpuUserTimeSum float64 `json:"m_cpu_user_time_sum,omitempty"`
	CpuSysTimeSum  float64 `json:"m_cpu_sys_time_sum,omitempty"`

	// Command type (SELECT/INSERT/UPDATE/DELETE/etc.)
	CmdType string `json:"cmd_type,omitempty"`
}

// MySQLQANMetrics holds MySQL/MariaDB/Percona-specific query metrics from
// performance_schema.events_statements_summary_by_digest (delta from previous).
type MySQLQANMetrics struct {
	// Lock time
	LockTimeCnt float64 `json:"m_lock_time_cnt"`
	LockTimeSum float64 `json:"m_lock_time_sum"`
	LockTimeMin float64 `json:"m_lock_time_min"`
	LockTimeMax float64 `json:"m_lock_time_max"`

	// Rows
	RowsSentCnt     float64 `json:"m_rows_sent_cnt"`
	RowsSentSum     float64 `json:"m_rows_sent_sum"`
	RowsExaminedCnt float64 `json:"m_rows_examined_cnt"`
	RowsExaminedSum float64 `json:"m_rows_examined_sum"`
	RowsAffectedCnt float64 `json:"m_rows_affected_cnt"`
	RowsAffectedSum float64 `json:"m_rows_affected_sum"`

	// Bytes sent
	BytesSentCnt float64 `json:"m_bytes_sent_cnt"`
	BytesSentSum float64 `json:"m_bytes_sent_sum"`

	// Temporary tables
	TmpTablesCnt     float64 `json:"m_tmp_tables_cnt"`
	TmpTablesSum     float64 `json:"m_tmp_tables_sum"`
	TmpDiskTablesCnt float64 `json:"m_tmp_disk_tables_cnt"`
	TmpDiskTablesSum float64 `json:"m_tmp_disk_tables_sum"`

	// Merge passes
	MergePassesCnt float64 `json:"m_merge_passes_cnt"`
	MergePassesSum float64 `json:"m_merge_passes_sum"`

	// Boolean metrics (cnt/sum only — 0 or 1 per occurrence)
	QcHitCnt       float64 `json:"m_qc_hit_cnt"`
	QcHitSum       float64 `json:"m_qc_hit_sum"`
	FullScanCnt    float64 `json:"m_full_scan_cnt"`
	FullScanSum    float64 `json:"m_full_scan_sum"`
	FullJoinCnt    float64 `json:"m_full_join_cnt"`
	FullJoinSum    float64 `json:"m_full_join_sum"`
	TmpTableCnt    float64 `json:"m_tmp_table_cnt"`
	TmpTableSum    float64 `json:"m_tmp_table_sum"`
	FilesortCnt    float64 `json:"m_filesort_cnt"`
	FilesortSum    float64 `json:"m_filesort_sum"`
	NoIndexUsedCnt float64 `json:"m_no_index_used_cnt"`
	NoIndexUsedSum float64 `json:"m_no_index_used_sum"`
}

// MongoDBQANMetrics holds MongoDB-specific query metrics from the profiler
// or mongolog (delta from previous snapshot).
type MongoDBQANMetrics struct {
	// Document counts
	DocsReturnedCnt float64 `json:"m_docs_returned_cnt"`
	DocsReturnedSum float64 `json:"m_docs_returned_sum"`
	DocsScannedCnt  float64 `json:"m_docs_scanned_cnt"`
	DocsScannedSum  float64 `json:"m_docs_scanned_sum"`
	KeysExaminedCnt float64 `json:"m_keys_examined_cnt"`
	KeysExaminedSum float64 `json:"m_keys_examined_sum"`

	// Response size
	ResponseLengthCnt float64 `json:"m_response_length_cnt"`
	ResponseLengthSum float64 `json:"m_response_length_sum"`

	// Full collection scan
	FullScanCnt float64 `json:"m_full_scan_cnt"`
	FullScanSum float64 `json:"m_full_scan_sum"`

	// Lock metrics
	LocksGlobalAcquireCountReadSharedCnt float64 `json:"m_locks_global_acquire_count_read_shared_cnt"`
	LocksGlobalAcquireCountReadSharedSum float64 `json:"m_locks_global_acquire_count_read_shared_sum"`

	// Storage
	StorageBytesReadCnt float64 `json:"m_storage_bytes_read_cnt"`
	StorageBytesReadSum float64 `json:"m_storage_bytes_read_sum"`

	// Plan summary (COLLSCAN/IXSCAN/etc.)
	PlanSummary string `json:"plan_summary,omitempty"`

	// Application name
	ApplicationName string `json:"application_name,omitempty"`
}

// MSSQLQANMetrics holds SQL Server-specific query metrics from
// sys.dm_exec_query_stats (delta from previous snapshot).
type MSSQLQANMetrics struct {
	// Execution statistics
	ExecutionCount float64 `json:"m_execution_count"`

	// CPU time (microseconds → seconds)
	TotalWorkerTime float64 `json:"m_total_worker_time"`
	TotalCPUTime    float64 `json:"m_total_cpu_time"`

	// Elapsed time (microseconds → seconds)
	TotalElapsedTime float64 `json:"m_total_elapsed_time"`

	// Logical reads
	TotalLogicalReads  float64 `json:"m_total_logical_reads"`
	TotalLogicalWrites float64 `json:"m_total_logical_writes"`

	// Physical reads
	TotalPhysicalReads float64 `json:"m_total_physical_reads"`

	// Row counts
	RowCounts float64 `json:"m_row_counts"`

	// Memory grants
	MaxGrantKB     float64 `json:"m_max_grant_kb,omitempty"`
	MinGrantKB     float64 `json:"m_min_grant_kb,omitempty"`
	MaxUsedGrantKB float64 `json:"m_max_used_grant_kb,omitempty"`
	MinUsedGrantKB float64 `json:"m_min_used_grant_kb,omitempty"`

	// Degree of parallelism
	MaxDOP float64 `json:"m_max_dop,omitempty"`

	// Query Store specific (when source = Query Store)
	QueryStoreQueryID float64 `json:"qs_query_id,omitempty"`
}

// CockroachDBQANMetrics holds CockroachDB-specific query metrics from
// crdb_internal.node_statement_statistics (delta from previous snapshot).
type CockroachDBQANMetrics struct {
	// Row counts
	RowsReadCnt    float64 `json:"m_rows_read_cnt"`
	RowsReadSum    float64 `json:"m_rows_read_sum"`
	RowsWrittenCnt float64 `json:"m_rows_written_cnt"`
	RowsWrittenSum float64 `json:"m_rows_written_sum"`

	// Bytes
	BytesReadCnt    float64 `json:"m_bytes_read_cnt"`
	BytesReadSum    float64 `json:"m_bytes_read_sum"`
	NetworkBytesCnt float64 `json:"m_network_bytes_cnt"`
	NetworkBytesSum float64 `json:"m_network_bytes_sum"`

	// Retry statistics
	MaxRetriesCnt float64 `json:"m_max_retries_cnt"`
	MaxRetriesSum float64 `json:"m_max_retries_sum"`

	// First attempt count (successful first attempts)
	FirstAttemptCnt float64 `json:"m_first_attempt_cnt"`
	FirstAttemptSum float64 `json:"m_first_attempt_sum"`

	// Application name (CRDB stat grouping dimension)
	ApplicationName string `json:"application_name,omitempty"`
}

// CollectRequest is the top-level push payload sent to the QAN endpoint.
type CollectRequest struct {
	AgentID string             `json:"agent_id"`
	Buckets []QANMetricsBucket `json:"metrics_bucket"`
}

// CollectResponse is the response from the QAN endpoint.
type CollectResponse struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors,omitempty"`
}

// QANConfig holds configuration for the QAN data path.
type QANConfig struct {
	// Enabled controls whether the QAN path is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Interval is how often to collect QAN data (default: 60s).
	Interval time.Duration `json:"interval" yaml:"interval"`

	// Endpoint is the TFO Platform QAN API URL.
	// Example: "https://api.telemetryflow.id"
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// APIKeyID and APIKeySecret for authentication.
	APIKeyID     string `json:"api_key_id" yaml:"api_key_id"`
	APIKeySecret string `json:"-" yaml:"api_key_secret"`

	// BatchSize is the maximum number of buckets per push (default: 100).
	BatchSize int `json:"batch_size" yaml:"batch_size"`

	// FlushInterval is how long to buffer before flushing (default: 10s).
	FlushInterval time.Duration `json:"flush_interval" yaml:"flush_interval"`

	// Timeout for HTTP push requests (default: 30s).
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// MaxRetryAttempts for push requests (default: 3).
	MaxRetryAttempts int `json:"max_retry_attempts" yaml:"max_retry_attempts"`

	// TopQueriesLimit is the max number of query fingerprints to track per
	// database instance per cycle (default: 200).
	TopQueriesLimit int `json:"top_queries_limit" yaml:"top_queries_limit"`

	// Collectors enables/disables individual QAN collector types.
	// All default to true when QAN.Enabled is true — set to false to disable
	// specific DB types. Collectors only activate when the corresponding
	// regular DB collector is enabled and has instances configured.
	Collectors QANCollectorsConfig `json:"collectors" yaml:"collectors"`
}

// QANCollectorsConfig provides per-DB-type feature flags for QAN collection.
// When a flag is false, that DB type's QAN collector is never created,
// even if the regular collector has instances configured.
type QANCollectorsConfig struct {
	PostgreSQL    bool `json:"postgresql" yaml:"postgresql"`
	MySQL         bool `json:"mysql" yaml:"mysql"`
	MongoDB       bool `json:"mongodb" yaml:"mongodb"`
	MSSQL         bool `json:"mssql" yaml:"mssql"`
	CockroachDB   bool `json:"cockroachdb" yaml:"cockroachdb"`
	TimescaleDB   bool `json:"timescaledb" yaml:"timescaledb"`
	RDSPostgreSQL bool `json:"rds_postgresql" yaml:"rds_postgresql"`
	Aurora        bool `json:"aurora" yaml:"aurora"`
}

// DefaultQANConfig returns QAN config with production defaults.
func DefaultQANConfig() QANConfig {
	return QANConfig{
		Enabled:          false,
		Interval:         60 * time.Second,
		BatchSize:        100,
		FlushInterval:    10 * time.Second,
		Timeout:          30 * time.Second,
		MaxRetryAttempts: 3,
		TopQueriesLimit:  200,
		Collectors: QANCollectorsConfig{
			PostgreSQL:    true,
			MySQL:         true,
			MongoDB:       true,
			MSSQL:         true,
			CockroachDB:   true,
			TimescaleDB:   true,
			RDSPostgreSQL: true,
			Aurora:        true,
		},
	}
}
