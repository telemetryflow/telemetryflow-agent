// Package postgresql implements the PostgreSQL database monitoring collector.
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

package postgresql

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func detectVersion(ctx context.Context, q PgxQuerier, inst *pgInstance) error {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var versionNum int
	err := q.QueryRow(ctx2, "SELECT current_setting('server_version_num')::int").Scan(&versionNum)
	if err != nil {
		return fmt.Errorf("postgresql %s: detect version: %w", inst.config.Name, err)
	}
	inst.version = versionNum

	var versionStr string
	if err := q.QueryRow(ctx2, "SHOW server_version").Scan(&versionStr); err == nil {
		inst.versionStr = strings.TrimSpace(versionStr)
	} else {
		inst.versionStr = strconv.Itoa(versionNum)
	}

	vLower := strings.ToLower(inst.versionStr)
	switch {
	case strings.Contains(vLower, "aws"):
		inst.flavor = "aws-rds"
	case strings.Contains(vLower, "azure"):
		inst.flavor = "azure"
	case strings.Contains(vLower, "google") || strings.Contains(vLower, "cloudsql"):
		inst.flavor = "gcp-cloudsql"
	default:
		inst.flavor = "postgresql"
	}
	return nil
}

func hasPgStatWal(inst *pgInstance) bool {
	return inst.version >= 140000
}

func hasExecTimeColumns(inst *pgInstance) bool {
	return inst.version >= 130000
}

// PG15+ (pg_stat_statements 1.10) removed blk_read_time / blk_write_time and
// split them into shared_/local_/temp_blk_*_time. Querying the old names raises
// SQLSTATE 42703 ("column does not exist"), which broke QAN collection entirely
// on PG15+ (e.g. PG18). Detect the version so callers can select the right cols.
func hasSplitBlkTimeColumns(versionNum int) bool {
	return versionNum >= 150000
}

// blkTimeColumns returns the pg_stat_statements block-I/O timing columns aliased
// as blk_read_time / blk_write_time so downstream scanning is version-agnostic.
// Old blk_read_time == shared + local block read time (temp is tracked separately).
func blkTimeColumns(versionNum int) string {
	if hasSplitBlkTimeColumns(versionNum) {
		return "(shared_blk_read_time + local_blk_read_time) AS blk_read_time, " +
			"(shared_blk_write_time + local_blk_write_time) AS blk_write_time"
	}
	return "blk_read_time, blk_write_time"
}

// ---------------------------------------------------------------------------
// Version-aware statistics-view queries (PostgreSQL 16 / 17 / 18)
//
// PG17 moved the checkpoint columns out of pg_stat_bgwriter into the new
// pg_stat_checkpointer view and dropped buffers_backend / buffers_backend_fsync
// (now surfaced via pg_stat_io). PG18 removed wal_write / wal_sync /
// wal_write_time / wal_sync_time from pg_stat_wal (also moved to pg_stat_io) and
// renamed pg_stat_progress_vacuum.{max_dead_tuples,num_dead_tuples} (PG17) to
// max_dead_tuple_bytes / num_dead_item_ids. Each builder returns SQL with a
// FIXED output-column shape so the Go scan code stays version-agnostic.
//
// version == 0 (unknown) falls back to the legacy shape so mocked unit tests and
// pre-detection calls keep working.
// ---------------------------------------------------------------------------

// hasCheckpointerView reports whether checkpoint stats live in
// pg_stat_checkpointer rather than pg_stat_bgwriter (PostgreSQL 17+).
func hasCheckpointerView(versionNum int) bool { return versionNum >= 170000 }

// walIOInStatIO reports whether pg_stat_wal dropped the write/sync timing
// columns in favour of pg_stat_io (PostgreSQL 18+).
func walIOInStatIO(versionNum int) bool { return versionNum >= 180000 }

// vacuumDeadTupleBytes reports whether pg_stat_progress_vacuum exposes the
// byte-based dead-tuple columns (PostgreSQL 17+) instead of the tuple counts.
func vacuumDeadTupleBytes(versionNum int) bool { return versionNum >= 170000 }

// bgWriterQuery returns a background-writer / checkpointer query whose output is
// always: checkpoints_timed, checkpoints_req, checkpoint_write_time,
// checkpoint_sync_time, buffers_checkpoint, buffers_clean, buffers_backend,
// maxwritten_clean, buffers_backend_fsync, buffers_alloc.
func bgWriterQuery(versionNum int) string {
	if hasCheckpointerView(versionNum) {
		// PG17+: checkpoint stats from pg_stat_checkpointer; buffers_backend and
		// buffers_backend_fsync were removed (reported as 0 for compatibility).
		return `
			SELECT
				c.num_timed       AS checkpoints_timed,
				c.num_requested   AS checkpoints_req,
				c.write_time      AS checkpoint_write_time,
				c.sync_time       AS checkpoint_sync_time,
				c.buffers_written AS buffers_checkpoint,
				b.buffers_clean,
				0::bigint         AS buffers_backend,
				b.maxwritten_clean,
				0::bigint         AS buffers_backend_fsync,
				b.buffers_alloc
			FROM pg_stat_checkpointer c CROSS JOIN pg_stat_bgwriter b`
	}
	return `
		SELECT
			checkpoints_timed,
			checkpoints_req,
			checkpoint_write_time,
			checkpoint_sync_time,
			buffers_checkpoint,
			buffers_clean,
			buffers_backend,
			maxwritten_clean,
			buffers_backend_fsync,
			buffers_alloc
		FROM pg_stat_bgwriter`
}

// walStatsQuery returns a WAL-stats query whose output is always: wal_records,
// wal_fpi, wal_bytes, wal_buffers_full, wal_write, wal_sync, wal_write_time,
// wal_sync_time.
func walStatsQuery(versionNum int) string {
	if walIOInStatIO(versionNum) {
		// PG18+: write/sync counters + timings moved to pg_stat_io (object='wal').
		return `
			SELECT
				w.wal_records,
				w.wal_fpi,
				w.wal_bytes,
				w.wal_buffers_full,
				COALESCE(io.writes, 0)::bigint               AS wal_write,
				COALESCE(io.fsyncs, 0)::bigint               AS wal_sync,
				COALESCE(io.write_time, 0)::double precision AS wal_write_time,
				COALESCE(io.fsync_time, 0)::double precision AS wal_sync_time
			FROM pg_stat_wal w
			LEFT JOIN (
				SELECT sum(writes) AS writes, sum(fsyncs) AS fsyncs,
				       sum(write_time) AS write_time, sum(fsync_time) AS fsync_time
				FROM pg_stat_io WHERE object = 'wal'
			) io ON true`
	}
	return `
		SELECT
			wal_records,
			wal_fpi,
			wal_bytes,
			wal_buffers_full,
			wal_write,
			wal_sync,
			wal_write_time,
			wal_sync_time
		FROM pg_stat_wal`
}

// vacuumProgressQuery returns a vacuum-progress query whose output is always:
// table_name, phase, heap_blks_total, heap_blks_scanned, heap_blks_vacuumed,
// index_vacuum_count, max_dead (bytes on PG17+, tuple count before),
// num_dead (dead item ids on PG17+, tuple count before).
func vacuumProgressQuery(versionNum int) string {
	if vacuumDeadTupleBytes(versionNum) {
		return `SELECT relid::regclass::text AS table_name,
		               phase,
		               heap_blks_total,
		               heap_blks_scanned,
		               heap_blks_vacuumed,
		               index_vacuum_count,
		               max_dead_tuple_bytes,
		               num_dead_item_ids
		        FROM pg_stat_progress_vacuum`
	}
	return `SELECT relid::regclass::text AS table_name,
	               phase,
	               heap_blks_total,
	               heap_blks_scanned,
	               heap_blks_vacuumed,
	               index_vacuum_count,
	               max_dead_tuples,
	               num_dead_tuples
	        FROM pg_stat_progress_vacuum`
}
