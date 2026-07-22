// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package timescaledb_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	tsdb "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- parseFloat remaining type branches ---

func TestParseFloat_Float32AndInt64(t *testing.T) {
	if got := tsdb.ParseFloatExport(float32(1.5)); got != 1.5 {
		t.Errorf("parseFloat(float32 1.5) = %v, want 1.5", got)
	}
	if got := tsdb.ParseFloatExport(int64(7)); got != 7 {
		t.Errorf("parseFloat(int64 7) = %v, want 7", got)
	}
}

// --- resolveEnvVars: env-set return path and no-default form ---

func TestResolveEnvVars_EnvSetAndNoDefault(t *testing.T) {
	const key = "TSDB_EDGE_TEST_VAR"
	t.Setenv(key, "resolved")

	// ${VAR} with no default separator -> exercises findDefaultSep's -1 return
	// and the os.Getenv non-empty return path.
	if got := tsdb.ResolveEnvVarsExport("${" + key + "}"); got != "resolved" {
		t.Errorf("expected resolved, got %q", got)
	}
	// ${VAR:-default} with the var set -> returns the env value, not the default.
	if got := tsdb.ResolveEnvVarsExport("${" + key + ":-fallback}"); got != "resolved" {
		t.Errorf("expected resolved (env wins over default), got %q", got)
	}
	// Sanity: unset var with no default resolves to empty string.
	os.Unsetenv(key)
	if got := tsdb.ResolveEnvVarsExport("${" + key + "}"); got != "" {
		t.Errorf("expected empty for unset no-default var, got %q", got)
	}
}

// --- advanceBackoff exponential cap at 60s ---

func TestAdvanceBackoff_CapsAtMax(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")
	// 1 -> 2 -> 4 -> ... doubling until it clamps at 60s; 10 iterations is plenty.
	for i := 0; i < 10; i++ {
		c.AdvanceBackoffExport(inst)
	}
}

// --- ensureConnection parse-config error path (no network) ---

func TestEnsureConnection_ParseConfigError(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	// A host containing an invalid URL escape makes pgxpool.ParseConfig fail
	// before any network I/O, exercising the parse-error branch deterministically.
	inst := tsdb.NewTsdbInstanceExport(
		config.TimescaleDBInstanceConfig{Name: "bad", Host: "%zz", Port: 5432, User: "u", DBName: "d"}, "", "")
	if err := c.EnsureConnectionNoBackoffExport(context.Background(), inst); err == nil {
		t.Fatal("expected parse-config error")
	}
}

// --- Stop close-loop with configured instances (nil pools) ---

func TestCollectorStop_ClosesInstances(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{
		Instances: []config.TimescaleDBInstanceConfig{{Name: "a"}, {Name: "b"}},
	}, zap.NewNop())

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()
	waitFor(t, c.IsRunning)

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
	<-done
}

// --- QAN: nil logger default + Stop close-loop with instances ---

func TestNewQANCollector_NilLoggerAndStopLoop(t *testing.T) {
	c := tsdb.NewQANTimescaleDBCollector(tsdb.QANTimescaleDBConfig{
		Instances: []config.TimescaleDBInstanceConfig{{Name: "q"}},
	}, nil) // nil logger -> internal default production logger

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

// --- collectQANBuckets: candidate-pool clamping branches ---

func TestCollectQANBuckets_CandidatePoolClamp(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", DBName: "db", User: "u"})
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	// limit 2000 -> limit*3 = 6000 clamps to 1000, then 1000 < limit clamps back to 2000.
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(2000).WillReturnRows(qanStatementRows())

	if _, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 2000, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- collectQANBuckets: scan error is skipped ---

func TestCollectQANBuckets_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", DBName: "db", User: "u"})
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	// queryid as a non-numeric string forces a scan error -> row skipped.
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(30).WillReturnRows(
		qanStatementRows().AddRow("not-a-uint", "SELECT 1", uint64(1), float64(1), float64(1), float64(1), uint64(1), uint64(1), uint64(1)))

	buckets, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(buckets) != 0 {
		t.Fatalf("expected 0 buckets, got %d", len(buckets))
	}
}

// --- collectQANBuckets: no-delta (deltaCalls<=0) skip on second run ---

func TestCollectQANBuckets_NoDeltaSkip(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", DBName: "db", User: "u"})

	row := func() *pgxmock.Rows {
		return qanStatementRows().AddRow(uint64(1), "SELECT 1", uint64(100), float64(500), float64(1), float64(9), uint64(100), uint64(50), uint64(5))
	}
	// First run seeds the snapshot.
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(30).WillReturnRows(row())
	if _, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Second run with identical counters -> deltaCalls == 0 -> skipped.
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(30).WillReturnRows(row())
	buckets, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(buckets) != 0 {
		t.Fatalf("expected 0 buckets (no delta), got %d", len(buckets))
	}
}

// --- collectQANBuckets: example truncation + sort/limit trimming ---

func TestCollectQANBuckets_TruncationAndLimitTrim(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", DBName: "db", User: "u"})
	longQuery := "SELECT " + strings.Repeat("x", 2500)

	first := func() *pgxmock.Rows {
		return qanStatementRows().
			AddRow(uint64(1), longQuery, uint64(100), float64(500), float64(1), float64(9), uint64(100), uint64(50), uint64(5)).
			AddRow(uint64(2), "SELECT 2", uint64(100), float64(200), float64(1), float64(4), uint64(100), uint64(20), uint64(2))
	}
	// First run seeds both queries.
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(3).WillReturnRows(first())
	if _, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 1, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Second run: both have positive delta -> 2 buckets, but limit=1 forces sort+trim.
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(3).WillReturnRows(
		qanStatementRows().
			AddRow(uint64(1), longQuery, uint64(300), float64(1500), float64(1), float64(9), uint64(300), uint64(150), uint64(15)).
			AddRow(uint64(2), "SELECT 2", uint64(150), float64(400), float64(1), float64(4), uint64(150), uint64(40), uint64(4)))

	buckets, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 1, nil)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket after limit trim, got %d", len(buckets))
	}
	if !buckets[0].ExampleTruncated {
		t.Error("expected the long-query bucket to be truncated (highest QueryTimeSum wins the sort)")
	}
	if len(buckets[0].Example) != 2000 {
		t.Errorf("expected truncated example length 2000, got %d", len(buckets[0].Example))
	}
}

var _ = time.Second
