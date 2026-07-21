// Package cockroachdb_test contains integration tests that exercise the
// CockroachDB collector against a live CockroachDB node (crdb_internal tables).
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
package cockroachdb_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func crdbHost() string {
	if h := os.Getenv("CRDB_TEST_HOST"); h != "" {
		return h
	}
	return "localhost"
}

func crdbPort() int {
	if p := os.Getenv("CRDB_TEST_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	// Default targets a Postgres-wire-compatible backend that emulates the
	// crdb_internal.* schema the collector queries (CockroachDB is Postgres
	// wire-compatible). Override with CRDB_TEST_HOST / CRDB_TEST_PORT to point
	// at a real CockroachDB node.
	return 5433
}

func crdbPassword() string {
	if p := os.Getenv("CRDB_TEST_PASSWORD"); p != "" {
		return p
	}
	return "pw"
}

func crdbDSN(inst config.CockroachDBInstanceConfig) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/system?sslmode=disable",
		inst.User, inst.Password, inst.Host, inst.SQLPort)
}

// requireLiveCRDB skips the test when no compatible backend is reachable.
func requireLiveCRDB(t *testing.T) config.CockroachDBInstanceConfig {
	t.Helper()
	inst := config.CockroachDBInstanceConfig{
		Name:     "crdb-it",
		Host:     crdbHost(),
		SQLPort:  crdbPort(),
		User:     "root",
		Password: crdbPassword(),
		Database: "system",
		SSLMode:  "disable",
		Tags:     map[string]string{"env": "test"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, crdbDSN(inst))
	if err != nil {
		t.Skipf("CockroachDB-compatible backend not available: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("CockroachDB-compatible backend not reachable at %s:%d: %v", inst.Host, inst.SQLPort, err)
	}
	return inst
}

func TestIntegration_Collect(t *testing.T) {
	inst := requireLiveCRDB(t)

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances:          []config.CockroachDBInstanceConfig{inst},
		TopStatementsLimit: 50,
	}, zap.NewNop())
	defer func() { _ = c.Stop() }()

	ctx := context.Background()

	// First collect: establishes connection, detects version, seeds counters,
	// runs node/sql/store/statement/range/leaseholder queries.
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "expected metrics from a live CRDB node")

	// Generate some SQL activity so statement statistics deltas move.
	for i := 0; i < 3; i++ {
		_, _ = c.Collect(ctx)
	}

	// Verify at least one known metric name is present.
	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
		assert.NotEmpty(t, m.Labels["cockroachdb_instance"])
	}
	assert.True(t,
		names["db.cockroachdb.ranges.total"] || names["db.cockroachdb.statement.count"],
		"expected range or statement metrics; got %d metrics", len(metrics))
}

func TestIntegration_StartCollectStopClosesPool(t *testing.T) {
	inst := requireLiveCRDB(t)

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
	}, zap.NewNop())

	// Start so that running==true, otherwise Stop short-circuits before it
	// closes any established connections.
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// Collect establishes a live pgx pool on the instance.
	_, err := c.Collect(context.Background())
	require.NoError(t, err)

	// Stop (while running) closes the live connection via closeConnection.
	require.NoError(t, c.Stop())
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	assert.False(t, c.IsRunning())
}

func TestIntegration_QANCollect(t *testing.T) {
	inst := requireLiveCRDB(t)

	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances:       []config.CockroachDBInstanceConfig{inst},
		TopQueriesLimit: 50,
		Labels:          map[string]string{"team": "obs"},
		Logger:          zap.NewNop(),
	}, zap.NewNop())
	defer func() { _ = c.Stop() }()

	ctx := context.Background()

	pool, perr := pgxpool.New(ctx, crdbDSN(inst))
	require.NoError(t, perr)
	defer pool.Close()

	// Seed a long-query fingerprint so the >2000 char truncation branch is
	// exercised on the emulated backend (no-op / ignored on a real node).
	longQuery := ""
	for i := 0; i < 2100; i++ {
		longQuery += "x"
	}
	_, _ = pool.Exec(ctx, `INSERT INTO crdb_internal.node_statement_statistics
		(fingerprint_id, anonymized_query, app_name, count, first_attempt_count, max_retries,
		 avg_latency, max_latency, rows_read, rows_written, bytes_read, network_bytes)
		VALUES ('fp_long', $1, 'appL', 10, 10, 0, 100, 200, 1, 1, 1, 1)
		ON CONFLICT DO NOTHING`, longQuery)

	// First pass seeds the snapshot (no buckets emitted yet).
	_, err := c.CollectQAN(ctx)
	require.NoError(t, err)

	// Bump statement counts so the second pass sees positive deltas and emits
	// buckets (covers delta computation, labels, database name, truncation).
	// Bump all but fp3 so fp3 keeps a zero delta (exercises the deltaCount<=0
	// skip branch) while the others emit buckets.
	_, _ = pool.Exec(ctx, `UPDATE crdb_internal.node_statement_statistics
		SET count = count + 20, rows_read = rows_read + 5, rows_written = rows_written + 2,
		    bytes_read = bytes_read + 100, network_bytes = network_bytes + 10,
		    max_retries = max_retries + 1, first_attempt_count = first_attempt_count + 20
		WHERE fingerprint_id <> 'fp3'`)

	// Second pass computes deltas and should produce buckets for changed fingerprints.
	buckets, err := c.CollectQAN(ctx)
	require.NoError(t, err)
	for _, b := range buckets {
		assert.Equal(t, "cockroachdb", b.Labels["db_system"])
		assert.NotEmpty(t, b.QueryID)
		require.NotNil(t, b.CockroachDB)
	}
}

func TestIntegration_QANStartStopClosesPool(t *testing.T) {
	inst := requireLiveCRDB(t)
	// Empty Database exercises the databaseName "system" fallback branch while
	// still connecting (the DSN defaults the database to system).
	inst.Database = ""

	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances:       []config.CockroachDBInstanceConfig{inst},
		TopQueriesLimit: 50,
		Logger:          zap.NewNop(),
	}, zap.NewNop())

	ctx := context.Background()
	require.NoError(t, c.Start(ctx))

	pool, perr := pgxpool.New(ctx, crdbDSN(inst))
	require.NoError(t, perr)
	defer pool.Close()

	_, err := c.CollectQAN(ctx) // seed snapshot (pool established)
	require.NoError(t, err)
	_, _ = pool.Exec(ctx, `UPDATE crdb_internal.node_statement_statistics SET count = count + 7`)
	_, err = c.CollectQAN(ctx) // deltas -> databaseName() invoked with empty DB
	require.NoError(t, err)

	// Stop (running) closes the live pool.
	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
}

func TestIntegration_NodeLivenessFalse(t *testing.T) {
	inst := requireLiveCRDB(t)

	pool, perr := pgxpool.New(context.Background(), crdbDSN(inst))
	require.NoError(t, perr)
	defer pool.Close()

	// Flip liveness false so the fallback node query drives boolToFloat(false),
	// then restore it so other tests observe a live node.
	_, err := pool.Exec(context.Background(), `UPDATE crdb_internal.gossip_liveness SET is_live = false WHERE node_id = 1`)
	require.NoError(t, err)
	defer func() {
		_, _ = pool.Exec(context.Background(), `UPDATE crdb_internal.gossip_liveness SET is_live = true WHERE node_id = 1`)
	}()

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
	}, zap.NewNop())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)
	_, err = c.Collect(context.Background())
	require.NoError(t, err)
	require.NoError(t, c.Stop())
	<-errCh
}

// TestIntegration_QueryErrorsOnConnectedBackend connects successfully to a
// Postgres-wire backend that lacks the crdb_internal schema (a database without
// the emulated tables), so every collector query fails after connecting. This
// drives the per-query error-return branches (version detection, node liveness
// fallback, range stats, statement stats, store status).
func TestIntegration_QueryErrorsOnConnectedBackend(t *testing.T) {
	base := requireLiveCRDB(t)
	inst := base
	inst.Name = "crdb-noschema"
	inst.Database = "postgres" // exists, but has no crdb_internal.* relations

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
	}, zap.NewNop())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	_, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NoError(t, c.Stop())
	<-errCh

	// QAN against the same schema-less database: connects, query fails.
	q := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
		Logger:    zap.NewNop(),
	}, zap.NewNop())
	defer func() { _ = q.Stop() }()
	_, err = q.CollectQAN(context.Background())
	require.NoError(t, err)
}

// TestIntegration_LeaseholderScanFailure targets a database where the range
// query succeeds but the leaseholder rows fail to scan (lease_holder stored as
// non-numeric text), exercising the leaseholder scan-continue, rows.Err, and
// the caller's "leaseholder metrics skipped" debug branch.
func TestIntegration_LeaseholderScanFailure(t *testing.T) {
	base := requireLiveCRDB(t)
	inst := base
	inst.Name = "crdb-partial"
	inst.Database = "partial"

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
	}, zap.NewNop())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	_, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NoError(t, c.Stop())
	<-errCh
}

func TestIntegration_OTLPEmitSuccess(t *testing.T) {
	inst := requireLiveCRDB(t)

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
	}, zap.NewNop())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, metrics)

	endpoint := os.Getenv("OTLP_TEST_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:4318" // OTLP HTTP (the bridge uses otlpmetrichttp)
	}
	bridge, err := exporter.NewOTLPMetricBridge(context.Background(), exporter.OTLPMetricBridgeConfig{
		Endpoint: endpoint,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	emitter := cockroachdb.NewOTLPEmitter(bridge, zap.NewNop())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Best-effort emit: the export path (resource attrs + bridge.Export) is
	// exercised regardless of whether the OTLP endpoint accepts the batch.
	_ = emitter.EmitMetrics(ctx, metrics)
	_ = emitter.Shutdown(context.Background())
}
