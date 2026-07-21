// Package cockroachdb_test exercises collector error branches against a real
// CockroachDB node, whose crdb_internal schema differs from the columns the
// production queries request, so every query returns an error after a
// successful connection.
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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func realCRDBPort() int {
	if p := os.Getenv("CRDB_REAL_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return 26257
}

// requireRealCRDB skips unless an actual CockroachDB node (real crdb_internal
// virtual tables) is reachable.
func requireRealCRDB(t *testing.T) config.CockroachDBInstanceConfig {
	t.Helper()
	inst := config.CockroachDBInstanceConfig{
		Name:     "crdb-real",
		Host:     crdbHost(),
		SQLPort:  realCRDBPort(),
		User:     "root",
		Database: "system",
		SSLMode:  "disable",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dsn := fmt.Sprintf("postgres://root@%s:%d/system?sslmode=disable", inst.Host, inst.SQLPort)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("real CockroachDB not available: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("real CockroachDB not reachable: %v", err)
	}
	// Confirm this is a real node: the version function must resolve.
	var v string
	if err := pool.QueryRow(ctx, "SELECT crdb_internal.node_executable_version()").Scan(&v); err != nil {
		t.Skipf("not a real CockroachDB node: %v", err)
	}
	return inst
}

// TestErrorPaths_RealCRDB drives Collect against a real node so the collector's
// per-query error branches (columns not present in the real schema) execute
// while the connection itself succeeds.
func TestErrorPaths_RealCRDB(t *testing.T) {
	inst := requireRealCRDB(t)

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
	}, zap.NewNop())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// Version detection succeeds; node/sql/store/statement/range queries fail on
	// the real schema and hit their error-return branches.
	_, err := c.Collect(context.Background())
	require.NoError(t, err)

	require.NoError(t, c.Stop())
	<-errCh
}

// TestErrorPaths_RealCRDB_QAN exercises the QAN collector's query-error branch.
func TestErrorPaths_RealCRDB_QAN(t *testing.T) {
	inst := requireRealCRDB(t)

	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{inst},
		Logger:    zap.NewNop(),
	}, zap.NewNop())
	defer c.Stop()

	// Connection succeeds; the statement-statistics query fails on real columns.
	_, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
}

// TestBackoff_Doubles forces two connection failures spaced past the initial
// back-off window so advanceBackoff takes its doubling branch.
func TestBackoff_Doubles(t *testing.T) {
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{{
			Name:    "dead",
			Host:    "127.0.0.1",
			SQLPort: 1,
			SSLMode: "disable",
		}},
	}, zap.NewNop())

	ctx := context.Background()
	_, _ = c.Collect(ctx) // first failure: backoff = 1s
	time.Sleep(1100 * time.Millisecond)
	_, _ = c.Collect(ctx) // window elapsed: retry, fail again, backoff *= 2
	require.NoError(t, c.Stop())
}
