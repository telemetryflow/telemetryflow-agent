// Package timescaledb_test — orchestration-path tests driving collectInstance +
// ensureConnection through an injected pgxmock pool via SetPoolFactoryExported.
// An expectation-less mock fails every query, which the collectors
// log-and-continue, so the per-instance flow is walked without a live database.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package timescaledb_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	tsdb "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestCollect_OrchestrationViaMockPool_TSDB(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("new mock pool: %v", err)
	}
	mock.MatchExpectationsInOrder(false)
	for range 8 {
		mock.ExpectPing()
	}
	tsdb.SetPoolFactoryExported(func(_ context.Context, _ *pgxpool.Config) (tsdb.PgxPool, error) {
		return mock, nil
	})
	defer func() {
		tsdb.SetPoolFactoryExported(nil)
		mock.Close()
	}()

	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{
		Instances: []config.TimescaleDBInstanceConfig{
			{Name: "i1", Host: "127.0.0.1", Port: 5432, User: "tsdb", DBName: "tsdb", SSLMode: "disable"},
		},
	}, zap.NewNop())

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
}
