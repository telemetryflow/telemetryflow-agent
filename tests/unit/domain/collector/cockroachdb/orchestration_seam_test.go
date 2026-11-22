// Package cockroachdb_test — orchestration-path tests driving collectInstance +
// ensureConnection through an injected pgxmock pool via SetPoolFactoryExported.
// An expectation-less mock fails every query, which the collectors
// log-and-continue, so the per-instance flow is walked without a live database.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package cockroachdb_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestCollect_OrchestrationViaMockPool_CRDB(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("new mock pool: %v", err)
	}
	mock.MatchExpectationsInOrder(false)
	for range 8 {
		mock.ExpectPing()
	}
	cockroachdb.SetPoolFactoryExported(func(_ context.Context, _ *pgxpool.Config) (cockroachdb.PgxPool, error) {
		return mock, nil
	})
	defer func() {
		cockroachdb.SetPoolFactoryExported(nil)
		mock.Close()
	}()

	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{
			{Name: "i1", Host: "127.0.0.1", SQLPort: 26257, SSLMode: "disable"},
		},
	}, zap.NewNop())

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
}
