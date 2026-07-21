// Package cockroachdb_test contains unit tests for the CockroachDB collector.
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

func TestQAN_Metadata(t *testing.T) {
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{}, zap.NewNop())
	assert.Equal(t, "qan-cockroachdb-stmtstats", c.Name())
	assert.Equal(t, qan.AgentTypeCockroachDBStmtStats, c.AgentType())
	assert.False(t, c.IsRunning())
}

func TestQAN_DefaultTopQueriesLimit(t *testing.T) {
	// TopQueriesLimit == 0 => defaulted; nil logger => production logger fallback.
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{{Name: "n1"}},
	}, nil)
	require.NotNil(t, c)
}

func TestQAN_StartStop(t *testing.T) {
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{{Name: "n1"}},
		Logger:    zap.NewNop(),
	}, zap.NewNop())

	require.NoError(t, c.Start(context.Background()))
	assert.True(t, c.IsRunning())

	// Double start => error.
	assert.Error(t, c.Start(context.Background()))

	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())

	// Idempotent second stop.
	require.NoError(t, c.Stop())
}

func TestQAN_CollectNoInstances(t *testing.T) {
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{}, zap.NewNop())
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Nil(t, buckets)
}

func TestQAN_CollectParseConfigError(t *testing.T) {
	// A host containing spaces makes pgxpool.ParseConfig fail, covering the
	// parse-config error branch of the QAN connection path.
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{{
			Name:    "badcfg",
			Host:    "bad host with spaces",
			SQLPort: 26257,
			SSLMode: "disable",
		}},
	}, zap.NewNop())

	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err) // per-instance error is swallowed
	assert.Empty(t, buckets)
}

func TestQAN_CollectDefaultPort(t *testing.T) {
	// SQLPort 0 exercises the port->26257 defaulting branch. The connection then
	// fails (or the query does), and the per-instance error is swallowed.
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{{
			Name: "defport",
			Host: "127.0.0.1", // SQLPort 0 -> defaults to 26257
		}},
	}, zap.NewNop())

	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestQAN_CollectUnreachable(t *testing.T) {
	// SQLPort 0, empty Database and empty SSLMode force the connection
	// defaulting branches (port->26257, db->system, ssl->disable).
	c := cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances: []config.CockroachDBInstanceConfig{{
			Name:    "dead",
			Host:    "127.0.0.1",
			SQLPort: 1, // nothing listens -> ping fails (covers ping error branch)
			// Empty Database and SSLMode exercise the "system"/"disable" defaults.
		}},
	}, zap.NewNop())

	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err) // per-instance failure is swallowed
	assert.Empty(t, buckets)
}
