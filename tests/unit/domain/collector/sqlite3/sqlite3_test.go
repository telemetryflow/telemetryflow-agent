// Package sqlite3_test contains unit tests for the corresponding collector module.
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

package sqlite3_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	sqlitedriver "modernc.org/sqlite"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/sqlite3"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// The production collector opens databases using the driver name "sqlite3".
// Register the pure-Go modernc driver under that name so the real collection
// paths can be exercised without cgo.
func init() {
	sql.Register("sqlite3", &sqlitedriver.Driver{})
}

// --- NewConfig defaults ---

func TestNewConfig_Defaults(t *testing.T) {
	cfg := sqlite3.NewConfig(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Path: "/var/db/app.db"},
		},
	})

	assert.Equal(t, 60*time.Second, cfg.CollectionInterval)
	assert.Equal(t, 300*time.Second, cfg.TableStatsInterval)
	assert.Equal(t, 120*time.Second, cfg.ProcessInterval)
	assert.Equal(t, time.Duration(0), cfg.IntegrityInterval, "integrity disabled by default")
	assert.Equal(t, 300*time.Second, cfg.IntegrityTimeout)

	// applyDatabaseDefaults: Name defaults to Path when empty.
	require.Len(t, cfg.Databases, 1)
	assert.Equal(t, "/var/db/app.db", cfg.Databases[0].Name)
}

func TestNewConfig_CustomValues(t *testing.T) {
	cfg := sqlite3.NewConfig(config.SQLite3CollectorConfig{
		CollectionInterval: 15 * time.Second,
		TableStatsInterval: 45 * time.Second,
		ProcessInterval:    90 * time.Second,
		IntegrityInterval:  600 * time.Second,
		IntegrityTimeout:   30 * time.Second,
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "primary", Path: "/data/primary.db"},
		},
	})

	assert.Equal(t, 15*time.Second, cfg.CollectionInterval)
	assert.Equal(t, 45*time.Second, cfg.TableStatsInterval)
	assert.Equal(t, 90*time.Second, cfg.ProcessInterval)
	assert.Equal(t, 600*time.Second, cfg.IntegrityInterval)
	assert.Equal(t, 30*time.Second, cfg.IntegrityTimeout)

	// Explicit Name is preserved (default not applied).
	assert.Equal(t, "primary", cfg.Databases[0].Name)
}

func TestNewConfig_DatabaseDefaults_EmptyPathAndName(t *testing.T) {
	cfg := sqlite3.NewConfig(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{}, // Neither Name nor Path -> Name stays empty.
		},
	})
	assert.Equal(t, "", cfg.Databases[0].Name)
}

// --- NewSQLite3Collector ---

func TestNewSQLite3Collector(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "db1", Path: "/tmp/db1.db"},
			{Name: "db2", Path: "/tmp/db2.db"},
		},
	}, zap.NewNop())

	assert.Equal(t, "sqlite3", c.Name())
	assert.False(t, c.IsRunning(), "collector should not run before Start")
}

// --- Lifecycle ---

func TestCollector_StopWhenNotRunning(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{}, zap.NewNop())
	assert.NoError(t, c.Stop(), "stopping a non-running collector must be a no-op")
}

func TestCollector_StartStop_ContextCancel(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{{Name: "db", Path: "/tmp/none.db"}},
	}, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// Wait until the collector reports running.
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	cancel() // Start should observe ctx.Done and invoke Stop().

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
	assert.False(t, c.IsRunning())
}

func TestCollector_StartStop_ExplicitStop(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{}, zap.NewNop())

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()

	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	require.NoError(t, c.Stop())

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	assert.False(t, c.IsRunning())
}

func TestCollector_DoubleStart(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{}, zap.NewNop())

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// A second Start while running must error.
	err := c.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	require.NoError(t, c.Stop())
	<-done
}

// --- Collect: no databases ---

func TestCollect_NoDatabases(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{}, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics)
}
