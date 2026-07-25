// Package integration_test contains integration tests that spin up real
// services via Docker testcontainers. These tests only run when invoked with
// the `integration` build tag (go test -tags integration).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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

//go:build integration

package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	rediscol "github.com/telemetryflow/telemetryflow-agent/internal/collector/redis"
	valkeycol "github.com/telemetryflow/telemetryflow-agent/internal/collector/valkey"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// TestMain detects once whether the Docker daemon is reachable so each test
// can short-circuit with a focused t.Skip. Without Docker (e.g. on bare CI
// runners) every test in this file is skipped automatically rather than
// failing at the first GenericContainer call. m.Run is still invoked so the
// skip messages show up in `go test -v` output instead of "no tests to run".
func TestMain(m *testing.M) {
	dockerAvailable = checkDocker()
	os.Exit(m.Run())
}

// skipIfNoDocker shortens each test function so it stops as soon as Docker is
// unavailable. Putting the gate inside TestMain is not enough because
// t.Skipf carries useful context (which test was skipped and why).
func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if !dockerAvailable {
		t.Skip("docker daemon unavailable: skipping testcontainers test")
	}
}

// TestRedisCollector_RealInstance spins up a real redis:7-alpine container,
// points the TelemetryFlow Redis collector at it, seeds a small keyspace, and
// asserts that a representative set of db.redis.* metrics is emitted.
func TestRedisCollector_RealInstance(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	container, err := startRedisContainer(ctx)
	if err != nil {
		t.Skipf("redis container unavailable: %v", err)
	}
	defer func() { _ = container.Terminate(context.Background()) }()

	host, port, err := containerHostPort(ctx, container, redisPort)
	if err != nil {
		t.Fatalf("resolve host/port: %v", err)
	}

	cfg := config.RedisCollectorConfig{
		Enabled: true,
		Instances: []config.RedisInstanceConfig{{
			Name:                "test",
			Host:                host,
			Port:                port,
			CollectCommandStats: true,
		}},
	}
	coll := rediscol.NewRedisCollector(cfg, zap.NewNop())
	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = coll.Stop() }()

	seedRedisData(t, host, port, "")

	metrics, err := coll.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics from live Redis instance")
	}

	// A real Redis INFO "all" response covers server, clients, memory,
	// persistence, stats, replication, and keyspace sections — well over 30
	// distinct db.redis.* metrics.
	if len(metrics) < 30 {
		t.Errorf("expected >= 30 metrics, got %d", len(metrics))
	}

	expected := map[string]bool{
		"db.redis.uptime_seconds":           false,
		"db.redis.connected_clients":        false,
		"db.redis.used_memory":              false,
		"db.redis.used_memory_rss":          false,
		"db.redis.mem_fragmentation_ratio":  false,
		"db.redis.total_commands_processed": false,
		"db.redis.ops_per_sec":              false,
		"db.redis.role":                     false,
		"db.redis.connected_slaves":         false,
		"db.redis.aof_enabled":              false,
	}
	for _, m := range metrics {
		if found, ok := expected[m.Name]; ok && !found {
			expected[m.Name] = true
		}
		if m.Labels["redis_instance"] != "test" {
			t.Errorf("metric %s missing redis_instance=test label", m.Name)
		}
		if m.Labels["db_system"] != "redis" {
			t.Errorf("metric %s missing db_system=redis label", m.Name)
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("missing expected metric: %s", name)
		}
	}
}

// TestRedisCollector_AuthRequired verifies that the collector succeeds when
// the correct password is configured against a requirepass-protected instance.
func TestRedisCollector_AuthRequired(t *testing.T) {
	skipIfNoDocker(t)
	const password = "tfo-secret"

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	container, err := startRedisContainerWithAuth(ctx, password)
	if err != nil {
		t.Skipf("auth redis container unavailable: %v", err)
	}
	defer func() { _ = container.Terminate(context.Background()) }()

	host, port, err := containerHostPort(ctx, container, redisPort)
	if err != nil {
		t.Fatalf("resolve host/port: %v", err)
	}

	t.Run("auth_failure_without_password", func(t *testing.T) {
		cfg := config.RedisCollectorConfig{
			Enabled: true,
			Instances: []config.RedisInstanceConfig{{
				Name: "noauth", Host: host, Port: port,
			}},
		}
		coll := rediscol.NewRedisCollector(cfg, zap.NewNop())
		_ = coll.Start(ctx)
		defer func() { _ = coll.Stop() }()
		metrics, err := coll.Collect(ctx)
		if err != nil {
			t.Fatalf("Collect top-level error: %v", err)
		}
		if len(metrics) != 0 {
			t.Fatalf("expected zero metrics without AUTH, got %d", len(metrics))
		}
	})

	t.Run("auth_success_with_password", func(t *testing.T) {
		cfg := config.RedisCollectorConfig{
			Enabled: true,
			Instances: []config.RedisInstanceConfig{{
				Name: "auth", Host: host, Port: port, Password: password,
			}},
		}
		coll := rediscol.NewRedisCollector(cfg, zap.NewNop())
		if err := coll.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer func() { _ = coll.Stop() }()
		metrics, err := coll.Collect(ctx)
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if len(metrics) == 0 {
			t.Fatal("expected metrics after successful AUTH")
		}
	})
}

// TestValkeyCollector_RealInstance runs the Valkey collector against a live
// valkey/valkey:7.2-alpine container and asserts the db.valkey.* metrics are
// produced. Valkey is wire-compatible with Redis, so the same RESP code path
// is exercised under a different engine.
func TestValkeyCollector_RealInstance(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	container, err := startValkeyContainer(ctx)
	if err != nil {
		t.Skipf("valkey container unavailable: %v", err)
	}
	defer func() { _ = container.Terminate(context.Background()) }()

	host, port, err := containerHostPort(ctx, container, redisPort)
	if err != nil {
		t.Fatalf("resolve host/port: %v", err)
	}

	cfg := config.ValkeyCollectorConfig{
		Enabled: true,
		Instances: []config.ValkeyInstanceConfig{{
			Name:                "test",
			Host:                host,
			Port:                port,
			CollectCommandStats: true,
		}},
	}
	coll := valkeycol.NewValkeyCollector(cfg, zap.NewNop())
	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = coll.Stop() }()

	seedRedisData(t, host, port, "")

	metrics, err := coll.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics from live Valkey instance")
	}
	if len(metrics) < 20 {
		t.Errorf("expected >= 20 valkey metrics, got %d", len(metrics))
	}

	// None of the metrics produced by the Valkey collector should carry the
	// db.redis.* prefix — this catches accidental namespace bleed-through.
	for _, m := range metrics {
		if strings.HasPrefix(m.Name, "db.redis.") {
			t.Errorf("valkey collector emitted redis metric %s", m.Name)
		}
		if m.Labels["valkey_instance"] != "test" {
			t.Errorf("metric %s missing valkey_instance=test label", m.Name)
		}
		if m.Labels["db_system"] != "valkey" {
			t.Errorf("metric %s missing db_system=valkey label", m.Name)
		}
	}

	expected := map[string]bool{
		"db.valkey.uptime_seconds":          false,
		"db.valkey.connected_clients":       false,
		"db.valkey.used_memory":             false,
		"db.valkey.mem_fragmentation_ratio": false,
		"db.valkey.ops_per_sec":             false,
		"db.valkey.aof_enabled":             false,
	}
	for _, m := range metrics {
		if found, ok := expected[m.Name]; ok && !found {
			expected[m.Name] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("missing expected metric: %s", name)
		}
	}
}
