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
	"fmt"
	"strings"
	"testing"
	"time"

	dockerclient "github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	rediscol "github.com/telemetryflow/telemetryflow-agent/internal/collector/redis"
)

const (
	// redisImage is a stable, lightweight Redis image used for tests.
	redisImage = "redis:7-alpine"
	// valkeyImage is a stable Valkey image (Valkey is the Redis fork). It
	// speaks the RESP wire protocol and accepts the same INFO commands.
	valkeyImage = "valkey/valkey:7.2-alpine"
	// redisPort is the canonical in-container port for both engines.
	redisPort = "6379/tcp"
	// startupTimeout bounds how long we wait for a container to accept
	// connections before declaring the test setup failed.
	startupTimeout = 60 * time.Second
)

// dockerAvailable reports whether the Docker daemon is reachable. It is
// populated once by TestMain so every test in the package can short-circuit
// with t.Skip on CI runners that do not expose Docker.
var dockerAvailable bool

// checkDocker pings the local Docker daemon using the moby client (already a
// transitive dependency through the docker collector). The ping honours a
// short timeout so environments without Docker fail fast instead of hanging.
func checkDocker() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return false
	}
	defer func() { _ = cli.Close() }()
	if _, err := cli.Ping(ctx, dockerclient.PingOptions{}); err != nil {
		return false
	}
	return true
}

// startRedisContainer launches a redis:7-alpine container with no password and
// waits until the engine reports it is ready to accept client connections.
func startRedisContainer(ctx context.Context) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        redisImage,
		ExposedPorts: []string{redisPort},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(startupTimeout),
	}
	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

// startValkeyContainer launches a valkey/valkey:7.2-alpine container. Valkey
// reuses the Redis INFO protocol, so we wait for the same "Ready to accept
// connections" banner.
func startValkeyContainer(ctx context.Context) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        valkeyImage,
		ExposedPorts: []string{redisPort},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(startupTimeout),
	}
	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

// startRedisContainerWithAuth launches a redis container configured with
// `requirepass <password>` so tests can exercise the AUTH path. Returns the
// container; the caller supplies the same password to the collector.
func startRedisContainerWithAuth(ctx context.Context, password string) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        redisImage,
		ExposedPorts: []string{redisPort},
		Cmd:          []string{"redis-server", "--requirepass", password},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(startupTimeout),
	}
	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

// containerHostPort resolves the externally mapped host/port for a given
// in-container port (e.g. "6379/tcp"). The port string must include the
// protocol suffix used in ExposedPorts.
func containerHostPort(ctx context.Context, c testcontainers.Container, port string) (string, int, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("container host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, port)
	if err != nil {
		return "", 0, fmt.Errorf("mapped port %s: %w", port, err)
	}
	return host, int(mapped.Num()), nil
}

// seedRedisData opens a RESP connection against the running container and
// writes a handful of keys so the keyspace section of INFO is non-zero. This
// keeps the integration assertions realistic without depending on engine
// internals that already produce keyspace rows.
func seedRedisData(t *testing.T, host string, port int, password string) {
	t.Helper()
	cli := rediscol.NewRespClient(host, port, password, 0, false, false, 10*time.Second)
	if err := cli.Connect(); err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	defer cli.Close()
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("tfo:integration:%d", i)
		// RespClient.BulkString tolerates simple-string replies (+OK), so it
		// doubles as a way to issue SET commands without a dedicated helper.
		if _, err := cli.BulkString([]string{"SET", key, strings.Repeat("x", 32)}); err != nil {
			t.Fatalf("seed SET %s: %v", key, err)
		}
	}
}
