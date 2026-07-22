// Package agent_test contains additional unit tests raising coverage of the
// core Agent construction, orchestration, lifecycle, config wiring, and
// heartbeat/registration paths using in-process fakes only.
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
package agent_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/agent"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// enableAllCollectors flips on every collector plus QAN, the metric export
// pipeline, the Prometheus server, and the Agent API server so agent
// construction exercises the maximum number of branches. DB collectors get a
// single (zero-value) instance so their QAN counterparts are also created.
func enableAllCollectors(cfg *config.Config) {
	c := &cfg.Collector

	c.System.Enabled = true
	c.System.Interval = time.Second
	c.NodeExporter.Enabled = true
	c.CAdvisor.Enabled = true

	c.ClickHouse.Enabled = true
	c.ClickHouse.Instances = []config.ClickHouseInstanceConfig{{}}

	c.CockroachDB.Enabled = true
	c.CockroachDB.Instances = []config.CockroachDBInstanceConfig{{}}

	c.Aurora.Enabled = true
	c.Aurora.EnablePI = true
	c.Aurora.Clusters = []config.AuroraClusterConfig{{}}

	c.MySQL.Enabled = true
	c.MySQL.Instances = []config.MySQLInstanceConfig{{}}

	c.PostgreSQL.Enabled = true
	c.PostgreSQL.Instances = []config.PostgreSQLInstanceConfig{{}}

	c.RDSPostgreSQL.Enabled = true
	c.RDSPostgreSQL.Instances = []config.RDSPostgreSQLInstanceConfig{{}}

	c.SQLite3.Enabled = true
	c.SQLite3.Databases = []config.SQLite3DatabaseConfig{{}}

	c.MongoDBCommunity.Enabled = true
	c.MongoDBCommunity.Instances = []config.MongoDBCommunityInstanceConfig{{}}

	c.MSSQL.Enabled = true
	c.MSSQL.Instances = []config.MSSQLInstanceConfig{{}}

	c.TimescaleDB.Enabled = true
	c.TimescaleDB.Instances = []config.TimescaleDBInstanceConfig{{}}

	c.Redis.Enabled = true
	c.Redis.Instances = []config.RedisInstanceConfig{{}}

	c.Valkey.Enabled = true
	c.Valkey.Instances = []config.ValkeyInstanceConfig{{}}

	c.Memcache.Enabled = true
	c.Memcache.Instances = []config.MemcacheInstanceConfig{{}}

	c.RabbitMQ.Enabled = true
	c.RabbitMQ.Instances = []config.RabbitMQInstanceConfig{{}}

	c.Kafka.Enabled = true
	c.Kafka.Instances = []config.KafkaInstanceConfig{{}}

	c.ConfluentKafka.Enabled = true
	c.ConfluentKafka.Instances = []config.ConfluentKafkaInstanceConfig{{}}

	c.NATS.Enabled = true
	c.NATS.Instances = []config.NATSInstanceConfig{{}}

	c.PubSub.Enabled = true
	c.PubSub.Instances = []config.PubSubInstanceConfig{{}}
}

func newTestLogger() *zap.Logger {
	return zap.NewNop()
}

// TestNewWithAllCollectors drives NewWithConfigFile through the full collector,
// QAN, Prometheus server, Agent API, and metric export branch set.
func TestNewWithAllCollectors(t *testing.T) {
	cfg := config.DefaultConfig()
	enableAllCollectors(cfg)

	// Enable the OTLP metric export pipeline (drives OTLP bridge + forwarder).
	cfg.Exporter.OTLP.Enabled = true
	cfg.Exporter.OTLP.Metrics.Enabled = true

	// Prometheus /metrics server.
	cfg.PrometheusServer.Enabled = true
	cfg.PrometheusServer.Port = 0
	cfg.PrometheusServer.Path = "/metrics"

	// Agent API server (no K8s clientset -> supervisor-only branch).
	cfg.AgentAPI.Enabled = true
	cfg.AgentAPI.Port = 0

	// Prometheus scraper collector with a fully-populated job.
	cfg.Collector.PrometheusScraper.Enabled = true
	cfg.Collector.PrometheusScraper.ScrapeJobs = []config.ScrapeJobConfig{
		{
			JobName:       "job1",
			Enabled:       true,
			StaticTargets: []string{"localhost:9100"},
			BasicAuth:     &config.BasicAuthConfig{Username: "u", Password: "p"},
			RelabelConfigs: []config.RelabelConfig{
				{SourceLabels: []string{"__name__"}, Regex: ".*", TargetLabel: "t", Replacement: "r", Action: "replace"},
			},
		},
	}

	// Remote write receiver with basic auth + TLS.
	cfg.Collector.RemoteWriteReceiver.Enabled = true
	cfg.Collector.RemoteWriteReceiver.Port = 0
	cfg.Collector.RemoteWriteReceiver.BasicAuth = &config.BasicAuthConfig{Username: "u", Password: "p"}
	cfg.Collector.RemoteWriteReceiver.TLS = &config.TLSConfig{SkipVerify: true}

	// QAN across all supported DB engines.
	cfg.QAN.Enabled = true
	cfg.QAN.Interval = time.Second
	cfg.QAN.Collectors.PostgreSQL = true
	cfg.QAN.Collectors.MySQL = true
	cfg.QAN.Collectors.MongoDB = true
	cfg.QAN.Collectors.MSSQL = true
	cfg.QAN.Collectors.CockroachDB = true
	cfg.QAN.Collectors.TimescaleDB = true
	cfg.QAN.Collectors.RDSPostgreSQL = true
	cfg.QAN.Collectors.Aurora = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)

	stats := ag.Stats()
	assert.Greater(t, stats.CollectorCount, 10)
}

// TestNewSupervisorMode covers newCollectorManager's enabled branch and the
// status-report heartbeat wiring.
func TestNewSupervisorMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = true
	cfg.Supervisor.Enabled = true
	cfg.Supervisor.StatusReport = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	// CollectorStates should be non-nil under supervisor mode.
	states := ag.CollectorStates()
	assert.NotNil(t, states)
}

// TestNewFluentBitFallback enables Fluent Bit (which fails to construct without
// the binary) and expects the native log collector fallback branch.
func TestNewFluentBitFallback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.FluentBit.Enabled = true
	cfg.Collector.FluentBit.BinaryPath = "/nonexistent/fluent-bit-binary"
	cfg.Collector.Logs.Enabled = true
	cfg.Exporter.OTLP.Enabled = true
	cfg.Exporter.OTLP.Logs.Enabled = true
	cfg.Exporter.OTLP.Logs.Endpoint = "localhost:4318"

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
}

// TestNewNativeLogCollector covers the native-log branch when Fluent Bit is off.
func TestNewNativeLogCollector(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.FluentBit.Enabled = false
	cfg.Collector.Logs.Enabled = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
}

// TestNewDockerAndEBPF exercises the Docker and eBPF construction branches.
// Both may fail to construct in CI (warn+skip) or succeed; either path is fine.
func TestNewDockerAndEBPF(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.Docker.Enabled = true
	cfg.Collector.Docker.SocketPath = "/nonexistent/docker.sock"
	cfg.Collector.EBPF.Enabled = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
}

// TestNewKubernetesDisabledEnv covers the explicit-disable env branch of the
// K8s auto-detection logic.
func TestNewKubernetesDisabledEnv(t *testing.T) {
	t.Setenv("TELEMETRYFLOW_K8S_ENABLED", "false")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
	assert.False(t, ag.Config().Collector.Kubernetes.Enabled)
}

// TestNewKubernetesAutoDetect covers the auto-enable branch (including the
// sync_to_backend auto-flip). The collector itself fails to construct outside a
// cluster (warn+skip), leaving the agent valid.
func TestNewKubernetesAutoDetect(t *testing.T) {
	os.Unsetenv("TELEMETRYFLOW_K8S_ENABLED")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.Kubernetes.Enabled = false
	cfg.Collector.Kubernetes.SyncToBackend = false

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
	assert.True(t, ag.Config().Collector.Kubernetes.Enabled)
	assert.True(t, ag.Config().Collector.Kubernetes.SyncToBackend)
}

// TestNewKubernetesConstructFail covers the collector construction-failure
// (warn + skip) branch using an unreadable kubeconfig path.
func TestNewKubernetesConstructFail(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.Kubernetes.Enabled = true
	cfg.Collector.Kubernetes.Kubeconfig = "/nonexistent/kubeconfig-does-not-exist"

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
}

// TestNewKubernetesPreconfiguredCluster covers the branch where ClusterID is
// already set (registration skipped) and the KubernetesSync exporter is built
// with the default sync interval (SyncInterval == 0).
func TestNewKubernetesPreconfiguredCluster(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false

	k := &cfg.Collector.Kubernetes
	k.Enabled = true
	k.Kubeconfig = writeFakeKubeconfig(t)
	k.ClusterName = "test-cluster"
	k.ClusterProvider = "self-managed"
	k.SyncToBackend = true
	k.ClusterID = "pre-configured-cluster-id"
	k.SyncInterval = 0 // exercises the default-interval branch

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
}

// TestNewMetricForwarderDefaultInterval covers the forwarder's default-interval
// branch (System.Interval == 0 with at least one collector present).
func TestNewMetricForwarderDefaultInterval(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.System.Interval = 0
	cfg.Collector.NodeExporter.Enabled = true // provides a collector

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
	assert.Equal(t, 1, ag.Stats().CollectorCount)
}

const fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: fake
  cluster:
    server: http://127.0.0.1:1
contexts:
- name: fake
  context:
    cluster: fake
    user: fake
current-context: fake
users:
- name: fake
  user: {}
`

// writeFakeKubeconfig writes an offline-loadable kubeconfig and returns its path.
func writeFakeKubeconfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(p, []byte(fakeKubeconfig), 0o600))
	return p
}

// TestNewKubernetesRegistrationSuccess drives the K8s collector construction,
// successful auto-registration against a fake backend, and KubernetesSync
// creation — using an offline kubeconfig and an httptest backend (no live
// cluster or network egress).
func TestNewKubernetesRegistrationSuccess(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"cluster-uuid-123","name":"test-cluster","isNew":true}`))
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.TelemetryFlow.BackendEndpoint = backend.URL
	cfg.TelemetryFlow.APIKeyID = "tfk_test"
	cfg.TelemetryFlow.APIKeySecret = "tfs_test"

	k := &cfg.Collector.Kubernetes
	k.Enabled = true
	k.Kubeconfig = writeFakeKubeconfig(t)
	k.ClusterName = "test-cluster"
	k.ClusterProvider = "self-managed"
	k.SyncToBackend = true
	k.ClusterID = ""
	k.SyncInterval = time.Minute

	// Enable the Agent API server to also cover the k8s-clientset wiring branch.
	cfg.AgentAPI.Enabled = true
	cfg.AgentAPI.Port = 0

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)

	// Registration succeeded -> ClusterID was populated from the backend.
	assert.Equal(t, "cluster-uuid-123", ag.Config().Collector.Kubernetes.ClusterID)

	// Run briefly to exercise the KubernetesSync start path, then cancel.
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()
	require.Eventually(t, ag.IsRunning, 2*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-runErr:
	case <-time.After(12 * time.Second):
		t.Fatal("agent did not shut down")
	}
}

// TestNewKubernetesRegistrationFailure covers the K8s construction path where
// auto-registration fails (backend refuses the connection), leaving ClusterID
// empty and driving the background registration-retry goroutine in Run.
func TestNewKubernetesRegistrationFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	// Unreachable backend -> registration fails fast (connection refused).
	cfg.TelemetryFlow.BackendEndpoint = "http://127.0.0.1:1"
	cfg.TelemetryFlow.APIKeyID = "tfk_test"
	cfg.TelemetryFlow.APIKeySecret = "tfs_test"

	k := &cfg.Collector.Kubernetes
	k.Enabled = true
	k.Kubeconfig = writeFakeKubeconfig(t)
	k.ClusterName = "test-cluster"
	k.ClusterProvider = "self-managed"
	k.SyncToBackend = true
	k.ClusterID = ""

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)

	// Registration failed -> ClusterID remains empty, no sync exporter created.
	assert.Empty(t, ag.Config().Collector.Kubernetes.ClusterID)

	// Run drives the background registration-retry goroutine. In -short mode we
	// cancel promptly (exit via ctx.Done); otherwise we let one retry attempt
	// fail (first backoff is 15s) to cover the retry-failure/backoff branch.
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()
	require.Eventually(t, ag.IsRunning, 2*time.Second, 10*time.Millisecond)

	if testing.Short() {
		cancel()
	} else {
		time.Sleep(17 * time.Second) // allow the 15s retry to fire and fail
		cancel()
	}
	select {
	case <-runErr:
	case <-time.After(12 * time.Second):
		t.Fatal("agent did not shut down")
	}
}

// TestRunKubernetesRegistrationRetry covers the background registration-retry
// goroutine's success path: initial registration (in New) fails, then the
// retry (after the first backoff) succeeds against the fake backend, creating
// and starting the KubernetesSync exporter. This is the slow path (first
// backoff is 15s) so the test allows ample time.
func TestRunKubernetesRegistrationRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow K8s registration-retry test in -short mode")
	}

	start := time.Now()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail the initial registration attempts; succeed once the background
		// retry fires (well after the 15s first backoff).
		if time.Since(start) < 12*time.Second {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"retry-uuid","name":"test-cluster","isNew":false}`))
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.TelemetryFlow.BackendEndpoint = backend.URL
	cfg.TelemetryFlow.APIKeyID = "tfk_test"
	cfg.TelemetryFlow.APIKeySecret = "tfs_test"

	k := &cfg.Collector.Kubernetes
	k.Enabled = true
	k.Kubeconfig = writeFakeKubeconfig(t)
	k.ClusterName = "test-cluster"
	k.ClusterProvider = "self-managed"
	k.SyncToBackend = true
	k.ClusterID = ""
	k.SyncInterval = time.Minute

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	// Initial registration failed.
	assert.Empty(t, ag.Config().Collector.Kubernetes.ClusterID)

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()

	// Wait for the retry goroutine to register (first backoff is 15s).
	require.Eventually(t, func() bool {
		return ag.Config().Collector.Kubernetes.ClusterID == "retry-uuid"
	}, 25*time.Second, 250*time.Millisecond)

	cancel()
	select {
	case <-runErr:
	case <-time.After(12 * time.Second):
		t.Fatal("agent did not shut down")
	}
}

// TestRunSupervisorMode runs the agent with supervisor mode enabled, driving
// the collectorManager start/stop path.
func TestRunSupervisorMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = true
	cfg.Collector.System.Interval = 50 * time.Millisecond
	cfg.Supervisor.Enabled = true
	cfg.Supervisor.StatusReport = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() { errChan <- ag.Run(ctx) }()

	require.Eventually(t, ag.IsRunning, time.Second, 10*time.Millisecond)

	// CollectorStates should report while running.
	assert.NotNil(t, ag.CollectorStates())

	cancel()
	select {
	case err := <-errChan:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not shut down")
	}
	assert.False(t, ag.IsRunning())
}

// TestRunWithExportPipeline runs the agent with Prometheus + Agent API +
// metric forwarder + OTLP bridge active to cover their start/stop paths.
func TestRunWithExportPipeline(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = true
	cfg.Collector.System.Interval = 50 * time.Millisecond
	cfg.Exporter.OTLP.Enabled = true
	cfg.Exporter.OTLP.Metrics.Enabled = true
	cfg.PrometheusServer.Enabled = true
	cfg.PrometheusServer.Port = 0
	cfg.AgentAPI.Enabled = true
	cfg.AgentAPI.Port = 0

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() { errChan <- ag.Run(ctx) }()

	require.Eventually(t, ag.IsRunning, 2*time.Second, 10*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case <-errChan:
	case <-time.After(12 * time.Second):
		t.Fatal("agent did not shut down")
	}
}

// TestRunComponentError forces the Prometheus server to fail binding (its port
// is already occupied) so Run returns via the component-error branch of its
// select, covering the error-forwarding path.
func TestRunComponentError(t *testing.T) {
	// Bind on all interfaces (":0") so the agent's ":port" server collides.
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer ln.Close()
	occupiedPort := ln.Addr().(*net.TCPAddr).Port

	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.PrometheusServer.Enabled = true
	cfg.PrometheusServer.Port = occupiedPort

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = ag.Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prometheus server error")
}

// TestRunAgentAPIError forces the Agent API server to fail binding so Run
// returns via that component's error branch.
func TestRunAgentAPIError(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer ln.Close()
	occupiedPort := ln.Addr().(*net.TCPAddr).Port

	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.AgentAPI.Enabled = true
	cfg.AgentAPI.Port = occupiedPort

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = ag.Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent API server error")
}

// TestRunWithQAN runs the agent with QAN enabled to cover the QAN exporter and
// forwarder start/stop paths.
func TestRunWithQAN(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.Collector.PostgreSQL.Enabled = true
	cfg.Collector.PostgreSQL.Instances = []config.PostgreSQLInstanceConfig{{}}
	cfg.QAN.Enabled = true
	cfg.QAN.Interval = 50 * time.Millisecond
	cfg.QAN.Collectors.PostgreSQL = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() { errChan <- ag.Run(ctx) }()

	require.Eventually(t, ag.IsRunning, 2*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-errChan:
	case <-time.After(12 * time.Second):
		t.Fatal("agent did not shut down")
	}
}

// TestQANEnabledNoInstances covers the "QAN enabled but no DB collectors" warn
// branch.
func TestQANEnabledNoInstances(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.System.Enabled = false
	cfg.QAN.Enabled = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, ag)
}

// TestReloadConfigErrors covers the two guard clauses of ReloadConfig.
func TestReloadConfigErrors(t *testing.T) {
	t.Run("no supervisor", func(t *testing.T) {
		cfg := config.DefaultConfig()
		ag, err := agent.New(cfg, newTestLogger())
		require.NoError(t, err)
		err = ag.ReloadConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "supervisor")
	})

	t.Run("no config file path", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Supervisor.Enabled = true
		ag, err := agent.New(cfg, newTestLogger())
		require.NoError(t, err)
		err = ag.ReloadConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config file")
	})

	t.Run("bad config file", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Supervisor.Enabled = true
		ag, err := agent.NewWithConfigFile(cfg, newTestLogger(), "/nonexistent/does-not-exist.yaml")
		require.NoError(t, err)
		err = ag.ReloadConfig()
		assert.Error(t, err)
	})
}

// TestReloadConfigSuccess covers the successful reload path including
// rebuildCollectors across the supported collector set.
func TestReloadConfigSuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := `
agent:
  id: "reload-agent"
  hostname: "reload-host"
heartbeat:
  interval: 60s
  timeout: 10s
api:
  endpoint: "http://localhost:3100"
supervisor:
  enabled: true
collectors:
  system:
    enabled: true
    interval: 15s
  node_exporter:
    enabled: true
  cadvisor:
    enabled: true
  clickhouse:
    enabled: true
  cockroachdb:
    enabled: true
  aurora:
    enabled: true
  mysql:
    enabled: true
  postgresql:
    enabled: true
  rds_postgresql:
    enabled: true
  sqlite3:
    enabled: true
  mongodb_community:
    enabled: true
  mssql:
    enabled: true
  timescaledb:
    enabled: true
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))

	// Start from a supervisor-enabled config with a known file path.
	cfg := config.DefaultConfig()
	cfg.Supervisor.Enabled = true
	cfg.Collector.System.Enabled = true
	cfg.Collector.System.Interval = 50 * time.Millisecond

	ag, err := agent.NewWithConfigFile(cfg, newTestLogger(), cfgPath)
	require.NoError(t, err)

	// ReloadConfig (via the supervisor's ApplyDiff) starts the newly-built
	// collectors, so the manager must have a running context. Run the agent
	// first, then reload against the on-disk file.
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()
	require.Eventually(t, ag.IsRunning, 2*time.Second, 10*time.Millisecond)

	err = ag.ReloadConfig()
	require.NoError(t, err)

	assert.Equal(t, cfgPath, ag.ConfigFile())
	// After reload the config should reflect the file contents.
	assert.True(t, ag.Config().Collector.NodeExporter.Enabled)

	cancel()
	select {
	case <-runErr:
	case <-time.After(12 * time.Second):
		t.Fatal("agent did not shut down after reload")
	}
}

// TestProviderAdapter drives the agentProviderAdapter forwarding methods via
// the exported test shim.
func TestProviderAdapter(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Agent.Hostname = "adapter-host"
	cfg.Collector.System.Enabled = true
	cfg.Supervisor.Enabled = true

	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	provider := agent.NewProviderAdapterForTest(ag)

	assert.False(t, provider.IsRunning())

	stats := provider.Stats()
	assert.Equal(t, ag.ID(), stats.ID)
	assert.Equal(t, "adapter-host", stats.Hostname)

	// CollectorStates: supervisor is enabled, collectors registered but not
	// started -> returns a non-nil slice mirrored into agentapi types.
	states := provider.CollectorStates()
	assert.NotNil(t, states)

	// ReloadConfig forwards to the agent; no config file -> error.
	assert.Error(t, provider.ReloadConfig())
}

// TestProviderAdapterNilStates covers the nil-branch of the adapter's
// CollectorStates mirroring when supervisor mode is off.
func TestProviderAdapterNilStates(t *testing.T) {
	cfg := config.DefaultConfig()
	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)

	provider := agent.NewProviderAdapterForTest(ag)
	assert.Nil(t, provider.CollectorStates())
}

// TestConfigAndConfigFileAccessors covers the trivial accessors.
func TestConfigAndConfigFileAccessors(t *testing.T) {
	cfg := config.DefaultConfig()
	ag, err := agent.NewWithConfigFile(cfg, newTestLogger(), "/etc/tfo/agent.yaml")
	require.NoError(t, err)

	assert.Equal(t, "/etc/tfo/agent.yaml", ag.ConfigFile())
	assert.Same(t, cfg, ag.Config())
}

// TestCollectorStatesNoSupervisor covers the nil return when supervisor is off.
func TestCollectorStatesNoSupervisor(t *testing.T) {
	cfg := config.DefaultConfig()
	ag, err := agent.New(cfg, newTestLogger())
	require.NoError(t, err)
	assert.Nil(t, ag.CollectorStates())
}
