// Package config_test contains unit tests for the internal agent configuration
// package, exercising the Viper-based loader, defaults, validation, and the
// endpoint-resolution helpers.
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
package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	config "github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// writeConfig writes content to tfo-agent.yaml inside a fresh temp dir and returns the file path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tfo-agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestNewLoaderDefaults(t *testing.T) {
	l := config.NewLoader()
	require.NotNil(t, l)

	// Fluent options should return the same loader for chaining.
	assert.Same(t, l, l.WithEnvPrefix("CUSTOM"))
	assert.Same(t, l, l.WithConfigPaths("/tmp/does-not-exist"))
}

func TestLoadDefaultsWhenNoFileFound(t *testing.T) {
	// Point search paths at an empty dir so no config file is found;
	// loader should fall back to defaults + env and validate cleanly.
	l := config.NewLoader().WithConfigPaths(t.TempDir())
	cfg, err := l.Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "localhost:4317", cfg.TelemetryFlow.Endpoint)
	assert.Equal(t, "grpc", cfg.TelemetryFlow.Protocol)
	// Hostname is auto-detected when empty.
	assert.NotEmpty(t, cfg.Agent.Hostname)
}

func TestLoadExplicitFile(t *testing.T) {
	path := writeConfig(t, `
telemetryflow:
  endpoint: "collector.example.com:4317"
  protocol: "http"
heartbeat:
  interval: 30s
`)
	cfg, err := config.NewLoader().Load(path)
	require.NoError(t, err)
	assert.Equal(t, "collector.example.com:4317", cfg.TelemetryFlow.Endpoint)
	assert.Equal(t, "http", cfg.TelemetryFlow.Protocol)
	assert.Equal(t, 30*time.Second, cfg.Heartbeat.Interval)
}

func TestLoadMissingExplicitFile(t *testing.T) {
	_, err := config.NewLoader().Load(filepath.Join(t.TempDir(), "nope.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoadMalformedYAML(t *testing.T) {
	path := writeConfig(t, "telemetryflow: [this is : not valid yaml")
	_, err := config.NewLoader().Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestLoadEnvVarExpansionInValues(t *testing.T) {
	t.Setenv("NODE_IP", "10.1.2.3")
	path := writeConfig(t, `
telemetryflow:
  endpoint: "${NODE_IP}:4317"
`)
	cfg, err := config.NewLoader().Load(path)
	require.NoError(t, err)
	assert.Equal(t, "10.1.2.3:4317", cfg.TelemetryFlow.Endpoint)
}

func TestLoadEnvVarOverride(t *testing.T) {
	t.Setenv("TELEMETRYFLOW_ENDPOINT", "env-host:9999")
	t.Setenv("TELEMETRYFLOW_LOG_LEVEL", "debug")
	l := config.NewLoader().WithConfigPaths(t.TempDir())
	cfg, err := l.Load("")
	require.NoError(t, err)
	assert.Equal(t, "env-host:9999", cfg.TelemetryFlow.Endpoint)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadFileFoundViaSearchPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "tfo-agent.yaml"),
		[]byte("telemetryflow:\n  endpoint: \"searchpath:4317\"\n"),
		0o600,
	))
	cfg, err := config.NewLoader().WithConfigPaths(dir).Load("")
	require.NoError(t, err)
	assert.Equal(t, "searchpath:4317", cfg.TelemetryFlow.Endpoint)
}

func TestLoadOneForAllShorthand(t *testing.T) {
	path := writeConfig(t, `
telemetryflow:
  endpoint: "localhost:4317"
one_for_all:
  enabled: true
`)
	cfg, err := config.NewLoader().Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Collector.Kubernetes.ResourceQuotas)
	assert.True(t, cfg.Collector.Kubernetes.MetricsAPI)
	assert.True(t, cfg.Collector.PrometheusScraper.Enabled)
	assert.True(t, cfg.Collector.RemoteWriteReceiver.Enabled)
}

func TestLoadInvalidProtocol(t *testing.T) {
	path := writeConfig(t, `
telemetryflow:
  endpoint: "localhost:4317"
  protocol: "carrier-pigeon"
`)
	_, err := config.NewLoader().Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestLoadInvalidHeartbeat(t *testing.T) {
	path := writeConfig(t, `
telemetryflow:
  endpoint: "localhost:4317"
heartbeat:
  interval: 100ms
`)
	_, err := config.NewLoader().Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestLoadInvalidEndpointVersion(t *testing.T) {
	path := writeConfig(t, `
telemetryflow:
  endpoint: "localhost:4317"
exporter:
  otlp:
    endpoint_version: "v9"
`)
	_, err := config.NewLoader().Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestLoadFromFileAndReload(t *testing.T) {
	path := writeConfig(t, "telemetryflow:\n  endpoint: \"reload:4317\"\n")
	l := config.NewLoader()

	cfg, err := l.LoadFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, "reload:4317", cfg.TelemetryFlow.Endpoint)

	reloaded, err := l.Reload(path)
	require.NoError(t, err)
	assert.Equal(t, "reload:4317", reloaded.TelemetryFlow.Endpoint)
	// Reload returns a distinct instance (no mutation of the original).
	assert.NotSame(t, cfg, reloaded)
}

func TestGetConfigFilePath(t *testing.T) {
	// Just ensure the accessor is callable and returns a string.
	_ = config.GetConfigFilePath()
}

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	require.NotNil(t, cfg)
	assert.NoError(t, cfg.Validate())
	assert.Equal(t, "localhost:4317", cfg.TelemetryFlow.Endpoint)
}

func TestDurationHelpers(t *testing.T) {
	assert.Equal(t, 48*time.Hour, config.Days(2))
	assert.Equal(t, 3*time.Hour, config.Hours(3))
}

func TestRetentionPolicyDays(t *testing.T) {
	r := &config.RetentionPolicyConfig{}
	r.SetRetentionDays(7)
	assert.Equal(t, 7*24*time.Hour, r.Duration)
	assert.Equal(t, 7, r.RetentionDays())
}

func TestValidateBranches(t *testing.T) {
	t.Run("missing endpoint", func(t *testing.T) {
		c := &config.Config{}
		err := c.Validate()
		require.ErrorIs(t, err, config.ErrMissingEndpoint)
	})

	t.Run("invalid heartbeat", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Heartbeat.Interval = 500 * time.Millisecond
		err := c.Validate()
		require.ErrorIs(t, err, config.ErrInvalidHeartbeatInterval)
	})

	t.Run("invalid protocol", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.Protocol = "smoke-signal"
		err := c.Validate()
		require.ErrorIs(t, err, config.ErrInvalidProtocol)
	})

	t.Run("invalid endpoint version", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Exporter.OTLP.EndpointVersion = "v3"
		err := c.Validate()
		require.ErrorIs(t, err, config.ErrInvalidEndpointVersion)
	})

	t.Run("valid endpoint versions accepted", func(t *testing.T) {
		for _, v := range []string{"v1", "v2"} {
			c := config.DefaultConfig()
			c.Exporter.OTLP.EndpointVersion = v
			assert.NoError(t, c.Validate())
		}
	})

	t.Run("empty protocol skips protocol check", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.Protocol = ""
		assert.NoError(t, c.Validate())
	})
}

func TestConfigErrorMessage(t *testing.T) {
	assert.Equal(t, "telemetryflow.endpoint is required", config.ErrMissingEndpoint.Error())
}

func TestGetEffectiveEndpoint(t *testing.T) {
	t.Run("prefers api endpoint", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "api-host:8080" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		assert.Equal(t, "http://api-host:8080", c.GetEffectiveEndpoint())
	})

	t.Run("falls back to telemetryflow endpoint", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		c.TelemetryFlow.Endpoint = "tf-host:4317"
		assert.Equal(t, "http://tf-host:4317", c.GetEffectiveEndpoint())
	})

	t.Run("keeps existing scheme", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "https://secure:443" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		assert.Equal(t, "https://secure:443", c.GetEffectiveEndpoint())
	})

	t.Run("empty when nothing set", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		c.TelemetryFlow.Endpoint = ""
		assert.Equal(t, "", c.GetEffectiveEndpoint())
	})
}

func TestGetBackendEndpoint(t *testing.T) {
	t.Run("prefers backend endpoint", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.BackendEndpoint = "backend:9000"
		assert.Equal(t, "http://backend:9000", c.GetBackendEndpoint())
	})

	t.Run("falls back to telemetryflow endpoint", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.BackendEndpoint = ""
		c.TelemetryFlow.Endpoint = "tf:4317"
		assert.Equal(t, "http://tf:4317", c.GetBackendEndpoint())
	})

	t.Run("falls back to api endpoint", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.BackendEndpoint = ""
		c.TelemetryFlow.Endpoint = ""
		c.API.Endpoint = "https://api:443" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		assert.Equal(t, "https://api:443", c.GetBackendEndpoint())
	})

	t.Run("empty when nothing set", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.BackendEndpoint = ""
		c.TelemetryFlow.Endpoint = ""
		c.API.Endpoint = "" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		assert.Equal(t, "", c.GetBackendEndpoint())
	})
}

func TestGetEffectiveCredentials(t *testing.T) {
	c := config.DefaultConfig()

	c.API.APIKeyID = "" //nolint:staticcheck // exercises deprecated API field kept for backward compat
	c.TelemetryFlow.APIKeyID = "tf-id"
	assert.Equal(t, "tf-id", c.GetEffectiveAPIKeyID())
	c.API.APIKeyID = "api-id" //nolint:staticcheck // exercises deprecated API field kept for backward compat
	assert.Equal(t, "api-id", c.GetEffectiveAPIKeyID())

	c.API.APIKeySecret = "" //nolint:staticcheck // exercises deprecated API field kept for backward compat
	c.TelemetryFlow.APIKeySecret = "tf-secret"
	assert.Equal(t, "tf-secret", c.GetEffectiveAPIKeySecret())
	c.API.APIKeySecret = "api-secret" //nolint:staticcheck // exercises deprecated API field kept for backward compat
	assert.Equal(t, "api-secret", c.GetEffectiveAPIKeySecret())

	c.TelemetryFlow.WorkspaceID = "ws"
	c.TelemetryFlow.TenantID = "tn"
	assert.Equal(t, "ws", c.GetEffectiveWorkspaceID())
	assert.Equal(t, "tn", c.GetEffectiveTenantID())
}

func TestGetEffectiveTimeoutRetry(t *testing.T) {
	t.Run("configured values", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.Timeout = 5 * time.Second
		c.TelemetryFlow.Retry.MaxAttempts = 7
		c.TelemetryFlow.Retry.InitialInterval = 2 * time.Second
		assert.Equal(t, 5*time.Second, c.GetEffectiveTimeout())
		assert.Equal(t, 7, c.GetEffectiveRetryAttempts())
		assert.Equal(t, 2*time.Second, c.GetEffectiveRetryDelay())
	})

	t.Run("fallback defaults", func(t *testing.T) {
		c := config.DefaultConfig()
		c.TelemetryFlow.Timeout = 0
		c.TelemetryFlow.Retry.MaxAttempts = 0
		c.TelemetryFlow.Retry.InitialInterval = 0
		assert.Equal(t, 30*time.Second, c.GetEffectiveTimeout())
		assert.Equal(t, 3, c.GetEffectiveRetryAttempts())
		assert.Equal(t, time.Second, c.GetEffectiveRetryDelay())
	})
}

func TestGetEffectiveTLSConfig(t *testing.T) {
	c := config.DefaultConfig()
	c.TelemetryFlow.TLS.Enabled = true
	assert.True(t, c.GetEffectiveTLSConfig().Enabled)
}

func TestEndpointPathHelpers(t *testing.T) {
	// clearEndpointOverrides zeroes both the struct and legacy flat per-signal
	// endpoint overrides so the version-derived default path is computed.
	clearEndpointOverrides := func(c *config.Config) {
		c.Exporter.OTLP.Metrics.Endpoint = ""
		c.Exporter.OTLP.Traces.Endpoint = ""
		c.Exporter.OTLP.Logs.Endpoint = ""
		c.Exporter.OTLP.MetricsEndpoint = ""
		c.Exporter.OTLP.TracesEndpoint = ""
		c.Exporter.OTLP.LogsEndpoint = ""
	}

	t.Run("defaults to v2 paths", func(t *testing.T) {
		c := config.DefaultConfig()
		clearEndpointOverrides(c)
		c.Exporter.OTLP.EndpointVersion = ""
		assert.Equal(t, "/v2/metrics", c.GetMetricsEndpointPath())
		assert.Equal(t, "/v2/traces", c.GetTracesEndpointPath())
		assert.Equal(t, "/v2/logs", c.GetLogsEndpointPath())
		assert.Equal(t, "v2", c.GetEndpointVersion())
	})

	t.Run("honors explicit version", func(t *testing.T) {
		c := config.DefaultConfig()
		clearEndpointOverrides(c)
		c.Exporter.OTLP.EndpointVersion = "v1"
		assert.Equal(t, "/v1/metrics", c.GetMetricsEndpointPath())
		assert.Equal(t, "/v1/traces", c.GetTracesEndpointPath())
		assert.Equal(t, "/v1/logs", c.GetLogsEndpointPath())
		assert.Equal(t, "v1", c.GetEndpointVersion())
	})

	t.Run("per-signal struct override wins", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Exporter.OTLP.Metrics.Endpoint = "/custom/metrics"
		c.Exporter.OTLP.Traces.Endpoint = "/custom/traces"
		c.Exporter.OTLP.Logs.Endpoint = "/custom/logs"
		assert.Equal(t, "/custom/metrics", c.GetMetricsEndpointPath())
		assert.Equal(t, "/custom/traces", c.GetTracesEndpointPath())
		assert.Equal(t, "/custom/logs", c.GetLogsEndpointPath())
	})

	t.Run("legacy flat override wins", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Exporter.OTLP.MetricsEndpoint = "/flat/metrics"
		c.Exporter.OTLP.TracesEndpoint = "/flat/traces"
		c.Exporter.OTLP.LogsEndpoint = "/flat/logs"
		assert.Equal(t, "/flat/metrics", c.GetMetricsEndpointPath())
		assert.Equal(t, "/flat/traces", c.GetTracesEndpointPath())
		assert.Equal(t, "/flat/logs", c.GetLogsEndpointPath())
	})
}

func TestGetOTLPEndpoint(t *testing.T) {
	t.Run("full URL override parsed", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Exporter.OTLP.Metrics.Endpoint = "https://collector:4318/v1/metrics"
		host, path, useTLS := c.GetOTLPEndpoint("metrics")
		assert.Equal(t, "collector:4318", host)
		assert.Equal(t, "/v1/metrics", path)
		assert.True(t, useTLS)
	})

	t.Run("bare path override with base host", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "gateway:4318" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		c.TelemetryFlow.TLS.Enabled = false
		c.Exporter.OTLP.Traces.Endpoint = "/custom/traces"
		host, path, useTLS := c.GetOTLPEndpoint("traces")
		assert.Equal(t, "gateway:4318", host)
		assert.Equal(t, "/custom/traces", path)
		assert.False(t, useTLS)
	})

	t.Run("default path from base host", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "gateway:4318" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		c.Exporter.OTLP.EndpointVersion = "v2"
		host, path, _ := c.GetOTLPEndpoint("logs")
		assert.Equal(t, "gateway:4318", host)
		assert.Equal(t, "/v2/logs", path)
	})

	t.Run("base URL with path component prepended", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "http://gateway:4318/prefix" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		// Clear all metric endpoint overrides so the base-path prepend branch runs.
		c.Exporter.OTLP.Metrics.Endpoint = ""
		c.Exporter.OTLP.MetricsEndpoint = ""
		host, path, _ := c.GetOTLPEndpoint("metrics")
		assert.Equal(t, "gateway:4318", host)
		assert.Equal(t, "/prefix/v2/metrics", path)
	})

	t.Run("legacy flat metrics endpoint override", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Exporter.OTLP.MetricsEndpoint = "https://flat:4318/v1/metrics"
		host, path, useTLS := c.GetOTLPEndpoint("metrics")
		assert.Equal(t, "flat:4318", host)
		assert.Equal(t, "/v1/metrics", path)
		assert.True(t, useTLS)
	})

	t.Run("legacy flat traces and logs overrides", func(t *testing.T) {
		c := config.DefaultConfig()
		c.Exporter.OTLP.TracesEndpoint = "http://t:4318/v1/traces"
		c.Exporter.OTLP.LogsEndpoint = "http://l:4318/v1/logs"
		th, tp, _ := c.GetOTLPEndpoint("traces")
		assert.Equal(t, "t:4318", th)
		assert.Equal(t, "/v1/traces", tp)
		lh, lp, _ := c.GetOTLPEndpoint("logs")
		assert.Equal(t, "l:4318", lh)
		assert.Equal(t, "/v1/logs", lp)
	})

	t.Run("no host falls back to raw values", func(t *testing.T) {
		c := config.DefaultConfig()
		c.API.Endpoint = "" //nolint:staticcheck // exercises deprecated API field kept for backward compat
		c.TelemetryFlow.Endpoint = ""
		c.Exporter.OTLP.Metrics.Endpoint = ""
		c.Exporter.OTLP.MetricsEndpoint = ""
		host, path, _ := c.GetOTLPEndpoint("metrics")
		assert.Equal(t, "", host)
		assert.Equal(t, "/v2/metrics", path)
	})
}

func TestSignalEnabledFlags(t *testing.T) {
	c := config.DefaultConfig()
	c.Exporter.OTLP.Enabled = true
	c.Exporter.OTLP.Metrics.Enabled = true
	c.Exporter.OTLP.Traces.Enabled = false
	c.Exporter.OTLP.Logs.Enabled = true

	assert.True(t, c.IsMetricsEnabled())
	assert.False(t, c.IsTracesEnabled())
	assert.True(t, c.IsLogsEnabled())

	c.Exporter.OTLP.Enabled = false
	assert.False(t, c.IsMetricsEnabled())
	assert.False(t, c.IsLogsEnabled())
}

// TestSkipVerifyKeyMigration verifies that the unified "skip_verify" wording is
// honored and that the deprecated *_insecure_skip_verify keys still work
// (backward compatibility) for cAdvisor, Kubelet, and MongoDB instances.
func TestSkipVerifyKeyMigration(t *testing.T) {
	t.Run("new keys bind directly", func(t *testing.T) {
		path := writeConfig(t, `
telemetryflow:
  endpoint: "localhost:4317"
collectors:
  cadvisor:
    tls_skip_verify: true
  kubernetes:
    kubelet_skip_verify: true
  mongodb_community:
    instances:
      - name: m1
        uri: "mongodb://localhost:27017"
        tls_skip_verify: true
`)
		cfg, err := config.NewLoader().Load(path)
		require.NoError(t, err)
		assert.True(t, cfg.Collector.CAdvisor.InsecureSkipVerify)
		assert.True(t, cfg.Collector.Kubernetes.KubeletInsecureSkipVerify)
		require.Len(t, cfg.Collector.MongoDBCommunity.Instances, 1)
		assert.True(t, cfg.Collector.MongoDBCommunity.Instances[0].TLSInsecureSkipVerify)
	})

	t.Run("deprecated keys still honored", func(t *testing.T) {
		path := writeConfig(t, `
telemetryflow:
  endpoint: "localhost:4317"
collectors:
  cadvisor:
    insecure_skip_verify: true
  kubernetes:
    kubelet_insecure_skip_verify: true
  mongodb_community:
    instances:
      - name: m1
        uri: "mongodb://localhost:27017"
        tls_insecure_skip_verify: true
`)
		cfg, err := config.NewLoader().Load(path)
		require.NoError(t, err)
		assert.True(t, cfg.Collector.CAdvisor.InsecureSkipVerify, "cadvisor old key should migrate")
		assert.True(t, cfg.Collector.Kubernetes.KubeletInsecureSkipVerify, "kubelet old key should migrate")
		require.Len(t, cfg.Collector.MongoDBCommunity.Instances, 1)
		assert.True(t, cfg.Collector.MongoDBCommunity.Instances[0].TLSInsecureSkipVerify, "mongodb old key should migrate")
	})
}
