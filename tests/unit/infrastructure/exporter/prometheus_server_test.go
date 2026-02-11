package exporter_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func testPrometheusConfig(port int) config.PrometheusServerConfig {
	return config.PrometheusServerConfig{
		Enabled:               true,
		Port:                  port,
		Path:                  "/metrics",
		IncludeGoMetrics:      false,
		IncludeProcessMetrics: false,
		MetricPrefix:          "tfo",
		ReadTimeout:           5 * time.Second,
		WriteTimeout:          5 * time.Second,
	}
}

func TestPrometheusServerStartStop(t *testing.T) {
	logger := zap.NewNop()
	cfg := testPrometheusConfig(19090)
	server := exporter.NewPrometheusServer(cfg, logger)

	assert.False(t, server.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)
	assert.True(t, server.IsRunning())

	cancel()
	err := <-errCh
	assert.NoError(t, err)
	assert.False(t, server.IsRunning())
}

func TestPrometheusServerMetricsEndpoint(t *testing.T) {
	logger := zap.NewNop()
	cfg := testPrometheusConfig(19091)
	server := exporter.NewPrometheusServer(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", cfg.Port))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Should contain agent self-metrics
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "tfo_agent_info")
	assert.Contains(t, bodyStr, "tfo_agent_uptime_seconds")
}

func TestPrometheusServerReadyEndpoint(t *testing.T) {
	logger := zap.NewNop()
	cfg := testPrometheusConfig(19092)
	server := exporter.NewPrometheusServer(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/ready", cfg.Port))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ready", string(body))
}

func TestPrometheusServerUpdateMetrics(t *testing.T) {
	logger := zap.NewNop()
	cfg := testPrometheusConfig(19093)
	server := exporter.NewPrometheusServer(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Feed metrics
	metrics := []collector.Metric{
		collector.NewMetric("system.cpu.usage", 45.5, collector.MetricTypeGauge).
			WithUnit("percent").
			WithDescription("CPU usage"),
		collector.NewMetric("k8s.node.status", 1.0, collector.MetricTypeGauge).
			WithLabel("cluster", "test").
			WithLabel("node", "worker-1").
			WithDescription("Node status"),
	}
	server.UpdateMetrics(metrics)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", cfg.Port))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "tfo_system_cpu_usage")
	assert.Contains(t, bodyStr, "tfo_k8s_node_status")
}

func TestPrometheusServerRootRedirect(t *testing.T) {
	logger := zap.NewNop()
	cfg := testPrometheusConfig(19094)
	server := exporter.NewPrometheusServer(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Don't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/", cfg.Port))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Equal(t, "/metrics", resp.Header.Get("Location"))
}

func TestPrometheusServerDoubleStart(t *testing.T) {
	logger := zap.NewNop()
	cfg := testPrometheusConfig(19095)
	server := exporter.NewPrometheusServer(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	err := server.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}
