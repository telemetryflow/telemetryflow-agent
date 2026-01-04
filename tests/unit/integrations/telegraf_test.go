// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

func TestNewTelegrafExporter(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		config        integrations.TelegrafConfig
		expectedName  string
		expectedType  string
		expectEnabled bool
	}{
		{
			name: "enabled config",
			config: integrations.TelegrafConfig{
				Enabled:  true,
				Address:  "http://localhost:8086/write",
				Protocol: "http",
			},
			expectedName:  "telegraf",
			expectedType:  "collector",
			expectEnabled: true,
		},
		{
			name: "disabled config",
			config: integrations.TelegrafConfig{
				Enabled: false,
			},
			expectedName:  "telegraf",
			expectedType:  "collector",
			expectEnabled: false,
		},
		{
			name: "with all options",
			config: integrations.TelegrafConfig{
				Enabled:         true,
				Address:         "http://localhost:8086/write",
				Protocol:        "http",
				Database:        "telegraf",
				RetentionPolicy: "autogen",
				Precision:       "ns",
				Username:        "admin",
				Password:        "password",
				BatchSize:       5000,
				GlobalTags:      map[string]string{"env": "test"},
			},
			expectedName:  "telegraf",
			expectedType:  "collector",
			expectEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewTelegrafExporter(tt.config, logger)

			require.NotNil(t, exporter)
			assert.Equal(t, tt.expectedName, exporter.Name())
			assert.Equal(t, tt.expectedType, exporter.Type())
			assert.Equal(t, tt.expectEnabled, exporter.IsEnabled())
		})
	}
}

func TestTelegrafExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled config", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: false,
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("valid HTTP config with mock server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
		assert.True(t, exporter.IsInitialized())
	})

	t.Run("valid HTTPS config", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "https",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
		assert.True(t, exporter.IsInitialized())
	})

	t.Run("missing address", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled:  true,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("defaults are set", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled: true,
			Address: server.URL,
			// No protocol, precision, timeout, batch size, flush interval set
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
		assert.True(t, exporter.IsInitialized())
	})

	t.Run("UDP protocol", func(t *testing.T) {
		// Create a UDP listener for testing
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		require.NoError(t, err)
		conn, err := net.ListenUDP("udp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  conn.LocalAddr().String(),
			Protocol: "udp",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err = exporter.Init(ctx)
		assert.NoError(t, err)
		assert.True(t, exporter.IsInitialized())
	})

	t.Run("invalid UDP address", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  "invalid:address:format",
			Protocol: "udp",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})
}

func TestTelegrafExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.TelegrafConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.TelegrafConfig{
				Enabled:  true,
				Address:  "http://localhost:8086/write",
				Protocol: "http",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.TelegrafConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing address when enabled",
			config: integrations.TelegrafConfig{
				Enabled:  true,
				Protocol: "http",
			},
			expectError: true,
		},
		{
			name: "invalid protocol",
			config: integrations.TelegrafConfig{
				Enabled:  true,
				Address:  "http://localhost:8086",
				Protocol: "invalid",
			},
			expectError: true,
		},
		{
			name: "valid UDP protocol",
			config: integrations.TelegrafConfig{
				Enabled:  true,
				Address:  "localhost:8094",
				Protocol: "udp",
			},
			expectError: false,
		},
		{
			name: "valid TCP protocol",
			config: integrations.TelegrafConfig{
				Enabled:  true,
				Address:  "localhost:8094",
				Protocol: "tcp",
			},
			expectError: false,
		},
		{
			name: "empty protocol is valid",
			config: integrations.TelegrafConfig{
				Enabled: true,
				Address: "http://localhost:8086",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewTelegrafExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTelegrafExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export with metrics", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "text/plain; charset=utf-8", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		telemetryData := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{
					Name:      "cpu_usage",
					Value:     45.5,
					Type:      integrations.MetricTypeGauge,
					Timestamp: time.Now(),
					Tags:      map[string]string{"host": "server1"},
				},
			},
		}

		result, err := exporter.Export(ctx, telemetryData)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Contains(t, string(receivedBody), "cpu_usage")
	})

	t.Run("export empty telemetry data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		telemetryData := &integrations.TelemetryData{
			Metrics: []integrations.Metric{},
		}

		result, err := exporter.Export(ctx, telemetryData)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
	})

	t.Run("export when disabled", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: false,
		}
		exporter := integrations.NewTelegrafExporter(config, logger)

		telemetryData := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test_metric", Value: 1.0},
			},
		}

		result, err := exporter.Export(ctx, telemetryData)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestTelegrafExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics successfully", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:   true,
			Address:   server.URL,
			Protocol:  "http",
			Precision: "ns",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		testTime := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "test_metric",
				Value:     42.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: testTime,
				Tags:      map[string]string{"host": "server1", "region": "us-west"},
				Unit:      "percent",
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))
		assert.Greater(t, result.Duration, time.Duration(0))

		// Verify line protocol format
		body := string(receivedBody)
		assert.Contains(t, body, "test_metric")
		assert.Contains(t, body, "host=server1")
		assert.Contains(t, body, "region=us-west")
		assert.Contains(t, body, "value=42.5")
	})

	t.Run("export metrics with global tags", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:    true,
			Address:    server.URL,
			Protocol:   "http",
			GlobalTags: map[string]string{"env": "production", "dc": "us-east-1"},
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{
				Name:      "cpu_usage",
				Value:     75.0,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "server1"},
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)

		body := string(receivedBody)
		assert.Contains(t, body, "dc=us-east-1")
		assert.Contains(t, body, "env=production")
		assert.Contains(t, body, "host=server1")
	})

	t.Run("export metrics with different precisions", func(t *testing.T) {
		precisions := []string{"s", "ms", "us", "ns"}

		for _, precision := range precisions {
			t.Run("precision_"+precision, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				config := integrations.TelegrafConfig{
					Enabled:   true,
					Address:   server.URL,
					Protocol:  "http",
					Precision: precision,
				}
				exporter := integrations.NewTelegrafExporter(config, logger)
				err := exporter.Init(ctx)
				require.NoError(t, err)

				metrics := []integrations.Metric{
					{
						Name:      "test_metric",
						Value:     1.0,
						Timestamp: time.Now(),
					},
				}

				result, err := exporter.ExportMetrics(ctx, metrics)
				require.NoError(t, err)
				assert.True(t, result.Success)
			})
		}
	})

	t.Run("export metrics with authentication", func(t *testing.T) {
		var authHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
			Username: "testuser",
			Password: "testpass",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test_metric", Value: 1.0, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.NotEmpty(t, authHeader)
		assert.Contains(t, authHeader, "Basic")
	})

	t.Run("export metrics with custom headers", func(t *testing.T) {
		var customHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			customHeader = r.Header.Get("X-Custom-Header")
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
			Headers:  map[string]string{"X-Custom-Header": "custom-value"},
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test_metric", Value: 1.0, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, "custom-value", customHeader)
	})

	t.Run("export metrics when disabled", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: false,
		}
		exporter := integrations.NewTelegrafExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test_metric", Value: 1.0},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export metrics when not initialized", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: true,
			Address: "http://localhost:8086",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		// Do not call Init

		metrics := []integrations.Metric{
			{Name: "test_metric", Value: 1.0},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export metrics server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal Server Error"))
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test_metric", Value: 1.0, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("export metrics with special characters in measurement name", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{
				Name:      "cpu,usage test",
				Value:     50.0,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)

		body := string(receivedBody)
		// Comma and space should be escaped
		assert.Contains(t, body, `cpu\,usage\ test`)
	})

	t.Run("export multiple metrics in batch", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{Name: "metric1", Value: 1.0, Timestamp: now},
			{Name: "metric2", Value: 2.0, Timestamp: now},
			{Name: "metric3", Value: 3.0, Timestamp: now},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)

		body := string(receivedBody)
		assert.Contains(t, body, "metric1")
		assert.Contains(t, body, "metric2")
		assert.Contains(t, body, "metric3")
	})
}

func TestTelegrafExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs successfully", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-app",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))

		body := string(receivedBody)
		assert.Contains(t, body, "logs")
		assert.Contains(t, body, "level=info")
		assert.Contains(t, body, "source=test-app")
		assert.Contains(t, body, "message=")
	})

	t.Run("export logs with global tags", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:    true,
			Address:    server.URL,
			Protocol:   "http",
			GlobalTags: map[string]string{"env": "test"},
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelError,
				Message:   "Error occurred",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		assert.True(t, result.Success)

		body := string(receivedBody)
		assert.Contains(t, body, "env=test")
		assert.Contains(t, body, "level=error")
	})

	t.Run("export logs with different log levels", func(t *testing.T) {
		levels := []integrations.LogLevel{
			integrations.LogLevelDebug,
			integrations.LogLevelInfo,
			integrations.LogLevelWarn,
			integrations.LogLevelError,
			integrations.LogLevelFatal,
		}

		for _, level := range levels {
			t.Run(string(level), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				config := integrations.TelegrafConfig{
					Enabled:  true,
					Address:  server.URL,
					Protocol: "http",
				}
				exporter := integrations.NewTelegrafExporter(config, logger)
				err := exporter.Init(ctx)
				require.NoError(t, err)

				logs := []integrations.LogEntry{
					{Timestamp: time.Now(), Level: level, Message: "Test message"},
				}

				result, err := exporter.ExportLogs(ctx, logs)
				require.NoError(t, err)
				assert.True(t, result.Success)
			})
		}
	})

	t.Run("export logs when disabled", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: false,
		}
		exporter := integrations.NewTelegrafExporter(config, logger)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export logs when not initialized", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: true,
			Address: "http://localhost:8086",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		// Do not call Init

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export multiple logs", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := []integrations.LogEntry{
			{Timestamp: now, Level: integrations.LogLevelInfo, Message: "Log 1"},
			{Timestamp: now, Level: integrations.LogLevelWarn, Message: "Log 2"},
			{Timestamp: now, Level: integrations.LogLevelError, Message: "Log 3"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)

		body := string(receivedBody)
		lines := strings.Split(strings.TrimSpace(body), "\n")
		assert.Len(t, lines, 3)
	})
}

func TestTelegrafExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("traces not supported", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  "http://localhost:8086",
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)

		traces := []integrations.Trace{
			{
				TraceID:       "trace-123",
				SpanID:        "span-456",
				OperationName: "test-operation",
				ServiceName:   "test-service",
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not natively support traces")
	})
}

func TestTelegrafExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("health check disabled", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: false,
		}
		exporter := integrations.NewTelegrafExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("health check HTTP success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "HEAD", r.Method)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Message, "status: 200")
		assert.Greater(t, status.Latency, time.Duration(0))
	})

	t.Run("health check HTTP 204 success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
	})

	t.Run("health check HTTP server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "500")
	})

	t.Run("health check HTTP connection failed", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  "http://localhost:59999", // Non-existent port
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("health check UDP configured", func(t *testing.T) {
		// Create a UDP listener
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		require.NoError(t, err)
		conn, err := net.ListenUDP("udp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  conn.LocalAddr().String(),
			Protocol: "udp",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err = exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "UDP socket configured", status.Message)
		assert.NotNil(t, status.Details)
		assert.Equal(t, conn.LocalAddr().String(), status.Details["address"])
	})

	t.Run("health check default protocol", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled: true,
			Address: server.URL,
			// No protocol specified, defaults should be applied during Init
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		// Should work with default HTTP protocol
		assert.True(t, status.Healthy)
	})
}

func TestTelegrafExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("close HTTP client", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)
		assert.True(t, exporter.IsInitialized())

		err = exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close UDP connection", func(t *testing.T) {
		// Create a UDP listener
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		require.NoError(t, err)
		conn, err := net.ListenUDP("udp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  conn.LocalAddr().String(),
			Protocol: "udp",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err = exporter.Init(ctx)
		require.NoError(t, err)

		err = exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close uninitialized exporter", func(t *testing.T) {
		config := integrations.TelegrafConfig{
			Enabled: true,
			Address: "http://localhost:8086",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		// Do not call Init

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})
}

func TestTelegrafExporterUDPExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics via UDP", func(t *testing.T) {
		// Create a UDP listener
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		require.NoError(t, err)
		listener, err := net.ListenUDP("udp", addr)
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		// Channel to receive data
		received := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 4096)
			n, _, _ := listener.ReadFromUDP(buf)
			received <- buf[:n]
		}()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  listener.LocalAddr().String(),
			Protocol: "udp",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err = exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{
				Name:      "udp_test_metric",
				Value:     123.456,
				Timestamp: time.Now(),
				Tags:      map[string]string{"type": "udp"},
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)

		// Wait for data
		select {
		case data := <-received:
			assert.Contains(t, string(data), "udp_test_metric")
			assert.Contains(t, string(data), "type=udp")
			assert.Contains(t, string(data), "value=123.456")
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for UDP data")
		}
	})

	t.Run("export logs via UDP", func(t *testing.T) {
		// Create a UDP listener
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		require.NoError(t, err)
		listener, err := net.ListenUDP("udp", addr)
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		received := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 4096)
			n, _, _ := listener.ReadFromUDP(buf)
			received <- buf[:n]
		}()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  listener.LocalAddr().String(),
			Protocol: "udp",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err = exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "UDP log test message",
				Source:    "udp-source",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		assert.True(t, result.Success)

		select {
		case data := <-received:
			assert.Contains(t, string(data), "logs")
			assert.Contains(t, string(data), "level=info")
			assert.Contains(t, string(data), "source=udp-source")
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for UDP data")
		}
	})
}

func TestTelegrafExporterLineProtocol(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("line protocol with unit field", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{
				Name:      "memory_usage",
				Value:     85.5,
				Timestamp: time.Now(),
				Unit:      "percent",
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)

		body := string(receivedBody)
		assert.Contains(t, body, "value=85.5")
		assert.Contains(t, body, `unit="percent"`)
	})

	t.Run("line protocol with empty tags", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{
				Name:      "simple_metric",
				Value:     42.0,
				Timestamp: time.Now(),
				// No tags
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)

		body := string(receivedBody)
		assert.Contains(t, body, "simple_metric value=42")
	})

	t.Run("line protocol escapes special characters in tags", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.TelegrafConfig{
			Enabled:  true,
			Address:  server.URL,
			Protocol: "http",
		}
		exporter := integrations.NewTelegrafExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{
				Name:      "test_metric",
				Value:     1.0,
				Timestamp: time.Now(),
				Tags: map[string]string{
					"key,with,commas": "value with spaces",
					"key=with=equals": "value,with,commas",
				},
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		assert.True(t, result.Success)

		body := string(receivedBody)
		// Verify special characters are escaped
		assert.Contains(t, body, `key\,with\,commas=value\ with\ spaces`)
		assert.Contains(t, body, `key\=with\=equals=value\,with\,commas`)
	})
}

func TestTelegrafExporterConfigDefaults(t *testing.T) {
	t.Run("config defaults", func(t *testing.T) {
		config := integrations.TelegrafConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Address)
		assert.Empty(t, config.Protocol)
		assert.Empty(t, config.Database)
		assert.Empty(t, config.Precision)
		assert.Equal(t, 0, config.BatchSize)
		assert.Equal(t, time.Duration(0), config.Timeout)
		assert.Equal(t, time.Duration(0), config.FlushInterval)
	})
}

func BenchmarkNewTelegrafExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.TelegrafConfig{
		Enabled:  true,
		Address:  "http://localhost:8086/write",
		Protocol: "http",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewTelegrafExporter(config, logger)
	}
}

func BenchmarkTelegrafExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.TelegrafConfig{
		Enabled:  true,
		Address:  server.URL,
		Protocol: "http",
	}
	exporter := integrations.NewTelegrafExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{
			Name:      "benchmark_metric",
			Value:     42.5,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server1", "region": "us-west"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkTelegrafExporterExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.TelegrafConfig{
		Enabled:  true,
		Address:  server.URL,
		Protocol: "http",
	}
	exporter := integrations.NewTelegrafExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Benchmark log message",
			Source:    "benchmark-app",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}
