// package integrations_test provides unit tests for the Blackbox exporter integration.
package integrations_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// TestNewBlackboxExporter tests the NewBlackboxExporter constructor
func TestNewBlackboxExporter(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name           string
		config         integrations.BlackboxConfig
		expectedName   string
		expectedType   string
		expectedEnable bool
	}{
		{
			name: "enabled config",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Module:   "http_2xx",
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
			},
			expectedName:   "blackbox",
			expectedType:   "synthetic",
			expectedEnable: true,
		},
		{
			name: "disabled config",
			config: integrations.BlackboxConfig{
				Enabled: false,
			},
			expectedName:   "blackbox",
			expectedType:   "synthetic",
			expectedEnable: false,
		},
		{
			name: "config with custom settings",
			config: integrations.BlackboxConfig{
				Enabled:        true,
				Endpoint:       "http://blackbox.local:9115",
				Module:         "http_2xx",
				ScrapeInterval: 60 * time.Second,
				Timeout:        30 * time.Second,
				Targets: []integrations.BlackboxTarget{
					{Name: "target1", Target: "http://service1.local"},
					{Name: "target2", Target: "http://service2.local"},
				},
				Labels: map[string]string{"env": "test"},
			},
			expectedName:   "blackbox",
			expectedType:   "synthetic",
			expectedEnable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewBlackboxExporter(tt.config, logger)

			require.NotNil(t, exporter)
			assert.Equal(t, tt.expectedName, exporter.Name())
			assert.Equal(t, tt.expectedType, exporter.Type())
			assert.Equal(t, tt.expectedEnable, exporter.IsEnabled())
			assert.Contains(t, exporter.SupportedDataTypes(), integrations.DataTypeMetrics)
		})
	}
}

// TestBlackboxExporterInit tests the Init method
func TestBlackboxExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.BlackboxConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.BlackboxConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.BlackboxConfig{
				Enabled: true,
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
			},
			expectError: true,
		},
		{
			name: "missing targets",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
			},
			expectError: true,
		},
		{
			name: "target without URL",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: ""},
				},
			},
			expectError: true,
		},
		{
			name: "config with defaults applied",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
				// Module, ScrapeInterval, and Timeout should get defaults
			},
			expectError: false,
		},
		{
			name: "config with custom timeout",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Timeout:  5 * time.Second,
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewBlackboxExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.config.Enabled {
					assert.True(t, exporter.IsInitialized())
				}
			}
		})
	}
}

// TestBlackboxExporterValidate tests the Validate method
func TestBlackboxExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.BlackboxConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
			},
			expectError: false,
		},
		{
			name: "disabled config skips validation",
			config: integrations.BlackboxConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.BlackboxConfig{
				Enabled: true,
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: "http://example.com"},
				},
			},
			expectError: true,
			errorField:  "endpoint",
		},
		{
			name: "empty targets",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets:  []integrations.BlackboxTarget{},
			},
			expectError: true,
			errorField:  "targets",
		},
		{
			name: "target with empty URL",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets: []integrations.BlackboxTarget{
					{Name: "test", Target: ""},
				},
			},
			expectError: true,
			errorField:  "target",
		},
		{
			name: "multiple targets with one empty",
			config: integrations.BlackboxConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9115",
				Targets: []integrations.BlackboxTarget{
					{Name: "valid", Target: "http://example.com"},
					{Name: "invalid", Target: ""},
				},
			},
			expectError: true,
			errorField:  "target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewBlackboxExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorField != "" {
					assert.Contains(t, err.Error(), tt.errorField)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBlackboxExporterExport tests the Export method
func TestBlackboxExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("successful export with mock probe server", func(t *testing.T) {
		// Create a mock Blackbox exporter server
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/probe", r.URL.Path)
			assert.NotEmpty(t, r.URL.Query().Get("target"))
			assert.NotEmpty(t, r.URL.Query().Get("module"))

			// Return successful probe response
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 1
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.123456
`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test-target", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{
			Timestamp: time.Now(),
			AgentID:   "test-agent",
			Hostname:  "test-host",
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)

		// Verify metrics were added to data
		assert.NotEmpty(t, data.Metrics)
	})

	t.Run("export with disabled exporter", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled: false,
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		_ = exporter.Init(ctx)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)

		assert.Error(t, err)
		assert.Equal(t, integrations.ErrNotEnabled, err)
		assert.Nil(t, result)
	})

	t.Run("export with multiple targets", func(t *testing.T) {
		requestCount := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 1`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "target1", Target: "http://service1.local"},
				{Name: "target2", Target: "http://service2.local"},
				{Name: "target3", Target: "http://service3.local"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)
		assert.Equal(t, 3, requestCount)
	})

	t.Run("export with failed probe", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 0`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://failing-service.local"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
	})
}

// TestBlackboxExporterProbeAll tests the ProbeAll method
func TestBlackboxExporterProbeAll(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("probe all targets successfully", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 1`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "target1", Target: "http://service1.local"},
				{Name: "target2", Target: "http://service2.local"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		results, err := exporter.ProbeAll(ctx)
		require.NoError(t, err)
		assert.Len(t, results, 2)

		for _, result := range results {
			assert.True(t, result.Success)
			assert.NotEmpty(t, result.Target)
			assert.NotZero(t, result.Timestamp)
		}
	})

	t.Run("probe all with disabled exporter", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled: false,
		}

		exporter := integrations.NewBlackboxExporter(config, logger)

		results, err := exporter.ProbeAll(ctx)
		assert.Error(t, err)
		assert.Equal(t, integrations.ErrNotEnabled, err)
		assert.Nil(t, results)
	})

	t.Run("probe all with uninitialized exporter", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: "http://localhost:9115",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		// Do not call Init

		results, err := exporter.ProbeAll(ctx)
		assert.Error(t, err)
		assert.Equal(t, integrations.ErrNotInitialized, err)
		assert.Nil(t, results)
	})

	t.Run("probe all with mixed success and failure", func(t *testing.T) {
		requestNum := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestNum++
			if requestNum%2 == 0 {
				// Simulate connection error for even requests
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 1`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "target1", Target: "http://service1.local"},
				{Name: "target2", Target: "http://service2.local"},
				{Name: "target3", Target: "http://service3.local"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		results, err := exporter.ProbeAll(ctx)
		require.NoError(t, err)
		assert.Len(t, results, 3)
	})
}

// TestBlackboxExporterProbe tests the Probe method for a single target
func TestBlackboxExporterProbe(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("successful probe", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/probe", r.URL.Path)
			assert.Equal(t, "http://example.com", r.URL.Query().Get("target"))
			assert.Equal(t, "http_2xx", r.URL.Query().Get("module"))

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 1
# HELP probe_duration_seconds Duration of the probe
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.05
`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		target := integrations.BlackboxTarget{
			Name:   "test-target",
			Target: "http://example.com",
			Labels: map[string]string{"env": "test"},
		}

		result, err := exporter.Probe(ctx, target)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "http://example.com", result.Target)
		assert.Equal(t, "http_2xx", result.Module)
		assert.NotZero(t, result.Duration)
		assert.NotZero(t, result.Timestamp)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "test", result.Labels["env"])
	})

	t.Run("failed probe", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 0`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		target := integrations.BlackboxTarget{
			Name:   "failing-target",
			Target: "http://failing-service.local",
		}

		result, err := exporter.Probe(ctx, target)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("probe with target-specific module", func(t *testing.T) {
		var receivedModule string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedModule = r.URL.Query().Get("module")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 1`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx", // Default module
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Target with custom module
		target := integrations.BlackboxTarget{
			Name:   "tcp-target",
			Target: "tcp://database.local:5432",
			Module: "tcp_connect", // Override default module
		}

		result, err := exporter.Probe(ctx, target)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "tcp_connect", receivedModule)
		assert.Equal(t, "tcp_connect", result.Module)
	})

	t.Run("probe with basic auth", func(t *testing.T) {
		var authHeader string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 1`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Username: "testuser",
			Password: "testpass",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		target := integrations.BlackboxTarget{
			Name:   "auth-target",
			Target: "http://example.com",
		}

		_, err = exporter.Probe(ctx, target)
		require.NoError(t, err)
		assert.NotEmpty(t, authHeader)
		assert.Contains(t, authHeader, "Basic")
	})

	t.Run("probe with custom headers", func(t *testing.T) {
		var customHeader string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			customHeader = r.Header.Get("X-Custom-Header")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`probe_success 1`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Headers: map[string]string{
				"X-Custom-Header": "custom-value",
			},
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		target := integrations.BlackboxTarget{
			Name:   "header-target",
			Target: "http://example.com",
		}

		_, err = exporter.Probe(ctx, target)
		require.NoError(t, err)
		assert.Equal(t, "custom-value", customHeader)
	})

	t.Run("probe with server error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		target := integrations.BlackboxTarget{
			Name:   "error-target",
			Target: "http://example.com",
		}

		result, err := exporter.Probe(ctx, target)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, http.StatusInternalServerError, result.StatusCode)
	})

	t.Run("probe with connection timeout", func(t *testing.T) {
		// Create a server that closes immediately
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow response
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Timeout:  10 * time.Millisecond, // Very short timeout
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		target := integrations.BlackboxTarget{
			Name:   "timeout-target",
			Target: "http://example.com",
		}

		_, err = exporter.Probe(ctx, target)
		assert.Error(t, err)
	})
}

// TestBlackboxExporterHealth tests the Health method
func TestBlackboxExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("health check with disabled exporter", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled: false,
		}

		exporter := integrations.NewBlackboxExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("health check with healthy server", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/metrics", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
# HELP blackbox_exporter_build_info A metric with a constant '1' value
# TYPE blackbox_exporter_build_info gauge
blackbox_exporter_build_info{branch="HEAD",goversion="go1.21",revision="abc123",version="0.24.0"} 1
`))
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Message, "200")
		assert.NotZero(t, status.LastCheck)
		assert.NotZero(t, status.Latency)
		assert.NotNil(t, status.Details)
		assert.Equal(t, 1, status.Details["targets"])
		assert.Equal(t, "http_2xx", status.Details["module"])
	})

	t.Run("health check with unhealthy server", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "503")
	})

	t.Run("health check with basic auth", func(t *testing.T) {
		var authHeader string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Module:   "http_2xx",
			Username: "admin",
			Password: "secret",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.NotEmpty(t, authHeader)
		assert.Contains(t, authHeader, "Basic")
	})

	t.Run("health check with connection failure", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: "http://localhost:59999", // Non-existent port
			Module:   "http_2xx",
			Timeout:  100 * time.Millisecond,
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})
}

// TestBlackboxExporterClose tests the Close method
func TestBlackboxExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("close initialized exporter", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()

		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: mockServer.URL,
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)
		assert.True(t, exporter.IsInitialized())

		err = exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close uninitialized exporter", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: "http://localhost:9115",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		// Do not call Init

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close disabled exporter", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled: false,
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		_ = exporter.Init(ctx)

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})
}

// TestBlackboxExporterExportMetrics tests the ExportMetrics method
func TestBlackboxExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not supported", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: "http://localhost:9115",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

// TestBlackboxExporterExportTraces tests the ExportTraces method
func TestBlackboxExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export traces not supported", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: "http://localhost:9115",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		traces := []integrations.Trace{
			{TraceID: "trace-123", SpanID: "span-456"},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

// TestBlackboxExporterExportLogs tests the ExportLogs method
func TestBlackboxExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs not supported", func(t *testing.T) {
		config := integrations.BlackboxConfig{
			Enabled:  true,
			Endpoint: "http://localhost:9115",
			Targets: []integrations.BlackboxTarget{
				{Name: "test", Target: "http://example.com"},
			},
		}

		exporter := integrations.NewBlackboxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

// TestBlackboxProbeResultMarshalJSON tests the JSON marshaling of probe results
func TestBlackboxProbeResultMarshalJSON(t *testing.T) {
	t.Run("marshal probe result with all fields", func(t *testing.T) {
		result := integrations.BlackboxProbeResult{
			Target:        "http://example.com",
			Module:        "http_2xx",
			Success:       true,
			Duration:      123 * time.Millisecond,
			DNSLookup:     10 * time.Millisecond,
			TCPConnect:    20 * time.Millisecond,
			TLSHandshake:  30 * time.Millisecond,
			FirstByte:     50 * time.Millisecond,
			StatusCode:    200,
			ContentLength: 1024,
			Labels:        map[string]string{"env": "test"},
			Timestamp:     time.Now(),
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify the JSON contains expected fields
		var parsed map[string]interface{}
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "http://example.com", parsed["target"])
		assert.Equal(t, "http_2xx", parsed["module"])
		assert.Equal(t, true, parsed["success"])
		assert.Equal(t, float64(123), parsed["duration_ms"])
		assert.Equal(t, float64(10), parsed["dns_lookup_ms"])
		assert.Equal(t, float64(20), parsed["tcp_connect_ms"])
		assert.Equal(t, float64(30), parsed["tls_handshake_ms"])
		assert.Equal(t, float64(50), parsed["first_byte_ms"])
		assert.Equal(t, float64(200), parsed["status_code"])
	})

	t.Run("marshal probe result with minimal fields", func(t *testing.T) {
		result := integrations.BlackboxProbeResult{
			Target:    "http://example.com",
			Module:    "http_2xx",
			Success:   false,
			Timestamp: time.Now(),
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		var parsed map[string]interface{}
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "http://example.com", parsed["target"])
		assert.Equal(t, false, parsed["success"])
		assert.Equal(t, float64(0), parsed["duration_ms"])
	})
}

// TestBlackboxConfigDefaults tests the default configuration values
func TestBlackboxConfigDefaults(t *testing.T) {
	t.Run("default config values", func(t *testing.T) {
		config := integrations.BlackboxConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Endpoint)
		assert.Empty(t, config.Module)
		assert.Empty(t, config.Targets)
		assert.Zero(t, config.ScrapeInterval)
		assert.Zero(t, config.Timeout)
		assert.False(t, config.TLSEnabled)
		assert.False(t, config.TLSSkipVerify)
		assert.Empty(t, config.Username)
		assert.Empty(t, config.Password)
		assert.Nil(t, config.Headers)
		assert.Nil(t, config.Labels)
	})
}

// TestBlackboxTargetConfig tests target configuration
func TestBlackboxTargetConfig(t *testing.T) {
	t.Run("target with all fields", func(t *testing.T) {
		target := integrations.BlackboxTarget{
			Name:   "web-service",
			Target: "http://web.local:8080/health",
			Module: "http_2xx",
			Labels: map[string]string{
				"service": "web",
				"env":     "production",
			},
		}

		assert.Equal(t, "web-service", target.Name)
		assert.Equal(t, "http://web.local:8080/health", target.Target)
		assert.Equal(t, "http_2xx", target.Module)
		assert.Equal(t, "web", target.Labels["service"])
		assert.Equal(t, "production", target.Labels["env"])
	})

	t.Run("target with minimal fields", func(t *testing.T) {
		target := integrations.BlackboxTarget{
			Target: "http://example.com",
		}

		assert.Empty(t, target.Name)
		assert.Equal(t, "http://example.com", target.Target)
		assert.Empty(t, target.Module)
		assert.Nil(t, target.Labels)
	})
}

// Benchmark tests
func BenchmarkNewBlackboxExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.BlackboxConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9115",
		Module:   "http_2xx",
		Targets: []integrations.BlackboxTarget{
			{Name: "test", Target: "http://example.com"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewBlackboxExporter(config, logger)
	}
}

func BenchmarkBlackboxExporterProbe(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`probe_success 1`))
	}))
	defer mockServer.Close()

	config := integrations.BlackboxConfig{
		Enabled:  true,
		Endpoint: mockServer.URL,
		Module:   "http_2xx",
		Targets: []integrations.BlackboxTarget{
			{Name: "test", Target: "http://example.com"},
		},
	}

	exporter := integrations.NewBlackboxExporter(config, logger)
	_ = exporter.Init(ctx)

	target := integrations.BlackboxTarget{
		Name:   "bench-target",
		Target: "http://example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Probe(ctx, target)
	}
}

func BenchmarkBlackboxExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	config := integrations.BlackboxConfig{
		Enabled:  true,
		Endpoint: mockServer.URL,
		Module:   "http_2xx",
		Targets: []integrations.BlackboxTarget{
			{Name: "test", Target: "http://example.com"},
		},
	}

	exporter := integrations.NewBlackboxExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}
