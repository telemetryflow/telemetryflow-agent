// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
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

func TestNewProxmoxExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.ProxmoxConfig{
		Enabled:  true,
		APIUrl:   "https://proxmox.local:8006",
		Username: "root@pam",
		Password: "password",
	}

	exporter := integrations.NewProxmoxExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "proxmox", exporter.Name())
	assert.Equal(t, "infrastructure", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestProxmoxExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("valid config with mock server", func(t *testing.T) {
		// Create mock Proxmox API server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api2/json/access/ticket" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
		}
		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("disabled config", func(t *testing.T) {
		config := integrations.ProxmoxConfig{
			Enabled: false,
		}
		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("missing api url", func(t *testing.T) {
		config := integrations.ProxmoxConfig{
			Enabled:  true,
			Username: "root@pam",
			Password: "password",
		}
		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})

	t.Run("missing credentials", func(t *testing.T) {
		config := integrations.ProxmoxConfig{
			Enabled: true,
			APIUrl:  "https://proxmox.local:8006",
		}
		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})
}

func TestProxmoxExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.ProxmoxConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.ProxmoxConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing api url",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				Username: "root@pam",
				Password: "password",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewProxmoxExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProxmoxExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock API responses
	nodesResp := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"node":    "pve1",
				"status":  "online",
				"cpu":     0.15,
				"maxcpu":  8,
				"mem":     8589934592,
				"maxmem":  17179869184,
				"disk":    10737418240,
				"maxdisk": 107374182400,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Handle authentication
		if r.URL.Path == "/api2/json/access/ticket" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"ticket":              "PVE:root@pam:test-ticket",
					"CSRFPreventionToken": "test-csrf-token",
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(nodesResp)
	}))
	defer server.Close()

	config := integrations.ProxmoxConfig{
		Enabled:    true,
		APIUrl:     server.URL,
		Username:   "root@pam",
		Password:   "password",
		CollectVMs: true,
	}

	exporter := integrations.NewProxmoxExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	if err == nil {
		assert.NotEmpty(t, metrics)
	}
}

func TestProxmoxExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.ProxmoxConfig{Enabled: false}
		exporter := integrations.NewProxmoxExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("successful health check - HTTP 200", func(t *testing.T) {
		// Create mock server that returns successful responses
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:health-test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			// Node status endpoint for health check
			if r.URL.Path == "/api2/json/nodes/pve-health/status" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"uptime": 86400,
						"cpu":    0.25,
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-health",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "Proxmox connected", status.Message)
		assert.NotZero(t, status.Latency)
		assert.NotNil(t, status.Details)
		assert.Equal(t, server.URL, status.Details["api_url"])
		assert.Equal(t, "pve-health", status.Details["node"])
	})

	t.Run("failed health check - HTTP 500", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				requestCount++
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			// Return 500 for health check endpoint
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-error",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
		assert.NotZero(t, status.Latency)
	})

	t.Run("failed health check - HTTP 503 Service Unavailable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			// Return 503 for health check endpoint
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Service Unavailable"})
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-unavailable",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("authentication failure - HTTP 401", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Auth endpoint returns unauthorized
			if r.URL.Path == "/api2/json/access/ticket" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "invalid",
			Password: "wrongpassword",
			Node:     "pve-auth-fail",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		// Init should fail with auth error
		assert.Error(t, err)
	})

	t.Run("authentication failure during health check - token expired", func(t *testing.T) {
		authCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				authCallCount++
				if authCallCount == 1 {
					// First auth succeeds
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]string{
							"ticket":              "PVE:root@pam:expired-ticket",
							"CSRFPreventionToken": "test-csrf-token",
						},
					})
					return
				}
				// Subsequent auth fails
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Health check returns 401 (expired token)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "token expired"})
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-token-expired",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("connection timeout", func(t *testing.T) {
		// Create server that delays response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			// Simulate timeout by sleeping
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-timeout",
			Timeout:  50000000, // 50ms - shorter than sleep
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Use context with very short timeout
		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()

		status, err := exporter.Health(shortCtx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
	})

	t.Run("network error - server closed", func(t *testing.T) {
		// Create server, get URL, then close it
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		serverURL := server.URL
		// Don't close yet - we need to init first

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   serverURL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-network-error",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Now close the server to simulate network error
		server.Close()

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("health check with valid response contains latency", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			// Add small delay to ensure latency is measurable
			time.Sleep(5 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-latency",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(5))
		assert.NotZero(t, status.LastCheck)
	})

	t.Run("health check with HTTP 403 Forbidden", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden - insufficient permissions"})
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-forbidden",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("health check with malformed JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api2/json/access/ticket" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]string{
						"ticket":              "PVE:root@pam:test-ticket",
						"CSRFPreventionToken": "test-csrf-token",
					},
				})
				return
			}
			// Return malformed JSON
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{invalid json"))
		}))
		defer server.Close()

		config := integrations.ProxmoxConfig{
			Enabled:  true,
			APIUrl:   server.URL,
			Username: "root@pam",
			Password: "password",
			Node:     "pve-malformed",
		}

		exporter := integrations.NewProxmoxExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Health check should still succeed as we only check connectivity
		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		// The result depends on whether the health check parses JSON
		// Based on the implementation, it just checks for successful HTTP response
		assert.True(t, status.Healthy)
	})
}

func TestProxmoxExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api2/json/access/ticket" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"ticket":              "PVE:root@pam:test-ticket",
					"CSRFPreventionToken": "test-csrf-token",
				},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ProxmoxConfig{
		Enabled:  true,
		APIUrl:   server.URL,
		Username: "root@pam",
		Password: "password",
	}

	exporter := integrations.NewProxmoxExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func BenchmarkNewProxmoxExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.ProxmoxConfig{
		Enabled:  true,
		APIUrl:   "https://proxmox.local:8006",
		Username: "root@pam",
		Password: "password",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewProxmoxExporter(config, logger)
	}
}

func TestProxmoxExporterCollectMetricsWithMock(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock API responses for comprehensive metrics collection
	authResponse := map[string]interface{}{
		"data": map[string]string{
			"ticket":              "PVE:root@pam:test-ticket-12345",
			"CSRFPreventionToken": "test-csrf-token-67890",
		},
	}

	nodeStatusResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"uptime": 86400,
			"cpu":    0.25,
			"memory": map[string]interface{}{
				"used":  8589934592,
				"free":  8589934592,
				"total": 17179869184,
			},
			"rootfs": map[string]interface{}{
				"used":  53687091200,
				"avail": 53687091200,
				"total": 107374182400,
			},
			"swap": map[string]interface{}{
				"used":  1073741824,
				"free":  3221225472,
				"total": 4294967296,
			},
			"loadavg":  []float64{1.5, 1.2, 0.9},
			"kversion": "5.15.0-generic",
		},
	}

	qemuVMsResponse := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"vmid":      100,
				"name":      "test-vm-1",
				"status":    "running",
				"cpu":       0.15,
				"mem":       2147483648,
				"maxmem":    4294967296,
				"disk":      10737418240,
				"maxdisk":   53687091200,
				"uptime":    3600,
				"netin":     1073741824,
				"netout":    536870912,
				"diskread":  2147483648,
				"diskwrite": 1073741824,
			},
			{
				"vmid":      101,
				"name":      "test-vm-2",
				"status":    "stopped",
				"cpu":       0.0,
				"mem":       0,
				"maxmem":    8589934592,
				"disk":      0,
				"maxdisk":   107374182400,
				"uptime":    0,
				"netin":     0,
				"netout":    0,
				"diskread":  0,
				"diskwrite": 0,
			},
		},
	}

	lxcContainersResponse := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"vmid":    200,
				"name":    "test-container-1",
				"status":  "running",
				"cpu":     0.05,
				"mem":     536870912,
				"maxmem":  1073741824,
				"disk":    5368709120,
				"maxdisk": 21474836480,
				"uptime":  7200,
				"netin":   268435456,
				"netout":  134217728,
			},
		},
	}

	storageResponse := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"storage": "local",
				"type":    "dir",
				"used":    53687091200,
				"avail":   53687091200,
				"total":   107374182400,
				"active":  1,
			},
			{
				"storage": "local-lvm",
				"type":    "lvmthin",
				"used":    107374182400,
				"avail":   322122547200,
				"total":   429496729600,
				"active":  1,
			},
		},
	}

	// Create mock Proxmox API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api2/json/access/ticket":
			_ = json.NewEncoder(w).Encode(authResponse)
		case "/api2/json/nodes/pve1/status":
			_ = json.NewEncoder(w).Encode(nodeStatusResponse)
		case "/api2/json/nodes/pve1/qemu":
			_ = json.NewEncoder(w).Encode(qemuVMsResponse)
		case "/api2/json/nodes/pve1/lxc":
			_ = json.NewEncoder(w).Encode(lxcContainersResponse)
		case "/api2/json/nodes/pve1/storage":
			_ = json.NewEncoder(w).Encode(storageResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.ProxmoxConfig{
		Enabled:           true,
		APIUrl:            server.URL,
		Username:          "root@pam",
		Password:          "password",
		Node:              "pve1",
		CollectVMs:        true,
		CollectContainers: true,
		CollectStorage:    true,
	}

	exporter := integrations.NewProxmoxExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "CollectMetrics should return metrics")

	// Verify node metrics are present
	nodeMetricNames := []string{
		"proxmox_node_uptime_seconds",
		"proxmox_node_cpu_usage",
		"proxmox_node_memory_used_bytes",
		"proxmox_node_memory_total_bytes",
		"proxmox_node_memory_free_bytes",
		"proxmox_node_swap_used_bytes",
		"proxmox_node_swap_total_bytes",
		"proxmox_node_rootfs_used_bytes",
		"proxmox_node_rootfs_total_bytes",
		"proxmox_node_load1",
		"proxmox_node_load5",
		"proxmox_node_load15",
	}

	metricsMap := make(map[string]bool)
	for _, m := range metrics {
		metricsMap[m.Name] = true
	}

	for _, name := range nodeMetricNames {
		assert.True(t, metricsMap[name], "Expected metric %s to be present", name)
	}

	// Verify VM metrics are present
	vmMetricNames := []string{
		"proxmox_vm_running",
		"proxmox_vm_cpu_usage",
		"proxmox_vm_memory_used_bytes",
		"proxmox_vm_memory_max_bytes",
		"proxmox_vm_uptime_seconds",
	}

	for _, name := range vmMetricNames {
		assert.True(t, metricsMap[name], "Expected VM metric %s to be present", name)
	}

	// Verify container metrics are present
	containerMetricNames := []string{
		"proxmox_container_running",
		"proxmox_container_cpu_usage",
		"proxmox_container_memory_used_bytes",
	}

	for _, name := range containerMetricNames {
		assert.True(t, metricsMap[name], "Expected container metric %s to be present", name)
	}

	// Verify storage metrics are present
	storageMetricNames := []string{
		"proxmox_storage_active",
		"proxmox_storage_used_bytes",
		"proxmox_storage_available_bytes",
		"proxmox_storage_total_bytes",
	}

	for _, name := range storageMetricNames {
		assert.True(t, metricsMap[name], "Expected storage metric %s to be present", name)
	}

	// Verify metric values for specific metrics
	for _, m := range metrics {
		if m.Name == "proxmox_node_uptime_seconds" {
			assert.Equal(t, float64(86400), m.Value)
			assert.Equal(t, "pve1", m.Tags["node"])
		}
		if m.Name == "proxmox_node_cpu_usage" {
			assert.Equal(t, 0.25, m.Value)
		}
	}
}

func TestProxmoxExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock API responses
	authResponse := map[string]interface{}{
		"data": map[string]string{
			"ticket":              "PVE:root@pam:test-ticket",
			"CSRFPreventionToken": "test-csrf-token",
		},
	}

	nodeStatusResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"uptime": 43200,
			"cpu":    0.10,
			"memory": map[string]interface{}{
				"used":  4294967296,
				"free":  12884901888,
				"total": 17179869184,
			},
			"rootfs": map[string]interface{}{
				"used":  26843545600,
				"avail": 80530636800,
				"total": 107374182400,
			},
			"swap": map[string]interface{}{
				"used":  0,
				"free":  4294967296,
				"total": 4294967296,
			},
			"loadavg": []float64{0.5, 0.4, 0.3},
		},
	}

	qemuVMsResponse := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"vmid":   100,
				"name":   "export-test-vm",
				"status": "running",
				"cpu":    0.20,
				"mem":    1073741824,
				"maxmem": 2147483648,
			},
		},
	}

	lxcResponse := map[string]interface{}{"data": []map[string]interface{}{}}
	storageResponse := map[string]interface{}{"data": []map[string]interface{}{}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api2/json/access/ticket":
			_ = json.NewEncoder(w).Encode(authResponse)
		case "/api2/json/nodes/pve-export/status":
			_ = json.NewEncoder(w).Encode(nodeStatusResponse)
		case "/api2/json/nodes/pve-export/qemu":
			_ = json.NewEncoder(w).Encode(qemuVMsResponse)
		case "/api2/json/nodes/pve-export/lxc":
			_ = json.NewEncoder(w).Encode(lxcResponse)
		case "/api2/json/nodes/pve-export/storage":
			_ = json.NewEncoder(w).Encode(storageResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.ProxmoxConfig{
		Enabled:           true,
		APIUrl:            server.URL,
		Username:          "root@pam",
		Password:          "password",
		Node:              "pve-export",
		CollectVMs:        true,
		CollectContainers: true,
		CollectStorage:    true,
	}

	exporter := integrations.NewProxmoxExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Test Export method
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Greater(t, result.ItemsExported, 0)
	assert.NotEmpty(t, telemetryData.Metrics, "TelemetryData should contain metrics after Export")

	// Verify the telemetry data was populated
	assert.Greater(t, len(telemetryData.Metrics), 0, "Export should populate metrics in TelemetryData")

	// Test Export when disabled
	disabledConfig := integrations.ProxmoxConfig{Enabled: false}
	disabledExporter := integrations.NewProxmoxExporter(disabledConfig, logger)
	result, err = disabledExporter.Export(ctx, telemetryData)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestProxmoxExporterCollectMetricsAPIError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that returns errors for data endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api2/json/access/ticket" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"ticket":              "test-ticket",
					"CSRFPreventionToken": "test-csrf",
				},
			})
			return
		}
		// Return 500 error for all other endpoints
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
	}))
	defer server.Close()

	config := integrations.ProxmoxConfig{
		Enabled:           true,
		APIUrl:            server.URL,
		Username:          "root@pam",
		Password:          "password",
		Node:              "pve-error",
		CollectVMs:        true,
		CollectContainers: true,
		CollectStorage:    true,
	}

	exporter := integrations.NewProxmoxExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// CollectMetrics should not return an error but may return empty metrics
	metrics, err := exporter.CollectMetrics(ctx)
	// The implementation logs warnings but doesn't return errors for individual collection failures
	assert.NoError(t, err)
	assert.Empty(t, metrics, "Should return empty metrics when API returns errors")
}

// TestProxmoxExporterExportMetrics tests the ExportMetrics function
// Proxmox is a data source, not a metrics destination, so ExportMetrics should return an error
func TestProxmoxExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name    string
		config  integrations.ProxmoxConfig
		metrics []integrations.Metric
	}{
		{
			name: "export metrics returns error - proxmox is a data source",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			metrics: []integrations.Metric{
				{
					Name:  "test_metric",
					Value: 42.0,
					Type:  integrations.MetricTypeGauge,
					Tags:  map[string]string{"test": "true"},
				},
			},
		},
		{
			name: "export metrics with empty slice returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			metrics: []integrations.Metric{},
		},
		{
			name: "export metrics with nil slice returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			metrics: nil,
		},
		{
			name: "export metrics with multiple metrics returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			metrics: []integrations.Metric{
				{Name: "metric1", Value: 1.0, Type: integrations.MetricTypeGauge},
				{Name: "metric2", Value: 2.0, Type: integrations.MetricTypeCounter},
				{Name: "metric3", Value: 3.0, Type: integrations.MetricTypeHistogram},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewProxmoxExporter(tt.config, logger)

			result, err := exporter.ExportMetrics(ctx, tt.metrics)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "proxmox is a data source, not a metrics destination")
		})
	}
}

// TestProxmoxExporterExportTraces tests the ExportTraces function
// Proxmox does not support traces, so ExportTraces should return an error
func TestProxmoxExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.ProxmoxConfig
		traces []integrations.Trace
	}{
		{
			name: "export traces returns error - proxmox does not support traces",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			traces: []integrations.Trace{
				{
					TraceID:       "trace-123",
					SpanID:        "span-456",
					OperationName: "test-trace",
				},
			},
		},
		{
			name: "export traces with empty slice returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			traces: []integrations.Trace{},
		},
		{
			name: "export traces with nil slice returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			traces: nil,
		},
		{
			name: "export traces with multiple traces returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			traces: []integrations.Trace{
				{TraceID: "trace-1", SpanID: "span-1", OperationName: "trace1"},
				{TraceID: "trace-2", SpanID: "span-2", OperationName: "trace2"},
				{TraceID: "trace-3", SpanID: "span-3", OperationName: "trace3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewProxmoxExporter(tt.config, logger)

			result, err := exporter.ExportTraces(ctx, tt.traces)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "proxmox does not support traces")
		})
	}
}

// TestProxmoxExporterExportLogs tests the ExportLogs function
// Proxmox does not support log ingestion, so ExportLogs should return an error
func TestProxmoxExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.ProxmoxConfig
		logs   []integrations.LogEntry
	}{
		{
			name: "export logs returns error - proxmox does not support log ingestion",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			logs: []integrations.LogEntry{
				{
					Message:    "test log message",
					Level:      integrations.LogLevelInfo,
					Attributes: map[string]string{"service": "test"},
				},
			},
		},
		{
			name: "export logs with empty slice returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			logs: []integrations.LogEntry{},
		},
		{
			name: "export logs with nil slice returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			logs: nil,
		},
		{
			name: "export logs with multiple logs returns error",
			config: integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			logs: []integrations.LogEntry{
				{Message: "log1", Level: "info"},
				{Message: "log2", Level: "warn"},
				{Message: "log3", Level: "error"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewProxmoxExporter(tt.config, logger)

			result, err := exporter.ExportLogs(ctx, tt.logs)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "proxmox does not support log ingestion")
		})
	}
}
