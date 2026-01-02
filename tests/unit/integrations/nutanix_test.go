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

func TestNewNutanixExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.NutanixConfig{
		Enabled:         true,
		PrismCentralURL: "https://nutanix.local:9440",
		Username:        "admin",
		Password:        "password",
	}

	exporter := integrations.NewNutanixExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "nutanix", exporter.Name())
	assert.Equal(t, "infrastructure", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestNutanixExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.NutanixConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://nutanix.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.NutanixConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing prism url",
			config: integrations.NutanixConfig{
				Enabled:  true,
				Username: "admin",
				Password: "password",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewNutanixExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNutanixExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.NutanixConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://nutanix.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.NutanixConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing username",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://nutanix.local:9440",
				Password:        "password",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewNutanixExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNutanixExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.NutanixConfig{Enabled: false}
		exporter := integrations.NewNutanixExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("successful health check - HTTP 200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Verify basic auth
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Health check calls /clusters
			if r.URL.Path == "/api/nutanix/v2.0/clusters" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"entities": []map[string]interface{}{
						{"uuid": "cluster-001", "name": "Test-Cluster", "is_available": true},
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
			APIVersion:      "v2.0",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "Nutanix connected", status.Message)
		assert.NotZero(t, status.Latency)
		assert.NotNil(t, status.Details)
		assert.Equal(t, server.URL, status.Details["prism_central_url"])
	})

	t.Run("failed health check - HTTP 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("failed health check - HTTP 503 Service Unavailable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Prism Central unavailable"})
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("authentication failure - HTTP 401", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "invalid",
			Password:        "wrongpassword",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("connection timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Simulate timeout
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()

		status, err := exporter.Health(shortCtx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
	})

	t.Run("network error - server closed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"entities": []map[string]interface{}{}})
		}))
		serverURL := server.URL

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: serverURL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Close server to simulate network error
		server.Close()

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("health check with latency measurement", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Add delay for latency measurement
			time.Sleep(5 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"entities": []map[string]interface{}{}})
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
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
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden - insufficient permissions"})
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("health check with empty cluster list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Empty list is valid
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"entities": []map[string]interface{}{}})
		}))
		defer server.Close()

		config := integrations.NutanixConfig{
			Enabled:         true,
			PrismCentralURL: server.URL,
			Username:        "admin",
			Password:        "password",
		}

		exporter := integrations.NewNutanixExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "Nutanix connected", status.Message)
	})
}

func TestNutanixExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NutanixConfig{
		Enabled:         true,
		PrismCentralURL: "https://nutanix.local:9440",
		Username:        "admin",
		Password:        "password",
	}

	exporter := integrations.NewNutanixExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func BenchmarkNewNutanixExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.NutanixConfig{
		Enabled:         true,
		PrismCentralURL: "https://nutanix.local:9440",
		Username:        "admin",
		Password:        "password",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewNutanixExporter(config, logger)
	}
}

func TestNutanixExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock Nutanix Prism API responses
	clustersResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                   "cluster-uuid-001",
				"name":                   "Nutanix-Cluster-1",
				"cluster_external_ip":    "10.0.0.100",
				"num_nodes":              4,
				"version":                "6.5.1",
				"hypervisor_types":       []string{"kKvm"},
				"is_available":           true,
				"encryption_status":      "ENABLED",
				"storage_capacity_bytes": 10995116277760,
				"storage_usage_bytes":    4398046511104,
			},
		},
	}

	clusterStatsResponse := map[string]interface{}{
		"cpu_capacity_hz":                 80000000000,
		"hypervisor_cpu_usage_ppm":        250000,
		"memory_capacity_bytes":           274877906944,
		"hypervisor_memory_usage_ppm":     450000,
		"storage_capacity_bytes":          10995116277760,
		"storage_usage_bytes":             4398046511104,
		"controller_io_bandwidth_kbps":    512000,
		"controller_num_iops":             15000,
		"controller_avg_io_latency_usecs": 500,
		"num_vms":                         25,
	}

	hostsResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                     "host-uuid-001",
				"name":                     "nutanix-host-1",
				"cluster_uuid":             "cluster-uuid-001",
				"hypervisor_type":          "kKvm",
				"num_cpu_cores":            16,
				"num_cpu_sockets":          2,
				"cpu_frequency_hz":         2500000000,
				"memory_capacity_in_bytes": 68719476736,
				"state":                    "NORMAL",
				"ipmi_address":             "10.0.0.10",
				"hypervisor_address":       "10.0.0.11",
			},
			{
				"uuid":                     "host-uuid-002",
				"name":                     "nutanix-host-2",
				"cluster_uuid":             "cluster-uuid-001",
				"hypervisor_type":          "kKvm",
				"num_cpu_cores":            16,
				"num_cpu_sockets":          2,
				"cpu_frequency_hz":         2500000000,
				"memory_capacity_in_bytes": 68719476736,
				"state":                    "NORMAL",
			},
		},
	}

	hostStatsResponse := map[string]interface{}{
		"hypervisor_cpu_usage_ppm":        200000,
		"hypervisor_memory_usage_ppm":     350000,
		"num_vms":                         10,
		"controller_io_bandwidth_kbps":    128000,
		"controller_num_iops":             5000,
		"controller_avg_io_latency_usecs": 400,
		"content_cache_hit_ppm":           850000,
	}

	vmsResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                "vm-uuid-001",
				"name":                "nutanix-vm-1",
				"power_state":         "on",
				"num_vcpus":           4,
				"memory_mb":           8192,
				"disk_capacity_bytes": 107374182400,
				"host_uuid":           "host-uuid-001",
				"cluster_uuid":        "cluster-uuid-001",
				"hypervisor_type":     "kKvm",
				"ip_addresses":        []string{"10.0.1.10"},
			},
			{
				"uuid":                "vm-uuid-002",
				"name":                "nutanix-vm-2",
				"power_state":         "off",
				"num_vcpus":           2,
				"memory_mb":           4096,
				"disk_capacity_bytes": 53687091200,
				"host_uuid":           "host-uuid-002",
				"cluster_uuid":        "cluster-uuid-001",
				"hypervisor_type":     "kKvm",
			},
		},
	}

	vmStatsResponse := map[string]interface{}{
		"hypervisor_cpu_usage_ppm":           150000,
		"hypervisor_memory_usage_ppm":        300000,
		"controller_io_bandwidth_kbps":       64000,
		"controller_num_iops":                2000,
		"controller_avg_io_latency_usecs":    300,
		"controller_read_io_bandwidth_kbps":  32000,
		"controller_write_io_bandwidth_kbps": 32000,
	}

	storageContainersResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                "container-uuid-001",
				"name":                "default-container",
				"cluster_uuid":        "cluster-uuid-001",
				"storage_pool_uuid":   "pool-uuid-001",
				"replication_factor":  2,
				"compression_enabled": true,
				"max_capacity_bytes":  5497558138880,
				"usage_bytes":         2199023255552,
			},
		},
	}

	alertsResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                        "alert-uuid-001",
				"alert_title":                 "High CPU Usage",
				"severity":                    "kWarning",
				"created_time_stamp_in_usecs": 1704067200000000,
				"resolved":                    false,
				"entity_type":                 "vm",
				"entity_uuid":                 "vm-uuid-001",
			},
			{
				"uuid":                        "alert-uuid-002",
				"alert_title":                 "Storage Almost Full",
				"severity":                    "kCritical",
				"created_time_stamp_in_usecs": 1704153600000000,
				"resolved":                    false,
				"entity_type":                 "storage_container",
				"entity_uuid":                 "container-uuid-001",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Verify basic auth is present
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/api/nutanix/v2.0/clusters":
			_ = json.NewEncoder(w).Encode(clustersResponse)
		case "/api/nutanix/v2.0/clusters/cluster-uuid-001/stats":
			_ = json.NewEncoder(w).Encode(clusterStatsResponse)
		case "/api/nutanix/v2.0/hosts":
			_ = json.NewEncoder(w).Encode(hostsResponse)
		case "/api/nutanix/v2.0/hosts/host-uuid-001/stats", "/api/nutanix/v2.0/hosts/host-uuid-002/stats":
			_ = json.NewEncoder(w).Encode(hostStatsResponse)
		case "/api/nutanix/v2.0/vms":
			_ = json.NewEncoder(w).Encode(vmsResponse)
		case "/api/nutanix/v2.0/vms/vm-uuid-001/stats":
			_ = json.NewEncoder(w).Encode(vmStatsResponse)
		case "/api/nutanix/v2.0/storage_containers":
			_ = json.NewEncoder(w).Encode(storageContainersResponse)
		case "/api/nutanix/v2.0/alerts":
			_ = json.NewEncoder(w).Encode(alertsResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.NutanixConfig{
		Enabled:         true,
		PrismCentralURL: server.URL,
		Username:        "admin",
		Password:        "password",
		CollectVMs:      true,
		CollectHosts:    true,
		CollectClusters: true,
		CollectStorage:  true,
		CollectAlerts:   true,
	}

	exporter := integrations.NewNutanixExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "CollectMetrics should return metrics")

	// Build metrics map for verification
	metricsMap := make(map[string]bool)
	for _, m := range metrics {
		metricsMap[m.Name] = true
	}

	// Verify cluster metrics
	clusterMetricNames := []string{
		"nutanix_cluster_available",
		"nutanix_cluster_nodes",
		"nutanix_cluster_storage_capacity_bytes",
		"nutanix_cluster_storage_usage_bytes",
		"nutanix_cluster_cpu_usage_percent",
		"nutanix_cluster_memory_usage_percent",
		"nutanix_cluster_io_bandwidth_kbps",
		"nutanix_cluster_iops",
		"nutanix_cluster_io_latency_ms",
		"nutanix_cluster_vms",
	}

	for _, name := range clusterMetricNames {
		assert.True(t, metricsMap[name], "Expected cluster metric %s to be present", name)
	}

	// Verify host metrics
	hostMetricNames := []string{
		"nutanix_host_healthy",
		"nutanix_host_cpu_cores",
		"nutanix_host_cpu_sockets",
		"nutanix_host_memory_capacity_bytes",
		"nutanix_host_cpu_usage_percent",
		"nutanix_host_memory_usage_percent",
		"nutanix_host_vms",
		"nutanix_host_iops",
	}

	for _, name := range hostMetricNames {
		assert.True(t, metricsMap[name], "Expected host metric %s to be present", name)
	}

	// Verify VM metrics
	vmMetricNames := []string{
		"nutanix_vm_power_state",
		"nutanix_vm_vcpus",
		"nutanix_vm_memory_mb",
		"nutanix_vm_disk_capacity_bytes",
		"nutanix_vm_cpu_usage_percent",
		"nutanix_vm_memory_usage_percent",
		"nutanix_vm_iops",
	}

	for _, name := range vmMetricNames {
		assert.True(t, metricsMap[name], "Expected VM metric %s to be present", name)
	}

	// Verify storage metrics
	storageMetricNames := []string{
		"nutanix_storage_container_capacity_bytes",
		"nutanix_storage_container_usage_bytes",
		"nutanix_storage_container_usage_percent",
		"nutanix_storage_container_replication_factor",
		"nutanix_storage_container_compression_enabled",
	}

	for _, name := range storageMetricNames {
		assert.True(t, metricsMap[name], "Expected storage metric %s to be present", name)
	}

	// Verify alert metrics
	alertMetricNames := []string{
		"nutanix_alerts_active",
		"nutanix_alerts_active_total",
	}

	for _, name := range alertMetricNames {
		assert.True(t, metricsMap[name], "Expected alert metric %s to be present", name)
	}

	// Verify specific metric values and tags
	for _, m := range metrics {
		if m.Name == "nutanix_cluster_available" && m.Tags["cluster_name"] == "Nutanix-Cluster-1" {
			assert.Equal(t, 1.0, m.Value, "Available cluster should have value = 1")
		}
		if m.Name == "nutanix_cluster_nodes" && m.Tags["cluster_name"] == "Nutanix-Cluster-1" {
			assert.Equal(t, float64(4), m.Value)
		}
		if m.Name == "nutanix_vm_power_state" && m.Tags["vm_name"] == "nutanix-vm-1" {
			assert.Equal(t, 1.0, m.Value, "Powered on VM should have power_state = 1")
		}
		if m.Name == "nutanix_vm_power_state" && m.Tags["vm_name"] == "nutanix-vm-2" {
			assert.Equal(t, 0.0, m.Value, "Powered off VM should have power_state = 0")
		}
		if m.Name == "nutanix_alerts_active_total" {
			assert.Equal(t, float64(2), m.Value)
		}
	}
}

func TestNutanixExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Simplified mock responses for Export test
	clustersResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                   "export-cluster-001",
				"name":                   "Export-Test-Cluster",
				"num_nodes":              2,
				"version":                "6.5.2",
				"is_available":           true,
				"storage_capacity_bytes": 5497558138880,
				"storage_usage_bytes":    1099511627776,
			},
		},
	}

	clusterStatsResponse := map[string]interface{}{
		"hypervisor_cpu_usage_ppm":        150000,
		"hypervisor_memory_usage_ppm":     300000,
		"controller_io_bandwidth_kbps":    256000,
		"controller_num_iops":             8000,
		"controller_avg_io_latency_usecs": 400,
		"num_vms":                         10,
	}

	hostsResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":                     "export-host-001",
				"name":                     "export-host-1",
				"cluster_uuid":             "export-cluster-001",
				"num_cpu_cores":            8,
				"num_cpu_sockets":          1,
				"memory_capacity_in_bytes": 34359738368,
				"state":                    "NORMAL",
			},
		},
	}

	hostStatsResponse := map[string]interface{}{
		"hypervisor_cpu_usage_ppm":    100000,
		"hypervisor_memory_usage_ppm": 200000,
		"num_vms":                     5,
		"controller_num_iops":         2500,
	}

	vmsResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":        "export-vm-001",
				"name":        "export-vm-1",
				"power_state": "on",
				"num_vcpus":   2,
				"memory_mb":   2048,
			},
		},
	}

	vmStatsResponse := map[string]interface{}{
		"hypervisor_cpu_usage_ppm":    100000,
		"hypervisor_memory_usage_ppm": 200000,
		"controller_num_iops":         1000,
	}

	storageResponse := map[string]interface{}{
		"entities": []map[string]interface{}{
			{
				"uuid":               "export-container-001",
				"name":               "export-container",
				"replication_factor": 2,
				"max_capacity_bytes": 2748779069440,
				"usage_bytes":        549755813888,
			},
		},
	}

	alertsResponse := map[string]interface{}{
		"entities": []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/api/nutanix/v2.0/clusters":
			_ = json.NewEncoder(w).Encode(clustersResponse)
		case "/api/nutanix/v2.0/clusters/export-cluster-001/stats":
			_ = json.NewEncoder(w).Encode(clusterStatsResponse)
		case "/api/nutanix/v2.0/hosts":
			_ = json.NewEncoder(w).Encode(hostsResponse)
		case "/api/nutanix/v2.0/hosts/export-host-001/stats":
			_ = json.NewEncoder(w).Encode(hostStatsResponse)
		case "/api/nutanix/v2.0/vms":
			_ = json.NewEncoder(w).Encode(vmsResponse)
		case "/api/nutanix/v2.0/vms/export-vm-001/stats":
			_ = json.NewEncoder(w).Encode(vmStatsResponse)
		case "/api/nutanix/v2.0/storage_containers":
			_ = json.NewEncoder(w).Encode(storageResponse)
		case "/api/nutanix/v2.0/alerts":
			_ = json.NewEncoder(w).Encode(alertsResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.NutanixConfig{
		Enabled:         true,
		PrismCentralURL: server.URL,
		Username:        "admin",
		Password:        "password",
		CollectVMs:      true,
		CollectHosts:    true,
		CollectClusters: true,
		CollectStorage:  true,
		CollectAlerts:   true,
	}

	exporter := integrations.NewNutanixExporter(config, logger)
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

	// Verify metrics count
	assert.Greater(t, len(telemetryData.Metrics), 10, "Export should populate multiple metrics")

	// Test Export when disabled
	disabledConfig := integrations.NutanixConfig{Enabled: false}
	disabledExporter := integrations.NewNutanixExporter(disabledConfig, logger)
	result, err = disabledExporter.Export(ctx, telemetryData)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Additional edge case tests for error handling

func TestNutanixExporterCollectMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NutanixConfig{
		Enabled:         true,
		PrismCentralURL: "https://prism.local:9440",
		Username:        "admin",
		Password:        "password",
	}

	exporter := integrations.NewNutanixExporter(config, logger)
	// Do not call Init

	metrics, err := exporter.CollectMetrics(ctx)
	assert.Error(t, err)
	assert.Nil(t, metrics)
}

// TestNutanixExporterExportMetrics tests the ExportMetrics function
// Nutanix is a data source, not a metrics destination, so ExportMetrics should return an error
func TestNutanixExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name    string
		config  integrations.NutanixConfig
		metrics []integrations.Metric
	}{
		{
			name: "export metrics returns error - nutanix is a data source",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
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
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			metrics: []integrations.Metric{},
		},
		{
			name: "export metrics with nil slice returns error",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			metrics: nil,
		},
		{
			name: "export metrics with multiple metrics returns error",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
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
			exporter := integrations.NewNutanixExporter(tt.config, logger)

			result, err := exporter.ExportMetrics(ctx, tt.metrics)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "nutanix is a data source, not a metrics destination")
		})
	}
}

// TestNutanixExporterExportTraces tests the ExportTraces function
// Nutanix does not support traces, so ExportTraces should return an error
func TestNutanixExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.NutanixConfig
		traces []integrations.Trace
	}{
		{
			name: "export traces returns error - nutanix does not support traces",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
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
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			traces: []integrations.Trace{},
		},
		{
			name: "export traces with nil slice returns error",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			traces: nil,
		},
		{
			name: "export traces with multiple traces returns error",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
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
			exporter := integrations.NewNutanixExporter(tt.config, logger)

			result, err := exporter.ExportTraces(ctx, tt.traces)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "nutanix does not support traces")
		})
	}
}

// TestNutanixExporterExportLogs tests the ExportLogs function
// Nutanix does not support log ingestion, so ExportLogs should return an error
func TestNutanixExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.NutanixConfig
		logs   []integrations.LogEntry
	}{
		{
			name: "export logs returns error - nutanix does not support log ingestion",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
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
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			logs: []integrations.LogEntry{},
		},
		{
			name: "export logs with nil slice returns error",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			logs: nil,
		},
		{
			name: "export logs with multiple logs returns error",
			config: integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://prism.local:9440",
				Username:        "admin",
				Password:        "password",
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
			exporter := integrations.NewNutanixExporter(tt.config, logger)

			result, err := exporter.ExportLogs(ctx, tt.logs)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "nutanix does not support log ingestion")
		})
	}
}
