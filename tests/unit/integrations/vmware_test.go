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

func TestNewVMwareExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.VMwareConfig{
		Enabled:    true,
		VCenterURL: "https://vcenter.local",
		Username:   "administrator@vsphere.local",
		Password:   "password",
	}

	exporter := integrations.NewVMwareExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "vmware", exporter.Name())
	assert.Equal(t, "infrastructure", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestVMwareExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("valid config with mock server", func(t *testing.T) {
		// Create mock vCenter API server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/session" {
				// vCenter 7.x API returns session ID as JSON string
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "administrator@vsphere.local",
			Password:   "password",
		}
		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("disabled config", func(t *testing.T) {
		config := integrations.VMwareConfig{
			Enabled: false,
		}
		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("missing vcenter url", func(t *testing.T) {
		config := integrations.VMwareConfig{
			Enabled:  true,
			Username: "admin",
			Password: "password",
		}
		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})

	t.Run("missing credentials", func(t *testing.T) {
		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: "https://vcenter.local",
		}
		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})
}

func TestVMwareExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.VMwareConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.VMwareConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing vcenter url",
			config: integrations.VMwareConfig{
				Enabled:  true,
				Username: "admin",
				Password: "password",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewVMwareExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVMwareExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.VMwareConfig{Enabled: false}
		exporter := integrations.NewVMwareExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("successful health check - HTTP 200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/api/session" && r.Method == "POST":
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("health-test-session-id")
			case r.URL.Path == "/api/session" && r.Method == "DELETE":
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/api/vcenter/vm":
				// Health check lists VMs
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"vm": "vm-001", "name": "test-vm", "power_state": "POWERED_ON"},
				})
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
			Datacenter: "DC1",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "VMware vSphere connected", status.Message)
		assert.NotZero(t, status.Latency)
		assert.NotNil(t, status.Details)
		assert.Equal(t, server.URL, status.Details["vcenter_url"])
		assert.Equal(t, "DC1", status.Details["datacenter"])
	})

	t.Run("failed health check - HTTP 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			// Return 500 for health check
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
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
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Service Unavailable"})
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
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

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "invalid",
			Password:   "wrongpassword",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		// Init should fail with auth error
		assert.Error(t, err)
	})

	t.Run("session expired during health check", func(t *testing.T) {
		sessionCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				sessionCallCount++
				if sessionCallCount == 1 {
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode("expired-session-id")
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Health check returns 401 (session expired)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "session expired"})
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
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
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			// Simulate timeout
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
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
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		serverURL := server.URL

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: serverURL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
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
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			// Add delay for latency measurement
			time.Sleep(5 * time.Millisecond)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
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
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden - insufficient privileges"})
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("health check with empty VM list response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/session" && r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode("test-session-id")
				return
			}
			if r.URL.Path == "/api/vcenter/vm" {
				// Empty list is valid
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.VMwareConfig{
			Enabled:    true,
			VCenterURL: server.URL,
			Username:   "admin@vsphere.local",
			Password:   "password",
		}

		exporter := integrations.NewVMwareExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "VMware vSphere connected", status.Message)
	})
}

func TestVMwareExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock vCenter API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/session" {
			if r.Method == "DELETE" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode("test-session-id")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.VMwareConfig{
		Enabled:    true,
		VCenterURL: server.URL,
		Username:   "admin",
		Password:   "password",
	}

	exporter := integrations.NewVMwareExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func BenchmarkNewVMwareExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.VMwareConfig{
		Enabled:    true,
		VCenterURL: "https://vcenter.local",
		Username:   "admin",
		Password:   "password",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewVMwareExporter(config, logger)
	}
}

func TestVMwareExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock vSphere API responses
	vmsResponse := []map[string]interface{}{
		{
			"vm":              "vm-100",
			"name":            "test-vm-vsphere-1",
			"power_state":     "POWERED_ON",
			"cpu_count":       4,
			"memory_size_MiB": 8192,
			"guest_OS":        "rhel8_64Guest",
		},
		{
			"vm":              "vm-101",
			"name":            "test-vm-vsphere-2",
			"power_state":     "POWERED_OFF",
			"cpu_count":       2,
			"memory_size_MiB": 4096,
			"guest_OS":        "windows2019srv_64Guest",
		},
		{
			"vm":              "vm-102",
			"name":            "test-vm-vsphere-3",
			"power_state":     "POWERED_ON",
			"cpu_count":       8,
			"memory_size_MiB": 16384,
			"guest_OS":        "ubuntu64Guest",
		},
	}

	hostsResponse := []map[string]interface{}{
		{
			"host":             "host-10",
			"name":             "esxi-host-1.local",
			"connection_state": "CONNECTED",
			"power_state":      "POWERED_ON",
		},
		{
			"host":             "host-11",
			"name":             "esxi-host-2.local",
			"connection_state": "CONNECTED",
			"power_state":      "POWERED_ON",
		},
	}

	datastoresResponse := []map[string]interface{}{
		{
			"datastore":  "datastore-100",
			"name":       "datastore1",
			"type":       "VMFS",
			"capacity":   1099511627776,
			"free_space": 549755813888,
		},
		{
			"datastore":  "datastore-101",
			"name":       "datastore-nfs",
			"type":       "NFS",
			"capacity":   2199023255552,
			"free_space": 1649267441664,
		},
	}

	clustersResponse := []map[string]interface{}{
		{
			"cluster":     "domain-c7",
			"name":        "Production-Cluster",
			"ha_enabled":  true,
			"drs_enabled": true,
		},
		{
			"cluster":     "domain-c8",
			"name":        "Dev-Cluster",
			"ha_enabled":  false,
			"drs_enabled": true,
		},
	}

	vmDetailsResponse := map[string]interface{}{
		"memory": map[string]interface{}{
			"size_MiB": 8192,
		},
		"cpu": map[string]interface{}{
			"count": 4,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/session" && r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode("test-vsphere-session-id")
		case r.URL.Path == "/api/session" && r.Method == "DELETE":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/vcenter/vm":
			_ = json.NewEncoder(w).Encode(vmsResponse)
		case r.URL.Path == "/api/vcenter/host":
			_ = json.NewEncoder(w).Encode(hostsResponse)
		case r.URL.Path == "/api/vcenter/datastore":
			_ = json.NewEncoder(w).Encode(datastoresResponse)
		case r.URL.Path == "/api/vcenter/cluster":
			_ = json.NewEncoder(w).Encode(clustersResponse)
		case r.URL.Path == "/api/vcenter/vm/vm-100" || r.URL.Path == "/api/vcenter/vm/vm-102":
			_ = json.NewEncoder(w).Encode(vmDetailsResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.VMwareConfig{
		Enabled:           true,
		VCenterURL:        server.URL,
		Username:          "administrator@vsphere.local",
		Password:          "password",
		Datacenter:        "DC1",
		CollectVMs:        true,
		CollectHosts:      true,
		CollectDatastores: true,
		CollectClusters:   true,
	}

	exporter := integrations.NewVMwareExporter(config, logger)
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

	// Verify VM metrics
	vmMetricNames := []string{
		"vmware_vm_power_state",
		"vmware_vm_cpu_count",
		"vmware_vm_memory_size_bytes",
		"vmware_vm_cpu_usage_percent",
		"vmware_vm_cpu_usage_mhz",
		"vmware_vm_memory_used_bytes",
		"vmware_vm_memory_active_bytes",
	}

	for _, name := range vmMetricNames {
		assert.True(t, metricsMap[name], "Expected VM metric %s to be present", name)
	}

	// Verify host metrics
	hostMetricNames := []string{
		"vmware_host_connected",
		"vmware_host_power_state",
	}

	for _, name := range hostMetricNames {
		assert.True(t, metricsMap[name], "Expected host metric %s to be present", name)
	}

	// Verify datastore metrics
	datastoreMetricNames := []string{
		"vmware_datastore_capacity_bytes",
		"vmware_datastore_free_bytes",
		"vmware_datastore_used_bytes",
		"vmware_datastore_usage_percent",
	}

	for _, name := range datastoreMetricNames {
		assert.True(t, metricsMap[name], "Expected datastore metric %s to be present", name)
	}

	// Verify cluster metrics
	clusterMetricNames := []string{
		"vmware_cluster_ha_enabled",
		"vmware_cluster_drs_enabled",
	}

	for _, name := range clusterMetricNames {
		assert.True(t, metricsMap[name], "Expected cluster metric %s to be present", name)
	}

	// Verify specific metric values and tags
	for _, m := range metrics {
		if m.Name == "vmware_vm_power_state" && m.Tags["vm_name"] == "test-vm-vsphere-1" {
			assert.Equal(t, 1.0, m.Value, "POWERED_ON VM should have power_state = 1")
			assert.Equal(t, "DC1", m.Tags["datacenter"])
		}
		if m.Name == "vmware_vm_power_state" && m.Tags["vm_name"] == "test-vm-vsphere-2" {
			assert.Equal(t, 0.0, m.Value, "POWERED_OFF VM should have power_state = 0")
		}
		if m.Name == "vmware_datastore_capacity_bytes" && m.Tags["datastore_name"] == "datastore1" {
			assert.Equal(t, float64(1099511627776), m.Value)
			assert.Equal(t, "VMFS", m.Tags["datastore_type"])
		}
	}
}

func TestVMwareExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock vSphere API responses
	vmsResponse := []map[string]interface{}{
		{
			"vm":              "vm-200",
			"name":            "export-test-vm",
			"power_state":     "POWERED_ON",
			"cpu_count":       2,
			"memory_size_MiB": 4096,
			"guest_OS":        "centos7_64Guest",
		},
	}

	hostsResponse := []map[string]interface{}{
		{
			"host":             "host-20",
			"name":             "esxi-export.local",
			"connection_state": "CONNECTED",
			"power_state":      "POWERED_ON",
		},
	}

	datastoresResponse := []map[string]interface{}{
		{
			"datastore":  "datastore-200",
			"name":       "export-datastore",
			"type":       "VMFS",
			"capacity":   549755813888,
			"free_space": 274877906944,
		},
	}

	clustersResponse := []map[string]interface{}{
		{
			"cluster":     "domain-c20",
			"name":        "Export-Cluster",
			"ha_enabled":  true,
			"drs_enabled": false,
		},
	}

	vmDetailsResponse := map[string]interface{}{
		"memory": map[string]interface{}{"size_MiB": 4096},
		"cpu":    map[string]interface{}{"count": 2},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/session" && r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode("test-export-session-id")
		case r.URL.Path == "/api/session" && r.Method == "DELETE":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/vcenter/vm":
			_ = json.NewEncoder(w).Encode(vmsResponse)
		case r.URL.Path == "/api/vcenter/host":
			_ = json.NewEncoder(w).Encode(hostsResponse)
		case r.URL.Path == "/api/vcenter/datastore":
			_ = json.NewEncoder(w).Encode(datastoresResponse)
		case r.URL.Path == "/api/vcenter/cluster":
			_ = json.NewEncoder(w).Encode(clustersResponse)
		case r.URL.Path == "/api/vcenter/vm/vm-200":
			_ = json.NewEncoder(w).Encode(vmDetailsResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.VMwareConfig{
		Enabled:           true,
		VCenterURL:        server.URL,
		Username:          "admin@vsphere.local",
		Password:          "password",
		CollectVMs:        true,
		CollectHosts:      true,
		CollectDatastores: true,
		CollectClusters:   true,
	}

	exporter := integrations.NewVMwareExporter(config, logger)
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
	assert.Greater(t, len(telemetryData.Metrics), 5, "Export should populate multiple metrics")

	// Test Export when disabled
	disabledConfig := integrations.VMwareConfig{Enabled: false}
	disabledExporter := integrations.NewVMwareExporter(disabledConfig, logger)
	result, err = disabledExporter.Export(ctx, telemetryData)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestVMwareExporterCollectMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.VMwareConfig{
		Enabled:    true,
		VCenterURL: "https://vcenter.local",
		Username:   "admin",
		Password:   "password",
	}

	exporter := integrations.NewVMwareExporter(config, logger)
	// Do not call Init

	metrics, err := exporter.CollectMetrics(ctx)
	assert.Error(t, err)
	assert.Nil(t, metrics)
}

// TestVMwareExporterExportMetrics tests the ExportMetrics function
// VMware is a data source, not a metrics destination, so ExportMetrics should return an error
func TestVMwareExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name    string
		config  integrations.VMwareConfig
		metrics []integrations.Metric
	}{
		{
			name: "export metrics returns error - vmware is a data source",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
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
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			metrics: []integrations.Metric{},
		},
		{
			name: "export metrics with nil slice returns error",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			metrics: nil,
		},
		{
			name: "export metrics with multiple metrics returns error",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
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
			exporter := integrations.NewVMwareExporter(tt.config, logger)

			result, err := exporter.ExportMetrics(ctx, tt.metrics)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "vmware is a data source, not a metrics destination")
		})
	}
}

// TestVMwareExporterExportTraces tests the ExportTraces function
// VMware does not support traces, so ExportTraces should return an error
func TestVMwareExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.VMwareConfig
		traces []integrations.Trace
	}{
		{
			name: "export traces returns error - vmware does not support traces",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
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
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			traces: []integrations.Trace{},
		},
		{
			name: "export traces with nil slice returns error",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			traces: nil,
		},
		{
			name: "export traces with multiple traces returns error",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
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
			exporter := integrations.NewVMwareExporter(tt.config, logger)

			result, err := exporter.ExportTraces(ctx, tt.traces)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "vmware does not support traces")
		})
	}
}

// TestVMwareExporterExportLogs tests the ExportLogs function
// VMware does not support log ingestion, so ExportLogs should return an error
func TestVMwareExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.VMwareConfig
		logs   []integrations.LogEntry
	}{
		{
			name: "export logs returns error - vmware does not support log ingestion",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
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
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			logs: []integrations.LogEntry{},
		},
		{
			name: "export logs with nil slice returns error",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			logs: nil,
		},
		{
			name: "export logs with multiple logs returns error",
			config: integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
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
			exporter := integrations.NewVMwareExporter(tt.config, logger)

			result, err := exporter.ExportLogs(ctx, tt.logs)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "vmware does not support log ingestion")
		})
	}
}
