// package integrations provides unit tests for TelemetryFlow Agent integrations.
package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// Cisco Exporter Tests
func TestNewCiscoExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.CiscoConfig{
		Enabled:      true,
		DNACenterURL: "https://dnac.local",
		Username:     "admin",
		Password:     "password",
	}

	exporter := integrations.NewCiscoExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "cisco", exporter.Name())
	assert.Equal(t, "network", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestCiscoExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("valid config with mock server", func(t *testing.T) {
		// Create mock DNA Center API server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/dna/system/api/v1/auth/token" {
				_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token"})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:      true,
			APIType:      "dnac",
			DNACenterURL: server.URL,
			Username:     "admin",
			Password:     "password",
		}
		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("disabled config", func(t *testing.T) {
		config := integrations.CiscoConfig{
			Enabled: false,
		}
		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("missing meraki api key", func(t *testing.T) {
		config := integrations.CiscoConfig{
			Enabled: true,
			APIType: "meraki",
		}
		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})
}

func TestCiscoExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.CiscoConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.CiscoConfig{
				Enabled:      true,
				DNACenterURL: "https://dnac.local",
				Username:     "admin",
				Password:     "password",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.CiscoConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing meraki api key",
			config: integrations.CiscoConfig{
				Enabled: true,
				APIType: "meraki",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewCiscoExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCiscoExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CiscoConfig{Enabled: false}
	exporter := integrations.NewCiscoExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestCiscoExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock DNA Center API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/dna/system/api/v1/auth/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.CiscoConfig{
		Enabled:      true,
		APIType:      "dnac",
		DNACenterURL: server.URL,
		Username:     "admin",
		Password:     "password",
	}

	exporter := integrations.NewCiscoExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// SNMP Exporter Tests
func TestNewSNMPExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.SNMPConfig{
		Enabled: true,
		Targets: []integrations.SNMPTarget{
			{Address: "192.168.1.1"},
		},
		Port:      161,
		Community: "public",
		Version:   "2c",
	}

	exporter := integrations.NewSNMPExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "snmp", exporter.Name())
	assert.Equal(t, "network", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestSNMPExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.SNMPConfig
		expectError bool
	}{
		{
			name: "valid config v2c",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Port:      161,
				Community: "public",
				Version:   "2c",
			},
			expectError: false,
		},
		{
			name: "valid config v3",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Port:         161,
				Version:      "3",
				Username:     "admin",
				AuthProtocol: "SHA",
				AuthPassword: "authpass",
				PrivProtocol: "AES",
				PrivPassword: "privpass",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.SNMPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing targets",
			config: integrations.SNMPConfig{
				Enabled:   true,
				Community: "public",
				Version:   "2c",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSNMPExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.SNMPConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.SNMPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing targets",
			config: integrations.SNMPConfig{
				Enabled:   true,
				Community: "public",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSNMPExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.SNMPConfig{Enabled: false}
	exporter := integrations.NewSNMPExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestSNMPExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.SNMPConfig{
		Enabled: true,
		Targets: []integrations.SNMPTarget{
			{Address: "192.168.1.1"},
		},
		Community: "public",
		Version:   "2c",
	}

	exporter := integrations.NewSNMPExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// eBPF Exporter Tests
func TestNewEBPFExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
		CollectNetwork:  true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "ebpf", exporter.Name())
	assert.Equal(t, "kernel", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestEBPFExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("valid config on linux", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// eBPF requires Linux, expect error on other platforms
		if err != nil {
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("disabled config", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
	})
}

func TestEBPFExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	t.Run("valid config on linux", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Validate()
		// eBPF requires Linux, expect error on other platforms
		if err != nil {
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("disabled always valid", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Validate()
		assert.NoError(t, err)
	})
}

func TestEBPFExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{Enabled: false}
	exporter := integrations.NewEBPFExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestEBPFExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Test config defaults
func TestNetworkConfigDefaults(t *testing.T) {
	t.Run("cisco defaults", func(t *testing.T) {
		config := integrations.CiscoConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.DNACenterURL)
	})

	t.Run("snmp defaults", func(t *testing.T) {
		config := integrations.SNMPConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Targets)
		assert.Equal(t, 0, config.Port)
	})

	t.Run("ebpf defaults", func(t *testing.T) {
		config := integrations.EBPFConfig{}
		assert.False(t, config.Enabled)
		assert.False(t, config.CollectSyscalls)
		assert.False(t, config.CollectNetwork)
	})
}

// Benchmark tests
func BenchmarkNewCiscoExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.CiscoConfig{
		Enabled:      true,
		DNACenterURL: "https://dnac.local",
		Username:     "admin",
		Password:     "password",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewCiscoExporter(config, logger)
	}
}

func BenchmarkNewSNMPExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.SNMPConfig{
		Enabled: true,
		Targets: []integrations.SNMPTarget{
			{Address: "192.168.1.1"},
		},
		Community: "public",
		Version:   "2c",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewSNMPExporter(config, logger)
	}
}

func BenchmarkNewEBPFExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewEBPFExporter(config, logger)
	}
}

// Cisco Exporter CollectMetrics and Export Tests with Mock Server
func TestCiscoExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("dnac collect metrics success", func(t *testing.T) {
		// Create mock DNA Center API server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				// Auth endpoint
				_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token-12345"})
			case "/dna/intent/api/v1/network-device":
				// Device list endpoint
				response := map[string]interface{}{
					"response": []map[string]interface{}{
						{
							"id":                  "device-001",
							"hostname":            "switch-core-01",
							"managementIpAddress": "10.0.0.1",
							"platformId":          "C9300-24P",
							"family":              "Switches and Hubs",
							"type":                "Cisco Catalyst 9300 Switch",
							"softwareVersion":     "17.3.4",
							"role":                "DISTRIBUTION",
							"serialNumber":        "FCW12345678",
							"reachabilityStatus":  "Reachable",
							"collectionStatus":    "Managed",
						},
						{
							"id":                  "device-002",
							"hostname":            "router-edge-01",
							"managementIpAddress": "10.0.0.2",
							"platformId":          "ISR4451",
							"family":              "Routers",
							"type":                "Cisco ISR 4451",
							"softwareVersion":     "17.3.2",
							"role":                "BORDER ROUTER",
							"serialNumber":        "FTX98765432",
							"reachabilityStatus":  "Unreachable",
							"collectionStatus":    "Unmanaged",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			case "/dna/intent/api/v1/network-health":
				// Health endpoint
				response := map[string]interface{}{
					"response": []map[string]interface{}{
						{
							"healthScore": 95,
							"category":    "wired",
						},
						{
							"healthScore": 87,
							"category":    "wireless",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:        true,
			APIType:        "dnac",
			DNACenterURL:   server.URL,
			Username:       "admin",
			Password:       "password",
			CollectDevices: true,
			CollectHealth:  true,
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify device metrics exist
		var foundReachable, foundManaged, foundHealthScore bool
		for _, m := range metrics {
			switch m.Name {
			case "cisco_dnac_device_reachable":
				foundReachable = true
				// First device is reachable
				if m.Tags["hostname"] == "switch-core-01" {
					assert.Equal(t, 1.0, m.Value)
				}
				// Second device is not reachable
				if m.Tags["hostname"] == "router-edge-01" {
					assert.Equal(t, 0.0, m.Value)
				}
			case "cisco_dnac_device_managed":
				foundManaged = true
			case "cisco_dnac_network_health_score":
				foundHealthScore = true
			}
		}

		assert.True(t, foundReachable, "Expected cisco_dnac_device_reachable metric")
		assert.True(t, foundManaged, "Expected cisco_dnac_device_managed metric")
		assert.True(t, foundHealthScore, "Expected cisco_dnac_network_health_score metric")
	})

	t.Run("dnac collect metrics with custom labels", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token"})
			case "/dna/intent/api/v1/network-device":
				response := map[string]interface{}{
					"response": []map[string]interface{}{
						{
							"id":                 "device-001",
							"hostname":           "test-switch",
							"reachabilityStatus": "Reachable",
							"collectionStatus":   "Managed",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"response": []interface{}{}})
			}
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:        true,
			APIType:        "dnac",
			DNACenterURL:   server.URL,
			Username:       "admin",
			Password:       "password",
			CollectDevices: true,
			Labels: map[string]string{
				"environment": "production",
				"datacenter":  "dc1",
			},
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify custom labels are applied
		for _, m := range metrics {
			assert.Equal(t, "production", m.Tags["environment"])
			assert.Equal(t, "dc1", m.Tags["datacenter"])
		}
	})

	t.Run("disabled exporter returns error", func(t *testing.T) {
		config := integrations.CiscoConfig{
			Enabled: false,
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		_ = exporter.Init(ctx)

		metrics, err := exporter.CollectMetrics(ctx)
		assert.Error(t, err)
		assert.Nil(t, metrics)
	})

	t.Run("uninitialized exporter returns error", func(t *testing.T) {
		config := integrations.CiscoConfig{
			Enabled:      true,
			APIType:      "dnac",
			DNACenterURL: "https://dnac.local",
			Username:     "admin",
			Password:     "password",
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		// Don't call Init

		metrics, err := exporter.CollectMetrics(ctx)
		assert.Error(t, err)
		assert.Nil(t, metrics)
	})

	t.Run("auth failure returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/dna/system/api/v1/auth/token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:      true,
			APIType:      "dnac",
			DNACenterURL: server.URL,
			Username:     "admin",
			Password:     "wrongpassword",
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		assert.Error(t, err)
	})
}

func TestCiscoExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token"})
			case "/dna/intent/api/v1/network-device":
				response := map[string]interface{}{
					"response": []map[string]interface{}{
						{
							"id":                 "device-001",
							"hostname":           "switch-01",
							"reachabilityStatus": "Reachable",
							"collectionStatus":   "Managed",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			default:
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"response": []interface{}{}})
			}
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:        true,
			APIType:        "dnac",
			DNACenterURL:   server.URL,
			Username:       "admin",
			Password:       "password",
			CollectDevices: true,
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{},
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Greater(t, result.ItemsExported, 0)
		assert.NotEmpty(t, data.Metrics)
	})

	t.Run("export disabled returns error", func(t *testing.T) {
		config := integrations.CiscoConfig{
			Enabled: false,
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		_ = exporter.Init(ctx)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export appends to existing metrics", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token"})
			case "/dna/intent/api/v1/network-device":
				response := map[string]interface{}{
					"response": []map[string]interface{}{
						{
							"id":                 "device-001",
							"hostname":           "switch-01",
							"reachabilityStatus": "Reachable",
							"collectionStatus":   "Managed",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			default:
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"response": []interface{}{}})
			}
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:        true,
			APIType:        "dnac",
			DNACenterURL:   server.URL,
			Username:       "admin",
			Password:       "password",
			CollectDevices: true,
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Pre-populate with existing metrics
		existingMetric := integrations.Metric{
			Name:  "existing_metric",
			Value: 100,
		}
		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{existingMetric},
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.True(t, result.Success)

		// Verify existing metric is preserved
		assert.Equal(t, "existing_metric", data.Metrics[0].Name)
		assert.Equal(t, 100.0, data.Metrics[0].Value)
		// Verify new metrics were added
		assert.Greater(t, len(data.Metrics), 1)
	})

	t.Run("export with API error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/dna/system/api/v1/auth/token":
				_ = json.NewEncoder(w).Encode(map[string]string{"Token": "test-token"})
			case "/dna/intent/api/v1/network-device":
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
			default:
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"response": []interface{}{}})
			}
		}))
		defer server.Close()

		config := integrations.CiscoConfig{
			Enabled:        true,
			APIType:        "dnac",
			DNACenterURL:   server.URL,
			Username:       "admin",
			Password:       "password",
			CollectDevices: true,
			CollectHealth:  false,
		}

		exporter := integrations.NewCiscoExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}

		// Even with device API error, should return empty metrics (logs warning)
		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.True(t, result.Success)
	})
}

// SNMP Exporter CollectMetrics and Export Tests
func TestSNMPExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("collect metrics with valid target", func(t *testing.T) {
		// SNMP uses UDP, not HTTP. We test with localhost which is always reachable
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{
					Address: "127.0.0.1",
					Port:    161,
					Name:    "localhost",
				},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify target up metric exists
		var foundUpMetric bool
		for _, m := range metrics {
			if m.Name == "snmp_target_up" {
				foundUpMetric = true
				assert.Equal(t, "127.0.0.1", m.Tags["target"])
				assert.Equal(t, "localhost", m.Tags["target_name"])
				assert.Equal(t, "2c", m.Tags["snmp_version"])
			}
		}
		assert.True(t, foundUpMetric, "Expected snmp_target_up metric")
	})

	t.Run("collect metrics with multiple targets", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "target1"},
				{Address: "127.0.0.1", Port: 162, Name: "target2"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify we have metrics for each target
		targetMetrics := make(map[string]bool)
		for _, m := range metrics {
			if m.Name == "snmp_target_up" {
				targetMetrics[m.Tags["target_name"]] = true
			}
		}
		assert.True(t, targetMetrics["target1"], "Expected metrics for target1")
		assert.True(t, targetMetrics["target2"], "Expected metrics for target2")
	})

	t.Run("collect metrics with custom labels", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{
					Address: "127.0.0.1",
					Port:    161,
					Name:    "test-device",
					Labels: map[string]string{
						"location": "rack-a1",
					},
				},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
			Labels: map[string]string{
				"environment": "test",
				"team":        "network",
			},
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify labels are applied
		for _, m := range metrics {
			assert.Equal(t, "test", m.Tags["environment"])
			assert.Equal(t, "network", m.Tags["team"])
			if m.Tags["target_name"] == "test-device" {
				assert.Equal(t, "rack-a1", m.Tags["location"])
			}
		}
	})

	t.Run("collect metrics disabled returns error", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: false,
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		_ = exporter.Init(ctx)

		metrics, err := exporter.CollectMetrics(ctx)
		assert.Error(t, err)
		assert.Nil(t, metrics)
	})

	t.Run("collect metrics uninitialized returns error", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "192.168.1.1"},
			},
			Community: "public",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		// Don't call Init

		metrics, err := exporter.CollectMetrics(ctx)
		assert.Error(t, err)
		assert.Nil(t, metrics)
	})

	t.Run("collect metrics with SNMPv3", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Name: "v3-device"},
			},
			Port:          161,
			Version:       "3",
			Username:      "admin",
			SecurityLevel: "authPriv",
			AuthProtocol:  "SHA",
			AuthPassword:  "authpassword",
			PrivProtocol:  "AES",
			PrivPassword:  "privpassword",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify v3 version tag
		for _, m := range metrics {
			if m.Name == "snmp_target_up" {
				assert.Equal(t, "3", m.Tags["snmp_version"])
			}
		}
	})
}

func TestSNMPExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export success", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "test-device"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{},
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Greater(t, result.ItemsExported, 0)
		assert.NotEmpty(t, data.Metrics)
	})

	t.Run("export disabled returns error", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: false,
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		_ = exporter.Init(ctx)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export appends to existing metrics", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "test-device"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Pre-populate with existing metrics
		existingMetric := integrations.Metric{
			Name:  "pre_existing_metric",
			Value: 42,
		}
		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{existingMetric},
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.True(t, result.Success)

		// Verify existing metric is preserved
		assert.Equal(t, "pre_existing_metric", data.Metrics[0].Name)
		assert.Equal(t, 42.0, data.Metrics[0].Value)
		// Verify new metrics were added
		assert.Greater(t, len(data.Metrics), 1)
	})

	t.Run("export with multiple targets", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "device1"},
				{Address: "127.0.0.1", Port: 162, Name: "device2"},
				{Address: "127.0.0.1", Port: 163, Name: "device3"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Greater(t, result.ItemsExported, 0)

		// Count unique targets in metrics
		targets := make(map[string]bool)
		for _, m := range data.Metrics {
			if name, ok := m.Tags["target_name"]; ok {
				targets[name] = true
			}
		}
		assert.Len(t, targets, 3)
	})

	t.Run("export result contains correct items count", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "test-device"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)

		// ItemsExported should match the number of metrics added
		assert.Equal(t, len(data.Metrics), result.ItemsExported)
	})
}
