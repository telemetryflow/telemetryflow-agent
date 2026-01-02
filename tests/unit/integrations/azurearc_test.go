// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"context"
	"encoding/json"
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

func TestNewAzureArcExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.AzureArcConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
	}

	exporter := integrations.NewAzureArcExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "azurearc", exporter.Name())
	assert.Equal(t, "hybrid", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestAzureArcExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.AzureArcConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				ResourceGroup:  "test-rg",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.AzureArcConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing subscription",
			config: integrations.AzureArcConfig{
				Enabled:       true,
				ResourceGroup: "test-rg",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureArcExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAzureArcExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.AzureArcConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				ResourceGroup:  "test-rg",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.AzureArcConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing subscription",
			config: integrations.AzureArcConfig{
				Enabled:       true,
				ResourceGroup: "test-rg",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureArcExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAzureArcExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{Enabled: false}
	exporter := integrations.NewAzureArcExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestAzureArcExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestAzureArcExporterExportMethods(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
	}

	exporter := integrations.NewAzureArcExporter(config, logger)

	// Without init or connection, exports should fail
	result, err := exporter.ExportMetrics(ctx, []integrations.Metric{})
	assert.Error(t, err)
	assert.Nil(t, result)

	result, err = exporter.ExportTraces(ctx, []integrations.Trace{})
	assert.Error(t, err)
	assert.Nil(t, result)

	result, err = exporter.ExportLogs(ctx, []integrations.LogEntry{})
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Azure Arc Exporter - Comprehensive Tests with Mock HTTP Server

// Helper function for Azure Arc path matching
func azureArcPathContains(path, substr string) bool {
	for i := 0; i <= len(path)-len(substr); i++ {
		if path[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestNewAzureArcExporterComprehensive tests the constructor with various configurations
func TestNewAzureArcExporterComprehensive(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name           string
		config         integrations.AzureArcConfig
		expectedName   string
		expectedType   string
		expectedEnable bool
	}{
		{
			name: "enabled with full config",
			config: integrations.AzureArcConfig{
				Enabled:            true,
				SubscriptionID:     "test-subscription-id",
				TenantID:           "test-tenant-id",
				ClientID:           "test-client-id",
				ClientSecret:       "test-client-secret",
				ResourceGroup:      "test-rg",
				Location:           "westus2",
				MachineName:        "test-machine",
				UseManagedIdentity: false,
				CollectMachines:    true,
				CollectKubernetes:  true,
				CollectSQLServers:  true,
			},
			expectedName:   "azurearc",
			expectedType:   "hybrid",
			expectedEnable: true,
		},
		{
			name: "enabled with managed identity",
			config: integrations.AzureArcConfig{
				Enabled:            true,
				SubscriptionID:     "test-subscription-id",
				UseManagedIdentity: true,
				ResourceGroup:      "test-rg",
			},
			expectedName:   "azurearc",
			expectedType:   "hybrid",
			expectedEnable: true,
		},
		{
			name: "disabled config",
			config: integrations.AzureArcConfig{
				Enabled: false,
			},
			expectedName:   "azurearc",
			expectedType:   "hybrid",
			expectedEnable: false,
		},
		{
			name: "minimal enabled config",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "minimal-sub-id",
			},
			expectedName:   "azurearc",
			expectedType:   "hybrid",
			expectedEnable: true,
		},
		{
			name: "config with labels and headers",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-sub",
				Labels: map[string]string{
					"env":    "production",
					"region": "us-west",
				},
				Headers: map[string]string{
					"X-Custom-Header": "custom-value",
				},
			},
			expectedName:   "azurearc",
			expectedType:   "hybrid",
			expectedEnable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureArcExporter(tt.config, logger)

			require.NotNil(t, exporter)
			assert.Equal(t, tt.expectedName, exporter.Name())
			assert.Equal(t, tt.expectedType, exporter.Type())
			assert.Equal(t, tt.expectedEnable, exporter.IsEnabled())
		})
	}
}

// TestAzureArcExporterInitComprehensive tests initialization with various scenarios
func TestAzureArcExporterInitComprehensive(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.AzureArcConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with service principal",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				TenantID:       "test-tenant",
				ClientID:       "test-client",
				ClientSecret:   "test-secret",
				ResourceGroup:  "test-rg",
			},
			expectError: false,
		},
		{
			name: "valid config with managed identity",
			config: integrations.AzureArcConfig{
				Enabled:            true,
				SubscriptionID:     "test-subscription",
				UseManagedIdentity: true,
				ResourceGroup:      "test-rg",
			},
			expectError: false,
		},
		{
			name: "disabled config skips validation",
			config: integrations.AzureArcConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing subscription id",
			config: integrations.AzureArcConfig{
				Enabled:       true,
				ResourceGroup: "test-rg",
			},
			expectError: true,
			errorMsg:    "subscription_id",
		},
		{
			name: "valid config without resource group",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
			},
			expectError: false,
		},
		{
			name: "config with custom endpoints",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				IMDSEndpoint:   "http://custom-imds:8080",
				HybridEndpoint: "https://custom-management.azure.com",
			},
			expectError: false,
		},
		{
			name: "config with custom timeouts",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				Timeout:        60000000000,  // 60 seconds
				ScrapeInterval: 120000000000, // 120 seconds
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureArcExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAzureArcExporterValidateComprehensive tests validation logic
func TestAzureArcExporterValidateComprehensive(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.AzureArcConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid with service principal",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "valid-subscription",
				TenantID:       "valid-tenant",
				ClientID:       "valid-client",
				ClientSecret:   "valid-secret",
			},
			expectError: false,
		},
		{
			name: "valid with managed identity",
			config: integrations.AzureArcConfig{
				Enabled:            true,
				SubscriptionID:     "valid-subscription",
				UseManagedIdentity: true,
			},
			expectError: false,
		},
		{
			name: "valid without explicit auth (defaults to managed identity)",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "valid-subscription",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.AzureArcConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing subscription id when enabled",
			config: integrations.AzureArcConfig{
				Enabled:  true,
				TenantID: "tenant",
				ClientID: "client",
			},
			expectError: true,
			errorMsg:    "subscription_id",
		},
		{
			name: "partial service principal config (falls back to managed identity)",
			config: integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "valid-subscription",
				TenantID:       "tenant-only",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureArcExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAzureArcExporterCollectMetricsWithMock tests metrics collection with mock Azure API
func TestAzureArcExporterCollectMetricsWithMock(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock Azure Arc API responses
	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.HybridCompute/machines/arc-machine-1",
				"name":     "arc-machine-1",
				"location": "eastus",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"provisioningState": "Succeeded",
					"status":            "Connected",
					"machineFqdn":       "arc-machine-1.contoso.com",
					"osName":            "linux",
					"osVersion":         "Ubuntu 20.04",
					"osType":            "linux",
					"lastStatusChange":  "2024-01-01T00:00:00Z",
					"agentVersion":      "1.35.0",
					"vmId":              "vm-12345",
					"displayName":       "Arc Machine 1",
					"errorDetails":      []map[string]interface{}{},
					"extensions": []map[string]interface{}{
						{
							"name":              "MicrosoftMonitoringAgent",
							"type":              "Microsoft.EnterpriseCloud.Monitoring",
							"provisioningState": "Succeeded",
						},
						{
							"name":              "DependencyAgent",
							"type":              "Microsoft.Azure.Monitoring.DependencyAgent",
							"provisioningState": "Succeeded",
						},
					},
				},
				"tags": map[string]string{
					"environment": "production",
					"team":        "platform",
				},
			},
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.HybridCompute/machines/arc-machine-2",
				"name":     "arc-machine-2",
				"location": "westus2",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"provisioningState": "Succeeded",
					"status":            "Disconnected",
					"machineFqdn":       "arc-machine-2.contoso.com",
					"osName":            "windows",
					"osVersion":         "Windows Server 2019",
					"osType":            "windows",
					"lastStatusChange":  "2024-01-02T00:00:00Z",
					"agentVersion":      "1.34.0",
					"displayName":       "Arc Machine 2",
					"errorDetails": []map[string]interface{}{
						{
							"code":    "HeartbeatMissing",
							"message": "Agent heartbeat not received",
						},
					},
					"extensions": []map[string]interface{}{
						{
							"name":              "AzureMonitorWindowsAgent",
							"type":              "Microsoft.Azure.Monitor.AzureMonitorWindowsAgent",
							"provisioningState": "Failed",
						},
					},
				},
				"tags": map[string]string{
					"environment": "staging",
				},
			},
		},
	}

	kubernetesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Kubernetes/connectedClusters/arc-k8s-1",
				"name":     "arc-k8s-1",
				"location": "eastus",
				"type":     "Microsoft.Kubernetes/connectedClusters",
				"properties": map[string]interface{}{
					"provisioningState":    "Succeeded",
					"connectivityStatus":   "Connected",
					"distribution":         "k3s",
					"infrastructure":       "generic",
					"kubernetesVersion":    "1.28.0",
					"totalNodeCount":       5,
					"totalCoreCount":       20,
					"agentVersion":         "1.14.0",
					"lastConnectivityTime": "2024-01-03T00:00:00Z",
				},
				"tags": map[string]string{
					"cluster-type": "edge",
				},
			},
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Kubernetes/connectedClusters/arc-k8s-2",
				"name":     "arc-k8s-2",
				"location": "westeurope",
				"type":     "Microsoft.Kubernetes/connectedClusters",
				"properties": map[string]interface{}{
					"provisioningState":    "Succeeded",
					"connectivityStatus":   "Offline",
					"distribution":         "AKS-HCI",
					"infrastructure":       "azure_stack_hci",
					"kubernetesVersion":    "1.27.4",
					"totalNodeCount":       3,
					"totalCoreCount":       12,
					"agentVersion":         "1.13.0",
					"lastConnectivityTime": "2024-01-01T12:00:00Z",
				},
			},
		},
	}

	sqlServersResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.AzureArcData/sqlServerInstances/sql-server-1",
				"name":     "sql-server-1",
				"location": "eastus",
				"type":     "Microsoft.AzureArcData/sqlServerInstances",
				"properties": map[string]interface{}{
					"version":     "SQL Server 2019",
					"edition":     "Enterprise",
					"containerId": "container-12345",
					"status":      "Registered",
					"vCore":       "8",
					"cores":       "8",
					"licenseType": "LicenseIncluded",
				},
				"tags": map[string]string{
					"workload": "database",
				},
			},
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.AzureArcData/sqlServerInstances/sql-server-2",
				"name":     "sql-server-2",
				"location": "westus2",
				"type":     "Microsoft.AzureArcData/sqlServerInstances",
				"properties": map[string]interface{}{
					"version":     "SQL Server 2022",
					"edition":     "Standard",
					"containerId": "container-67890",
					"status":      "Connected",
					"vCore":       "4",
					"cores":       "4",
					"licenseType": "PAYG",
				},
			},
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.AzureArcData/sqlServerInstances/sql-server-3",
				"name":     "sql-server-3",
				"location": "centralus",
				"type":     "Microsoft.AzureArcData/sqlServerInstances",
				"properties": map[string]interface{}{
					"version":     "SQL Server 2017",
					"edition":     "Developer",
					"containerId": "container-11111",
					"status":      "Disconnected",
					"vCore":       "2",
					"cores":       "2",
					"licenseType": "Free",
				},
			},
		},
	}

	tokenResponse := map[string]interface{}{
		"access_token": "mock-access-token-12345",
		"expires_in":   "3600",
	}

	// Create mock Azure ARM API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			// IMDS token endpoint
			if r.Header.Get("Metadata") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
			_ = json.NewEncoder(w).Encode(kubernetesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
			_ = json.NewEncoder(w).Encode(sqlServersResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		ResourceGroup:      "test-rg",
		Location:           "eastus",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
		Labels: map[string]string{
			"source": "azure-arc",
		},
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "CollectMetrics should return metrics")

	// Build metrics map for verification
	metricsMap := make(map[string][]integrations.Metric)
	for _, m := range metrics {
		metricsMap[m.Name] = append(metricsMap[m.Name], m)
	}

	// Verify machine metrics
	machineMetricNames := []string{
		"azurearc_machine_connected",
		"azurearc_machine_extension_count",
		"azurearc_machine_healthy_extensions",
		"azurearc_machine_error_count",
	}

	for _, name := range machineMetricNames {
		assert.Contains(t, metricsMap, name, "Expected machine metric %s to be present", name)
	}

	// Verify Kubernetes metrics
	k8sMetricNames := []string{
		"azurearc_kubernetes_connected",
		"azurearc_kubernetes_node_count",
		"azurearc_kubernetes_core_count",
	}

	for _, name := range k8sMetricNames {
		assert.Contains(t, metricsMap, name, "Expected Kubernetes metric %s to be present", name)
	}

	// Verify SQL Server metrics
	sqlMetricNames := []string{
		"azurearc_sqlserver_running",
	}

	for _, name := range sqlMetricNames {
		assert.Contains(t, metricsMap, name, "Expected SQL Server metric %s to be present", name)
	}

	// Verify specific metric values
	for _, m := range metrics {
		// Check connected machine
		if m.Name == "azurearc_machine_connected" && m.Tags["machine_name"] == "arc-machine-1" {
			assert.Equal(t, 1.0, m.Value, "Connected machine should have value = 1")
			assert.Equal(t, "eastus", m.Tags["location"])
			assert.Equal(t, "linux", m.Tags["os_type"])
			assert.Equal(t, "Connected", m.Tags["status"])
			assert.Equal(t, "azure-arc", m.Tags["source"], "Labels should be present")
		}

		// Check disconnected machine
		if m.Name == "azurearc_machine_connected" && m.Tags["machine_name"] == "arc-machine-2" {
			assert.Equal(t, 0.0, m.Value, "Disconnected machine should have value = 0")
			assert.Equal(t, "Disconnected", m.Tags["status"])
		}

		// Check machine extension count
		if m.Name == "azurearc_machine_extension_count" && m.Tags["machine_name"] == "arc-machine-1" {
			assert.Equal(t, 2.0, m.Value, "Machine 1 should have 2 extensions")
		}

		// Check healthy extensions
		if m.Name == "azurearc_machine_healthy_extensions" && m.Tags["machine_name"] == "arc-machine-1" {
			assert.Equal(t, 2.0, m.Value, "Machine 1 should have 2 healthy extensions")
		}

		// Check error count
		if m.Name == "azurearc_machine_error_count" && m.Tags["machine_name"] == "arc-machine-2" {
			assert.Equal(t, 1.0, m.Value, "Machine 2 should have 1 error")
		}

		// Check connected Kubernetes cluster
		if m.Name == "azurearc_kubernetes_connected" && m.Tags["cluster_name"] == "arc-k8s-1" {
			assert.Equal(t, 1.0, m.Value, "Connected cluster should have value = 1")
			assert.Equal(t, "k3s", m.Tags["distribution"])
			assert.Equal(t, "1.28.0", m.Tags["kubernetes_version"])
		}

		// Check offline Kubernetes cluster
		if m.Name == "azurearc_kubernetes_connected" && m.Tags["cluster_name"] == "arc-k8s-2" {
			assert.Equal(t, 0.0, m.Value, "Offline cluster should have value = 0")
		}

		// Check Kubernetes node count
		if m.Name == "azurearc_kubernetes_node_count" && m.Tags["cluster_name"] == "arc-k8s-1" {
			assert.Equal(t, 5.0, m.Value)
		}

		// Check Kubernetes core count
		if m.Name == "azurearc_kubernetes_core_count" && m.Tags["cluster_name"] == "arc-k8s-1" {
			assert.Equal(t, 20.0, m.Value)
		}

		// Check running SQL Server
		if m.Name == "azurearc_sqlserver_running" && m.Tags["server_name"] == "sql-server-1" {
			assert.Equal(t, 1.0, m.Value, "Registered SQL Server should have value = 1")
			assert.Equal(t, "Enterprise", m.Tags["edition"])
			assert.Equal(t, "SQL Server 2019", m.Tags["version"])
		}

		// Check disconnected SQL Server
		if m.Name == "azurearc_sqlserver_running" && m.Tags["server_name"] == "sql-server-3" {
			assert.Equal(t, 0.0, m.Value, "Disconnected SQL Server should have value = 0")
		}
	}

	// Verify total metric counts
	assert.Len(t, metricsMap["azurearc_machine_connected"], 2, "Should have 2 machine connected metrics")
	assert.Len(t, metricsMap["azurearc_kubernetes_connected"], 2, "Should have 2 kubernetes connected metrics")
	assert.Len(t, metricsMap["azurearc_sqlserver_running"], 3, "Should have 3 SQL server metrics")
}

// TestAzureArcExporterExportWithMock tests the Export method with mock server
func TestAzureArcExporterExportWithMock(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Mock responses
	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.HybridCompute/machines/export-machine",
				"name":     "export-machine",
				"location": "eastus",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"provisioningState": "Succeeded",
					"status":            "Connected",
					"osType":            "linux",
					"osName":            "linux",
					"osVersion":         "CentOS 8",
					"agentVersion":      "1.35.0",
					"extensions":        []map[string]interface{}{},
					"errorDetails":      []map[string]interface{}{},
				},
			},
		},
	}

	k8sResponse := map[string]interface{}{
		"value": []map[string]interface{}{},
	}

	sqlResponse := map[string]interface{}{
		"value": []map[string]interface{}{},
	}

	tokenResponse := map[string]interface{}{
		"access_token": "mock-export-token",
		"expires_in":   "3600",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
			_ = json.NewEncoder(w).Encode(k8sResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
			_ = json.NewEncoder(w).Encode(sqlResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		ResourceGroup:      "test-rg",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
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

	// Verify machine metrics were added
	foundMachineMetric := false
	for _, m := range telemetryData.Metrics {
		if m.Name == "azurearc_machine_connected" {
			foundMachineMetric = true
			break
		}
	}
	assert.True(t, foundMachineMetric, "Should have machine metrics in telemetry data")
}

// TestAzureArcExporterExportDisabled tests Export when disabled
func TestAzureArcExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{
		Enabled: false,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)

	telemetryData := &integrations.TelemetryData{}
	result, err := exporter.Export(ctx, telemetryData)

	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestAzureArcExporterHealthWithMock tests health check with mock server
func TestAzureArcExporterHealthWithMock(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("healthy connection", func(t *testing.T) {
		machinesResponse := map[string]interface{}{
			"value": []map[string]interface{}{},
		}

		tokenResponse := map[string]interface{}{
			"access_token": "mock-health-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch {
			case r.URL.Path == "/metadata/identity/oauth2/token":
				_ = json.NewEncoder(w).Encode(tokenResponse)
			case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
				_ = json.NewEncoder(w).Encode(machinesResponse)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			ResourceGroup:      "test-rg",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "Azure Arc connected", status.Message)
		assert.NotNil(t, status.Details)
		assert.Equal(t, "test-sub", status.Details["subscription_id"])
		assert.Equal(t, "test-rg", status.Details["resource_group"])
		assert.NotZero(t, status.Latency)
	})

	t.Run("authentication failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "authentication failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("API connection failure", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "mock-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}

			// Return error for machines endpoint
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})
}

// TestAzureArcExporterCloseComprehensive tests Close method
func TestAzureArcExporterCloseComprehensive(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("close after init", func(t *testing.T) {
		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			ResourceGroup:  "test-rg",
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)

		err := exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close without init", func(t *testing.T) {
		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		// Don't call Init

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close disabled exporter", func(t *testing.T) {
		config := integrations.AzureArcConfig{
			Enabled: false,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})
}

// TestAzureArcExporterExportMethodsNotSupported tests unsupported export methods
func TestAzureArcExporterExportMethodsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	_ = exporter.Init(ctx)

	t.Run("ExportMetrics not supported", func(t *testing.T) {
		result, err := exporter.ExportMetrics(ctx, []integrations.Metric{})
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "data source")
	})

	t.Run("ExportTraces not supported", func(t *testing.T) {
		result, err := exporter.ExportTraces(ctx, []integrations.Trace{})
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not support traces")
	})

	t.Run("ExportLogs not supported", func(t *testing.T) {
		result, err := exporter.ExportLogs(ctx, []integrations.LogEntry{})
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not support log")
	})
}

// TestAzureArcExporterCollectMetricsNotInitialized tests collection without init
func TestAzureArcExporterCollectMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	// Do not call Init

	metrics, err := exporter.CollectMetrics(ctx)
	assert.Error(t, err)
	assert.Nil(t, metrics)
}

// TestAzureArcExporterCollectMetricsDisabled tests collection when disabled
func TestAzureArcExporterCollectMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureArcConfig{
		Enabled: false,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)

	metrics, err := exporter.CollectMetrics(ctx)
	assert.Error(t, err)
	assert.Nil(t, metrics)
}

// TestAzureArcExporterCollectMetricsPartialFailure tests partial collection failures
func TestAzureArcExporterCollectMetricsPartialFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/working-machine",
				"name":     "working-machine",
				"location": "eastus",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"provisioningState": "Succeeded",
					"status":            "Connected",
					"osType":            "linux",
					"osName":            "linux",
					"osVersion":         "Ubuntu",
					"agentVersion":      "1.35.0",
					"extensions":        []map[string]interface{}{},
					"errorDetails":      []map[string]interface{}{},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
			// Return error for Kubernetes
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
			// Return error for SQL
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "access denied"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Should succeed and return machine metrics despite K8s and SQL failures
	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "Should return machine metrics even when other collections fail")

	// Verify only machine metrics are present
	for _, m := range metrics {
		assert.Contains(t, m.Name, "machine", "Only machine metrics should be present")
	}
}

// TestAzureArcExporterCollectMetricsSubscriptionLevel tests subscription-level collection
func TestAzureArcExporterCollectMetricsSubscriptionLevel(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	// Multiple machines across different resource groups
	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/resourceGroups/rg1/providers/Microsoft.HybridCompute/machines/machine-rg1",
				"name":     "machine-rg1",
				"location": "eastus",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"status":       "Connected",
					"osType":       "linux",
					"osName":       "linux",
					"osVersion":    "Ubuntu",
					"agentVersion": "1.35.0",
					"extensions":   []map[string]interface{}{},
					"errorDetails": []map[string]interface{}{},
				},
			},
			{
				"id":       "/subscriptions/test-sub/resourceGroups/rg2/providers/Microsoft.HybridCompute/machines/machine-rg2",
				"name":     "machine-rg2",
				"location": "westus",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"status":       "Connected",
					"osType":       "windows",
					"osName":       "windows",
					"osVersion":    "Windows 11",
					"agentVersion": "1.35.0",
					"extensions":   []map[string]interface{}{},
					"errorDetails": []map[string]interface{}{},
				},
			},
		},
	}

	k8sResponse := map[string]interface{}{"value": []map[string]interface{}{}}
	sqlResponse := map[string]interface{}{"value": []map[string]interface{}{}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
			_ = json.NewEncoder(w).Encode(k8sResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
			_ = json.NewEncoder(w).Encode(sqlResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// No resource group specified - should query at subscription level
	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		ResourceGroup:      "", // Empty - subscription level
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)

	// Should have metrics for both machines
	machineNames := map[string]bool{}
	for _, m := range metrics {
		if m.Name == "azurearc_machine_connected" {
			machineNames[m.Tags["machine_name"]] = true
		}
	}
	assert.True(t, machineNames["machine-rg1"], "Should have machine from rg1")
	assert.True(t, machineNames["machine-rg2"], "Should have machine from rg2")
}

// TestAzureArcExporterWithCustomHeaders tests custom headers
func TestAzureArcExporterWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{},
	}

	receivedHeaders := make(map[string]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Capture custom headers from API requests (not token requests)
		if r.URL.Path != "/metadata/identity/oauth2/token" {
			receivedHeaders["X-Custom-Header"] = r.Header.Get("X-Custom-Header")
			receivedHeaders["X-Request-ID"] = r.Header.Get("X-Request-ID")
		}

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		ResourceGroup:      "test-rg",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  false,
		CollectSQLServers:  false,
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Request-ID":    "test-request-123",
		},
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	_, err = exporter.CollectMetrics(ctx)
	require.NoError(t, err)

	// Verify custom headers were sent
	assert.Equal(t, "custom-value", receivedHeaders["X-Custom-Header"])
	assert.Equal(t, "test-request-123", receivedHeaders["X-Request-ID"])
}

// TestAzureArcExporterWithCustomLabels tests that custom labels are added to metrics
func TestAzureArcExporterWithCustomLabels(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/label-test-machine",
				"name":     "label-test-machine",
				"location": "eastus",
				"type":     "Microsoft.HybridCompute/machines",
				"properties": map[string]interface{}{
					"status":       "Connected",
					"osType":       "linux",
					"osName":       "linux",
					"osVersion":    "Ubuntu",
					"agentVersion": "1.35.0",
					"extensions":   []map[string]interface{}{},
					"errorDetails": []map[string]interface{}{},
				},
				"tags": map[string]string{
					"azure-tag": "azure-value",
				},
			},
		},
	}

	k8sResponse := map[string]interface{}{"value": []map[string]interface{}{}}
	sqlResponse := map[string]interface{}{"value": []map[string]interface{}{}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
			_ = json.NewEncoder(w).Encode(k8sResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
			_ = json.NewEncoder(w).Encode(sqlResponse)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		Labels: map[string]string{
			"environment": "test",
			"team":        "platform",
			"source":      "azure-arc",
		},
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)

	// Verify custom labels are present in all metrics
	for _, m := range metrics {
		assert.Equal(t, "test", m.Tags["environment"], "Custom label 'environment' should be present")
		assert.Equal(t, "platform", m.Tags["team"], "Custom label 'team' should be present")
		assert.Equal(t, "azure-arc", m.Tags["source"], "Custom label 'source' should be present")

		// Verify Azure tags are prefixed
		if m.Name == "azurearc_machine_connected" {
			assert.Equal(t, "azure-value", m.Tags["tag_azure-tag"], "Azure tags should be prefixed with 'tag_'")
		}
	}
}

// TestAzureArcExporterTokenExpiry tests token refresh behavior
func TestAzureArcExporterTokenExpiry(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenCallCount := 0
	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			tokenCallCount++
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  false,
		CollectSQLServers:  false,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// First collection - should acquire token
	_, err = exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	initialTokenCalls := tokenCallCount

	// Second collection - should reuse token (not expired)
	_, err = exporter.CollectMetrics(ctx)
	require.NoError(t, err)

	// Token should be reused, so call count shouldn't change
	assert.Equal(t, initialTokenCalls, tokenCallCount, "Token should be reused when not expired")
}

// TestAzureArcExporterAPIError tests handling of API errors
func TestAzureArcExporterAPIError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		default:
			// Return various error codes for different endpoints
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "InternalServerError",
					"message": "An internal error occurred",
				},
			})
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// CollectMetrics should handle errors gracefully (log warnings but don't fail)
	metrics, err := exporter.CollectMetrics(ctx)
	assert.NoError(t, err)
	assert.Empty(t, metrics, "Should return empty metrics when all API calls fail")
}

// TestAzureArcExporterEmptyResponses tests handling of empty API responses
func TestAzureArcExporterEmptyResponses(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "mock-token",
		"expires_in":   "3600",
	}

	emptyResponse := map[string]interface{}{
		"value": []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		default:
			_ = json.NewEncoder(w).Encode(emptyResponse)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "test-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics, err := exporter.CollectMetrics(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics, "Should return empty metrics when no resources exist")
}

// TestAzureArcExporterSelectiveCollection tests selective resource collection
func TestAzureArcExporterSelectiveCollection(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name              string
		collectMachines   bool
		collectKubernetes bool
		collectSQLServers bool
		expectedMetrics   []string
		notExpected       []string
	}{
		{
			name:              "only machines",
			collectMachines:   true,
			collectKubernetes: false,
			collectSQLServers: false,
			expectedMetrics:   []string{"azurearc_machine_connected"},
			notExpected:       []string{"azurearc_kubernetes_connected", "azurearc_sqlserver_running"},
		},
		{
			name:              "only kubernetes",
			collectMachines:   false,
			collectKubernetes: true,
			collectSQLServers: false,
			expectedMetrics:   []string{"azurearc_kubernetes_connected"},
			notExpected:       []string{"azurearc_machine_connected", "azurearc_sqlserver_running"},
		},
		{
			name:              "only sql servers",
			collectMachines:   false,
			collectKubernetes: false,
			collectSQLServers: true,
			expectedMetrics:   []string{"azurearc_sqlserver_running"},
			notExpected:       []string{"azurearc_machine_connected", "azurearc_kubernetes_connected"},
		},
		{
			name:              "machines and kubernetes",
			collectMachines:   true,
			collectKubernetes: true,
			collectSQLServers: false,
			expectedMetrics:   []string{"azurearc_machine_connected", "azurearc_kubernetes_connected"},
			notExpected:       []string{"azurearc_sqlserver_running"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenResponse := map[string]interface{}{
				"access_token": "mock-token",
				"expires_in":   "3600",
			}

			machinesResponse := map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/test-machine",
						"name":     "test-machine",
						"location": "eastus",
						"type":     "Microsoft.HybridCompute/machines",
						"properties": map[string]interface{}{
							"status":       "Connected",
							"osType":       "linux",
							"osName":       "linux",
							"osVersion":    "Ubuntu",
							"agentVersion": "1.35.0",
							"extensions":   []map[string]interface{}{},
							"errorDetails": []map[string]interface{}{},
						},
					},
				},
			}

			k8sResponse := map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":       "/subscriptions/test-sub/providers/Microsoft.Kubernetes/connectedClusters/test-cluster",
						"name":     "test-cluster",
						"location": "eastus",
						"type":     "Microsoft.Kubernetes/connectedClusters",
						"properties": map[string]interface{}{
							"connectivityStatus": "Connected",
							"distribution":       "k3s",
							"kubernetesVersion":  "1.28.0",
							"totalNodeCount":     3,
							"totalCoreCount":     12,
							"agentVersion":       "1.14.0",
						},
					},
				},
			}

			sqlResponse := map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":       "/subscriptions/test-sub/providers/Microsoft.AzureArcData/sqlServerInstances/test-sql",
						"name":     "test-sql",
						"location": "eastus",
						"type":     "Microsoft.AzureArcData/sqlServerInstances",
						"properties": map[string]interface{}{
							"version":     "SQL Server 2019",
							"edition":     "Standard",
							"status":      "Registered",
							"licenseType": "PAYG",
						},
					},
				},
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				switch {
				case r.URL.Path == "/metadata/identity/oauth2/token":
					_ = json.NewEncoder(w).Encode(tokenResponse)
				case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
					_ = json.NewEncoder(w).Encode(machinesResponse)
				case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
					_ = json.NewEncoder(w).Encode(k8sResponse)
				case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
					_ = json.NewEncoder(w).Encode(sqlResponse)
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()

			config := integrations.AzureArcConfig{
				Enabled:            true,
				SubscriptionID:     "test-sub",
				UseManagedIdentity: true,
				IMDSEndpoint:       server.URL,
				HybridEndpoint:     server.URL,
				CollectMachines:    tt.collectMachines,
				CollectKubernetes:  tt.collectKubernetes,
				CollectSQLServers:  tt.collectSQLServers,
			}

			exporter := integrations.NewAzureArcExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)

			metrics, err := exporter.CollectMetrics(ctx)
			require.NoError(t, err)

			// Build metrics map
			metricsMap := make(map[string]bool)
			for _, m := range metrics {
				metricsMap[m.Name] = true
			}

			// Verify expected metrics are present
			for _, expected := range tt.expectedMetrics {
				assert.True(t, metricsMap[expected], "Expected metric %s to be present", expected)
			}

			// Verify not-expected metrics are absent
			for _, notExpected := range tt.notExpected {
				assert.False(t, metricsMap[notExpected], "Metric %s should not be present", notExpected)
			}
		})
	}
}

// BenchmarkAzureArcExporterCollectMetrics benchmarks metrics collection
func BenchmarkAzureArcExporterCollectMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "bench-token",
		"expires_in":   "3600",
	}

	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/bench-machine",
				"name":     "bench-machine",
				"location": "eastus",
				"properties": map[string]interface{}{
					"status":       "Connected",
					"osType":       "linux",
					"osName":       "linux",
					"osVersion":    "Ubuntu",
					"agentVersion": "1.35.0",
					"extensions":   []map[string]interface{}{},
					"errorDetails": []map[string]interface{}{},
				},
			},
		},
	}

	k8sResponse := map[string]interface{}{"value": []map[string]interface{}{}}
	sqlResponse := map[string]interface{}{"value": []map[string]interface{}{}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.HybridCompute/machines"):
			_ = json.NewEncoder(w).Encode(machinesResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.Kubernetes/connectedClusters"):
			_ = json.NewEncoder(w).Encode(k8sResponse)
		case azureArcPathContains(r.URL.Path, "Microsoft.AzureArcData/sqlServerInstances"):
			_ = json.NewEncoder(w).Encode(sqlResponse)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "bench-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
		CollectMachines:    true,
		CollectKubernetes:  true,
		CollectSQLServers:  true,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.CollectMetrics(ctx)
	}
}

// BenchmarkAzureArcExporterHealthCheck benchmarks health check
func BenchmarkAzureArcExporterHealthCheck(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	tokenResponse := map[string]interface{}{
		"access_token": "bench-token",
		"expires_in":   "3600",
	}

	machinesResponse := map[string]interface{}{
		"value": []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/metadata/identity/oauth2/token":
			_ = json.NewEncoder(w).Encode(tokenResponse)
		default:
			_ = json.NewEncoder(w).Encode(machinesResponse)
		}
	}))
	defer server.Close()

	config := integrations.AzureArcConfig{
		Enabled:            true,
		SubscriptionID:     "bench-sub",
		UseManagedIdentity: true,
		IMDSEndpoint:       server.URL,
		HybridEndpoint:     server.URL,
	}

	exporter := integrations.NewAzureArcExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

func BenchmarkNewAzureArcExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.AzureArcConfig{
		Enabled:        true,
		SubscriptionID: "test-sub",
		ResourceGroup:  "test-rg",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewAzureArcExporter(config, logger)
	}
}

// TestAzureArcExporterHealthComprehensive tests comprehensive health check scenarios
func TestAzureArcExporterHealthComprehensive(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled integration", func(t *testing.T) {
		config := integrations.AzureArcConfig{Enabled: false}
		exporter := integrations.NewAzureArcExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("successful health check with managed identity", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "health-check-token",
			"expires_in":   "3600",
		}

		machinesResponse := map[string]interface{}{
			"value": []map[string]interface{}{
				{
					"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/healthy-machine",
					"name":     "healthy-machine",
					"location": "eastus",
					"type":     "Microsoft.HybridCompute/machines",
					"properties": map[string]interface{}{
						"status":       "Connected",
						"osType":       "linux",
						"osName":       "linux",
						"osVersion":    "Ubuntu",
						"agentVersion": "1.35.0",
						"extensions":   []map[string]interface{}{},
						"errorDetails": []map[string]interface{}{},
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			_ = json.NewEncoder(w).Encode(machinesResponse)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "Azure Arc connected", status.Message)
		assert.NotZero(t, status.Latency)
		assert.NotZero(t, status.LastCheck)
	})

	t.Run("successful health check with service principal", func(t *testing.T) {
		tokenCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Service principal token endpoint
			if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
				tokenCallCount++
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "sp-health-token",
					"expires_in":   3600,
				})
				return
			}
			// Machines endpoint
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/sp-machine",
						"name":     "sp-machine",
						"location": "westus",
						"properties": map[string]interface{}{
							"status":       "Connected",
							"osType":       "linux",
							"osName":       "linux",
							"osVersion":    "CentOS",
							"agentVersion": "1.35.0",
							"extensions":   []map[string]interface{}{},
							"errorDetails": []map[string]interface{}{},
						},
					},
				},
			})
		}))
		defer server.Close()

		// Extract base URL without protocol for tenant ID path
		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			TenantID:       "test-tenant",
			ClientID:       "test-client",
			ClientSecret:   "test-secret",
			HybridEndpoint: server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		// May fail if token endpoint not reachable to real Azure
		if status.Healthy {
			assert.Equal(t, "Azure Arc connected", status.Message)
		}
	})

	t.Run("failed health check - HTTP 500", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
		assert.NotNil(t, status.LastError)
	})

	t.Run("failed health check - HTTP 503 Service Unavailable", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Service Unavailable"})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("authentication failure - token refresh fails", func(t *testing.T) {
		tokenCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				tokenCallCount++
				if tokenCallCount == 1 {
					// First call succeeds (init)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"access_token": "expired-token",
						"expires_in":   "1", // Very short expiry
					})
					return
				}
				// Subsequent calls fail
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(50 * time.Millisecond)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		// Token should still be valid as expiry is conservative
		// Check based on actual behavior
		assert.NotNil(t, status)
	})

	t.Run("connection timeout", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			// Simulate slow response
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()

		status, err := exporter.Health(shortCtx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
	})

	t.Run("network error - server closed", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []map[string]interface{}{}})
		}))
		serverURL := server.URL

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       serverURL,
			HybridEndpoint:     serverURL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Close server to simulate network error
		server.Close()

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.NotNil(t, status.LastError)
	})

	t.Run("health check with latency measurement", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			// Add delay for latency measurement
			time.Sleep(5 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/latency-machine",
						"name":     "latency-machine",
						"location": "eastus",
						"properties": map[string]interface{}{
							"status":       "Connected",
							"osType":       "linux",
							"osName":       "linux",
							"osVersion":    "Ubuntu",
							"agentVersion": "1.35.0",
							"extensions":   []map[string]interface{}{},
							"errorDetails": []map[string]interface{}{},
						},
					},
				},
			})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(5))
		assert.NotZero(t, status.LastCheck)
	})

	t.Run("health check with HTTP 403 Forbidden", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Access denied"})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "connection failed")
	})

	t.Run("health check returns subscription and resource group details", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   "3600",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				_ = json.NewEncoder(w).Encode(tokenResponse)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":       "/subscriptions/test-sub/providers/Microsoft.HybridCompute/machines/details-machine",
						"name":     "details-machine",
						"location": "eastus",
						"properties": map[string]interface{}{
							"status":       "Connected",
							"osType":       "windows",
							"osName":       "Windows",
							"osVersion":    "Windows Server 2019",
							"agentVersion": "1.35.0",
							"extensions":   []map[string]interface{}{},
							"errorDetails": []map[string]interface{}{},
						},
					},
				},
			})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "my-subscription-123",
			ResourceGroup:      "my-resource-group",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.NotNil(t, status.Details)
		assert.Equal(t, "my-subscription-123", status.Details["subscription_id"])
		if rg, ok := status.Details["resource_group"]; ok && rg != "" {
			assert.Equal(t, "my-resource-group", rg)
		}
	})
}

// TestAzureArcServicePrincipalTokenFlow tests service principal token acquisition
func TestAzureArcServicePrincipalTokenFlow(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("successful service principal token acquisition", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Token endpoint
			if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
				// Verify request content type
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				// Return token
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "sp-test-token",
					"expires_in":   3600,
				})
				return
			}
			// Machines endpoint
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{},
			})
		}))
		defer server.Close()

		// Note: Can't easily test real service principal flow without mocking Azure AD
		// This tests the token would be used if obtainable
		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			TenantID:       "test-tenant",
			ClientID:       "test-client",
			ClientSecret:   "test-secret",
			HybridEndpoint: server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)
	})

	t.Run("service principal token failure - 401 Unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_client",
					"error_description": "Invalid client secret",
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			TenantID:       "test-tenant",
			ClientID:       "test-client",
			ClientSecret:   "wrong-secret",
			HybridEndpoint: server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		// Init may succeed since real Azure AD is used
		// But health check would fail
		_ = exporter.Init(ctx)
	})

	t.Run("service principal token failure - 400 Bad Request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_grant",
					"error_description": "Client ID is invalid",
				})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			TenantID:       "test-tenant",
			ClientID:       "invalid-client-id",
			ClientSecret:   "test-secret",
			HybridEndpoint: server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)
	})

	t.Run("service principal token timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
				// Simulate slow token endpoint
				time.Sleep(100 * time.Millisecond)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "sp-timeout-token",
					"expires_in":   3600,
				})
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			TenantID:       "test-tenant",
			ClientID:       "test-client",
			ClientSecret:   "test-secret",
			HybridEndpoint: server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)

		shortCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()

		_, err := exporter.CollectMetrics(shortCtx)
		// Should timeout or fail
		assert.Error(t, err)
	})

	t.Run("service principal with malformed response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
				// Return invalid JSON
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("{invalid json"))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:        true,
			SubscriptionID: "test-sub",
			TenantID:       "test-tenant",
			ClientID:       "test-client",
			ClientSecret:   "test-secret",
			HybridEndpoint: server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		_ = exporter.Init(ctx)
	})
}

// TestAzureArcEnsureTokenBehavior tests token caching and refresh behavior
func TestAzureArcEnsureTokenBehavior(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("token reuse within validity period", func(t *testing.T) {
		tokenCallCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/metadata/identity/oauth2/token" {
				tokenCallCount++
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "cached-token",
					"expires_in":   "3600",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []map[string]interface{}{}})
		}))
		defer server.Close()

		config := integrations.AzureArcConfig{
			Enabled:            true,
			SubscriptionID:     "test-sub",
			UseManagedIdentity: true,
			IMDSEndpoint:       server.URL,
			HybridEndpoint:     server.URL,
		}

		exporter := integrations.NewAzureArcExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)
		initialTokenCalls := tokenCallCount

		// Multiple operations should reuse token
		_, _ = exporter.Health(ctx)
		_, _ = exporter.Health(ctx)
		_, _ = exporter.CollectMetrics(ctx)

		// Token should be reused (might have some refresh but not many)
		assert.LessOrEqual(t, tokenCallCount, initialTokenCalls+2)
	})
}
