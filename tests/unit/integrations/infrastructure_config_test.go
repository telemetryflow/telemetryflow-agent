// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
)

func TestInfrastructureConfigDefaults(t *testing.T) {
	t.Run("proxmox defaults", func(t *testing.T) {
		config := integrations.ProxmoxConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.APIUrl)
	})

	t.Run("vmware defaults", func(t *testing.T) {
		config := integrations.VMwareConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.VCenterURL)
	})

	t.Run("nutanix defaults", func(t *testing.T) {
		config := integrations.NutanixConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.PrismCentralURL)
	})

	t.Run("azurearc defaults", func(t *testing.T) {
		config := integrations.AzureArcConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.SubscriptionID)
	})
}

// Benchmark tests
