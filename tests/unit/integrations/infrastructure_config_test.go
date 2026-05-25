// Package integrations_test contains unit tests for every third-party
// integration exporter verifying payload construction and error handling.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
