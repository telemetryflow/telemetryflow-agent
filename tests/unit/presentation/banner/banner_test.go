// Package banner_test contains unit tests for the startup banner renderer
// verifying product name, version, and vendor information output.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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
package banner_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telemetryflow/telemetryflow-agent/pkg/banner"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("should return valid default configuration", func(t *testing.T) {
		cfg := banner.DefaultConfig()

		assert.Equal(t, "TelemetryFlow Agent", cfg.ProductName)
		assert.Equal(t, "1.2.0", cfg.Version)
		assert.Equal(t, "Community Enterprise Observability Platform (CEOP)", cfg.Motto)
		assert.Equal(t, "TelemetryFlow", cfg.Vendor)
		assert.Equal(t, "Telemetri Data Indonesia", cfg.Developer)
		assert.Equal(t, "Apache-2.0", cfg.License)
	})
}

func TestGenerate(t *testing.T) {
	t.Run("should generate banner with all fields", func(t *testing.T) {
		cfg := banner.Config{
			ProductName: "Test Product",
			Version:     "1.2.0",
			Motto:       "Test Motto",
			GitCommit:   "abc123",
			BuildTime:   "2024-01-01",
			GoVersion:   "1.24.0",
			Platform:    "linux/amd64",
			Vendor:      "Test Vendor",
			VendorURL:   "https://test.com",
			Developer:   "Test Developer",
			License:     "MIT",
			SupportURL:  "https://support.test.com",
			Copyright:   "Copyright Test",
		}

		generatedBanner := banner.Generate(cfg)

		assert.Contains(t, generatedBanner, "Test Product")
		assert.Contains(t, generatedBanner, "1.2.0")
		assert.Contains(t, generatedBanner, "Test Motto")
		assert.Contains(t, generatedBanner, "abc123")
		assert.Contains(t, generatedBanner, "2024-01-01")
		assert.Contains(t, generatedBanner, "1.24.0")
		assert.Contains(t, generatedBanner, "linux/amd64")
		assert.Contains(t, generatedBanner, "Test Vendor")
		assert.Contains(t, generatedBanner, "Test Developer")
		assert.Contains(t, generatedBanner, "MIT")
		assert.Contains(t, generatedBanner, "Copyright Test")
	})

	t.Run("should contain ASCII art", func(t *testing.T) {
		cfg := banner.DefaultConfig()
		generatedBanner := banner.Generate(cfg)

		assert.Contains(t, generatedBanner, "Telemetry")
		assert.Contains(t, generatedBanner, "Flow")
		assert.Contains(t, generatedBanner, "Agent")
	})

	t.Run("should contain separator lines", func(t *testing.T) {
		cfg := banner.DefaultConfig()
		generatedBanner := banner.Generate(cfg)

		assert.Contains(t, generatedBanner, strings.Repeat("═", 78))
		assert.Contains(t, generatedBanner, strings.Repeat("─", 78))
	})
}

func TestGenerateCompact(t *testing.T) {
	t.Run("should generate compact banner", func(t *testing.T) {
		cfg := banner.Config{
			ProductName: "Test Product",
			Version:     "1.2.0",
			Motto:       "Test Motto",
			Copyright:   "Copyright Test",
		}

		compactBanner := banner.GenerateCompact(cfg)

		assert.Contains(t, compactBanner, "Test Product")
		assert.Contains(t, compactBanner, "1.2.0")
		assert.Contains(t, compactBanner, "Test Motto")
		assert.Contains(t, compactBanner, "Copyright Test")
	})

	t.Run("compact banner should be shorter than full banner", func(t *testing.T) {
		cfg := banner.DefaultConfig()

		fullBanner := banner.Generate(cfg)
		compactBanner := banner.GenerateCompact(cfg)

		assert.Less(t, len(compactBanner), len(fullBanner))
	})
}

func TestBannerContent(t *testing.T) {
	t.Run("should have multiple lines", func(t *testing.T) {
		cfg := banner.DefaultConfig()
		generatedBanner := banner.Generate(cfg)

		lines := strings.Split(generatedBanner, "\n")
		assert.Greater(t, len(lines), 10)
	})

	t.Run("should start with separator", func(t *testing.T) {
		cfg := banner.DefaultConfig()
		generatedBanner := banner.Generate(cfg)

		assert.True(t, strings.HasPrefix(generatedBanner, "\n"))
	})
}
