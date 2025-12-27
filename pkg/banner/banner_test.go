// Package banner provides ASCII art banner tests for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
package banner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("should return valid default configuration", func(t *testing.T) {
		cfg := DefaultConfig()

		assert.Equal(t, "TelemetryFlow Agent", cfg.ProductName)
		assert.Equal(t, "1.1.0", cfg.Version)
		assert.Equal(t, "Community Enterprise Observability Platform (CEOP)", cfg.Motto)
		assert.Equal(t, "TelemetryFlow", cfg.Vendor)
		assert.Equal(t, "DevOpsCorner Indonesia", cfg.Developer)
		assert.Equal(t, "Apache-2.0", cfg.License)
	})
}

func TestGenerate(t *testing.T) {
	t.Run("should generate banner with all fields", func(t *testing.T) {
		cfg := Config{
			ProductName: "Test Product",
			Version:     "1.0.0",
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

		banner := Generate(cfg)

		assert.Contains(t, banner, "Test Product")
		assert.Contains(t, banner, "1.0.0")
		assert.Contains(t, banner, "Test Motto")
		assert.Contains(t, banner, "abc123")
		assert.Contains(t, banner, "2024-01-01")
		assert.Contains(t, banner, "1.24.0")
		assert.Contains(t, banner, "linux/amd64")
		assert.Contains(t, banner, "Test Vendor")
		assert.Contains(t, banner, "Test Developer")
		assert.Contains(t, banner, "MIT")
		assert.Contains(t, banner, "Copyright Test")
	})

	t.Run("should contain ASCII art", func(t *testing.T) {
		cfg := DefaultConfig()
		banner := Generate(cfg)

		assert.Contains(t, banner, "Telemetry")
		assert.Contains(t, banner, "Flow")
		assert.Contains(t, banner, "Agent")
	})

	t.Run("should contain separator lines", func(t *testing.T) {
		cfg := DefaultConfig()
		banner := Generate(cfg)

		assert.Contains(t, banner, strings.Repeat("═", 78))
		assert.Contains(t, banner, strings.Repeat("─", 78))
	})
}

func TestGenerateCompact(t *testing.T) {
	t.Run("should generate compact banner", func(t *testing.T) {
		cfg := Config{
			ProductName: "Test Product",
			Version:     "1.0.0",
			Motto:       "Test Motto",
			Copyright:   "Copyright Test",
		}

		banner := GenerateCompact(cfg)

		assert.Contains(t, banner, "Test Product")
		assert.Contains(t, banner, "1.0.0")
		assert.Contains(t, banner, "Test Motto")
		assert.Contains(t, banner, "Copyright Test")
	})

	t.Run("compact banner should be shorter than full banner", func(t *testing.T) {
		cfg := DefaultConfig()

		fullBanner := Generate(cfg)
		compactBanner := GenerateCompact(cfg)

		assert.Less(t, len(compactBanner), len(fullBanner))
	})
}
