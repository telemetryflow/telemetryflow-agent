// Package agent_test provides unit tests for the version package.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package agent_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

func TestProductConstants(t *testing.T) {
	t.Run("should have correct product name", func(t *testing.T) {
		assert.Equal(t, "TelemetryFlow Agent", version.ProductName)
	})

	t.Run("should have correct short name", func(t *testing.T) {
		assert.Equal(t, "tfo-agent", version.ProductShortName)
	})

	t.Run("should have valid vendor info", func(t *testing.T) {
		assert.Equal(t, "TelemetryFlow", version.Vendor)
		assert.NotEmpty(t, version.VendorURL)
	})

	t.Run("should have valid developer info", func(t *testing.T) {
		assert.Equal(t, "DevOpsCorner Indonesia", version.Developer)
		assert.NotEmpty(t, version.DeveloperURL)
	})

	t.Run("should have Apache-2.0 license", func(t *testing.T) {
		assert.Equal(t, "Apache-2.0", version.License)
		assert.Contains(t, version.LicenseURL, "apache.org")
	})
}

func TestVersionInfo(t *testing.T) {
	t.Run("should return complete version info", func(t *testing.T) {
		info := version.Get()

		assert.Equal(t, version.ProductName, info.Product)
		assert.Equal(t, version.ProductDescription, info.Description)
		assert.NotEmpty(t, info.Version)
		assert.NotEmpty(t, info.GoVersion)
		assert.Equal(t, runtime.GOOS, info.OS)
		assert.Equal(t, runtime.GOARCH, info.Arch)
		assert.Equal(t, version.Vendor, info.Vendor)
		assert.Equal(t, version.Developer, info.Developer)
		assert.Equal(t, version.License, info.License)
	})

	t.Run("should have valid OS and architecture", func(t *testing.T) {
		info := version.Get()

		validOS := []string{"linux", "darwin", "windows"}
		validArch := []string{"amd64", "arm64", "386", "arm"}

		assert.Contains(t, validOS, info.OS)
		assert.Contains(t, validArch, info.Arch)
	})
}

func TestShort(t *testing.T) {
	t.Run("should return version string", func(t *testing.T) {
		short := version.Short()

		assert.NotEmpty(t, short)
		// Version should be semantic versioning format
		assert.Regexp(t, `^\d+\.\d+\.\d+`, short)
	})
}

func TestString(t *testing.T) {
	t.Run("should return formatted version string", func(t *testing.T) {
		str := version.String()

		assert.Contains(t, str, version.ProductName)
		assert.Contains(t, str, version.Short())
		assert.Contains(t, str, version.Vendor)
		assert.Contains(t, str, version.Developer)
		assert.Contains(t, str, version.License)
	})

	t.Run("should contain build information", func(t *testing.T) {
		str := version.String()

		assert.Contains(t, str, "Build Information")
		assert.Contains(t, str, "Go Version")
		assert.Contains(t, str, "Platform")
	})
}

func TestBanner(t *testing.T) {
	t.Run("should return ASCII art banner", func(t *testing.T) {
		banner := version.Banner()

		assert.NotEmpty(t, banner)
		// Banner should contain product name
		assert.Contains(t, banner, version.ProductName)
		// Banner should contain version
		assert.Contains(t, banner, version.Short())
	})

	t.Run("should contain branding info", func(t *testing.T) {
		banner := version.Banner()

		assert.Contains(t, banner, version.Vendor)
		assert.Contains(t, banner, version.Developer)
		assert.Contains(t, banner, version.License)
	})

	t.Run("should be multi-line", func(t *testing.T) {
		banner := version.Banner()
		lines := strings.Split(banner, "\n")

		// Banner should have multiple lines (ASCII art)
		assert.Greater(t, len(lines), 10)
	})
}

func TestOneLiner(t *testing.T) {
	t.Run("should return single-line version", func(t *testing.T) {
		oneLiner := version.OneLiner()

		// Should not contain newlines
		assert.NotContains(t, oneLiner, "\n")

		// Should contain key info
		assert.Contains(t, oneLiner, version.ProductName)
		assert.Contains(t, oneLiner, version.Short())
		assert.Contains(t, oneLiner, runtime.GOOS)
		assert.Contains(t, oneLiner, runtime.GOARCH)
	})
}

func TestUserAgent(t *testing.T) {
	t.Run("should return valid HTTP User-Agent string", func(t *testing.T) {
		ua := version.UserAgent()

		// Format: tfo-agent/1.0.0 (linux; amd64)
		assert.Contains(t, ua, version.ProductShortName)
		assert.Contains(t, ua, version.Short())
		assert.Contains(t, ua, runtime.GOOS)
		assert.Contains(t, ua, runtime.GOARCH)
	})

	t.Run("should be single line without special characters", func(t *testing.T) {
		ua := version.UserAgent()

		assert.NotContains(t, ua, "\n")
		assert.NotContains(t, ua, "\r")
	})
}

func TestGetMotto(t *testing.T) {
	t.Run("should return product motto", func(t *testing.T) {
		motto := version.GetMotto()

		assert.NotEmpty(t, motto)
		assert.Equal(t, version.Motto, motto)
		assert.Contains(t, motto, "CEOP")
	})
}

func TestGetProductInfo(t *testing.T) {
	t.Run("should return product info string", func(t *testing.T) {
		info := version.GetProductInfo()

		assert.Contains(t, info, version.ProductName)
		assert.Contains(t, info, version.ProductDescription)
	})
}

func TestGetSupportInfo(t *testing.T) {
	t.Run("should return support URL", func(t *testing.T) {
		support := version.GetSupportInfo()

		assert.Contains(t, support, version.SupportURL)
	})
}

func TestBuildVariables(t *testing.T) {
	t.Run("should have default values when not set via ldflags", func(t *testing.T) {
		info := version.Get()

		// When not built with ldflags, these should be "unknown" or default values
		// This tests the fallback behavior
		assert.NotEmpty(t, info.Version)
		assert.NotEmpty(t, info.GoVersion)
	})

	t.Run("GoVersion should match runtime", func(t *testing.T) {
		info := version.Get()

		assert.Equal(t, runtime.Version(), info.GoVersion)
	})
}

func TestFull(t *testing.T) {
	t.Run("should return full version info", func(t *testing.T) {
		full := version.Full()
		assert.NotEmpty(t, full)
		assert.Contains(t, full, version.ProductName)
	})
}

func TestBuildInfo(t *testing.T) {
	t.Run("should return build information map", func(t *testing.T) {
		info := version.BuildInfo()

		assert.NotNil(t, info)
		assert.Contains(t, info, "version")
		assert.Contains(t, info, "product_name")
	})

	t.Run("should have git information", func(t *testing.T) {
		info := version.BuildInfo()

		assert.Contains(t, info, "git_commit")
		assert.Contains(t, info, "git_branch")
	})

	t.Run("should have build time", func(t *testing.T) {
		info := version.BuildInfo()

		assert.Contains(t, info, "build_time")
	})
}
