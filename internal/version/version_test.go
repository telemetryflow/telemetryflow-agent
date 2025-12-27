// Package version provides version information tests for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package version

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConstants(t *testing.T) {
	t.Run("should have correct product name", func(t *testing.T) {
		assert.Equal(t, "TelemetryFlow Agent", ProductName)
	})

	t.Run("should have correct short name", func(t *testing.T) {
		assert.Equal(t, "tfo-agent", ProductShortName)
	})

	t.Run("should have correct vendor", func(t *testing.T) {
		assert.Equal(t, "TelemetryFlow", Vendor)
	})

	t.Run("should have correct developer", func(t *testing.T) {
		assert.Equal(t, "DevOpsCorner Indonesia", Developer)
	})

	t.Run("should have correct license", func(t *testing.T) {
		assert.Equal(t, "Apache-2.0", License)
	})

	t.Run("should have correct OTEL SDK version", func(t *testing.T) {
		assert.Equal(t, "1.39.0", OTELSDKVersion)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return full version info", func(t *testing.T) {
		info := Get()

		assert.Equal(t, ProductName, info.Product)
		assert.Equal(t, ProductDescription, info.Description)
		assert.Equal(t, Version, info.Version)
		assert.Equal(t, OTELSDKVersion, info.OTELSDKVersion)
		assert.Equal(t, GitCommit, info.GitCommit)
		assert.Equal(t, GitBranch, info.GitBranch)
		assert.Equal(t, BuildTime, info.BuildTime)
		assert.Equal(t, GoVersion, info.GoVersion)
		assert.Equal(t, runtime.GOOS, info.OS)
		assert.Equal(t, runtime.GOARCH, info.Arch)
		assert.Equal(t, Vendor, info.Vendor)
		assert.Equal(t, Developer, info.Developer)
		assert.Equal(t, License, info.License)
	})
}

func TestString(t *testing.T) {
	t.Run("should contain product name and version", func(t *testing.T) {
		str := String()

		assert.Contains(t, str, ProductName)
		assert.Contains(t, str, Version)
		assert.Contains(t, str, OTELSDKVersion)
	})

	t.Run("should contain build information", func(t *testing.T) {
		str := String()

		assert.Contains(t, str, "Commit")
		assert.Contains(t, str, "Branch")
		assert.Contains(t, str, "Built")
		assert.Contains(t, str, "Go Version")
	})

	t.Run("should contain vendor information", func(t *testing.T) {
		str := String()

		assert.Contains(t, str, Vendor)
		assert.Contains(t, str, Developer)
		assert.Contains(t, str, License)
	})
}

func TestShort(t *testing.T) {
	t.Run("should return just version number", func(t *testing.T) {
		short := Short()

		assert.Equal(t, Version, short)
	})
}

func TestUserAgent(t *testing.T) {
	t.Run("should return formatted user agent", func(t *testing.T) {
		ua := UserAgent()

		assert.Contains(t, ua, ProductShortName)
		assert.Contains(t, ua, Version)
		assert.Contains(t, ua, runtime.GOOS)
		assert.Contains(t, ua, runtime.GOARCH)
	})

	t.Run("should follow standard format", func(t *testing.T) {
		ua := UserAgent()

		// Format: product/version (os; arch)
		assert.True(t, strings.HasPrefix(ua, ProductShortName+"/"))
	})
}

func TestBanner(t *testing.T) {
	t.Run("should contain ASCII art", func(t *testing.T) {
		banner := Banner()

		assert.Contains(t, banner, "Telemetry")
		assert.Contains(t, banner, "Flow")
		assert.Contains(t, banner, "Agent")
	})

	t.Run("should contain version information", func(t *testing.T) {
		banner := Banner()

		assert.Contains(t, banner, ProductName)
		assert.Contains(t, banner, Version)
		assert.Contains(t, banner, OTELSDKVersion)
	})

	t.Run("should contain vendor information", func(t *testing.T) {
		banner := Banner()

		assert.Contains(t, banner, Vendor)
		assert.Contains(t, banner, Developer)
		assert.Contains(t, banner, Copyright)
	})

	t.Run("should contain separator lines", func(t *testing.T) {
		banner := Banner()

		assert.Contains(t, banner, "═")
		assert.Contains(t, banner, "─")
	})
}

func TestOneLiner(t *testing.T) {
	t.Run("should return single line format", func(t *testing.T) {
		oneLiner := OneLiner()

		// Should not contain newlines
		assert.NotContains(t, oneLiner, "\n")

		// Should contain key information
		assert.Contains(t, oneLiner, ProductName)
		assert.Contains(t, oneLiner, Version)
		assert.Contains(t, oneLiner, Motto)
	})
}

func TestGetMotto(t *testing.T) {
	t.Run("should return motto", func(t *testing.T) {
		motto := GetMotto()

		assert.Equal(t, Motto, motto)
		assert.Contains(t, motto, "CEOP")
	})
}

func TestGetProductInfo(t *testing.T) {
	t.Run("should return formatted product info", func(t *testing.T) {
		info := GetProductInfo()

		assert.Contains(t, info, ProductName)
		assert.Contains(t, info, ProductDescription)
	})
}

func TestGetSupportInfo(t *testing.T) {
	t.Run("should return support URL", func(t *testing.T) {
		info := GetSupportInfo()

		assert.Contains(t, info, SupportURL)
	})
}

func TestFull(t *testing.T) {
	t.Run("should return product name with version", func(t *testing.T) {
		full := Full()

		assert.Contains(t, full, ProductName)
		assert.Contains(t, full, Version)
		assert.True(t, strings.HasPrefix(full, ProductName))
	})
}

func TestBuildInfo(t *testing.T) {
	t.Run("should return map with all build info", func(t *testing.T) {
		info := BuildInfo()

		assert.Equal(t, Version, info["version"])
		assert.Equal(t, ProductName, info["product_name"])
		assert.Equal(t, OTELSDKVersion, info["otel_sdk_version"])
		assert.Equal(t, GitCommit, info["git_commit"])
		assert.Equal(t, GitBranch, info["git_branch"])
		assert.Equal(t, BuildTime, info["build_time"])
		assert.Equal(t, GoVersion, info["go_version"])
		assert.Equal(t, runtime.GOOS, info["os"])
		assert.Equal(t, runtime.GOARCH, info["arch"])
		assert.Equal(t, Vendor, info["vendor"])
		assert.Equal(t, Developer, info["developer"])
		assert.Equal(t, License, info["license"])
	})
}
