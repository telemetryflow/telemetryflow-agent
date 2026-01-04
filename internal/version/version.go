// Package version provides build and version information for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
package version

import (
	"fmt"
	"runtime"
)

// Product information
const (
	// ProductName is the official product name
	ProductName = "TelemetryFlow Agent"

	// ProductShortName is the short name used in CLI
	ProductShortName = "tfo-agent"

	// ProductDescription is the product description
	ProductDescription = "Community Enterprise-grade observability agent for metrics, logs, and traces collection"

	// Motto is the product tagline
	Motto = "Community Enterprise Observability Platform (CEOP)"

	// Vendor is the organization that owns this software
	Vendor = "TelemetryFlow"

	// VendorURL is the official website
	VendorURL = "https://telemetryflow.id"

	// Developer is the organization that built this software
	Developer = "DevOpsCorner Indonesia"

	// DeveloperURL is the developer website
	DeveloperURL = "https://devopscorner.id"

	// Copyright is the copyright notice
	Copyright = "Copyright (c) 2024-2026 DevOpsCorner Indonesia"

	// License is the license type
	License = "Apache-2.0"

	// LicenseURL is the license URL
	LicenseURL = "https://www.apache.org/licenses/LICENSE-2.0"

	// SupportURL is the support documentation URL
	SupportURL = "https://docs.telemetryflow.id"

	// OTELSDKVersion is the OpenTelemetry SDK version this agent is based on
	OTELSDKVersion = "1.39.0"
)

// Build-time variables (set via ldflags)
var (
	// Version is the semantic version of the agent
	Version = "1.1.2"

	// GitCommit is the git commit hash
	GitCommit = "unknown"

	// GitBranch is the git branch name
	GitBranch = "unknown"

	// BuildTime is the UTC build timestamp
	BuildTime = "unknown"

	// GoVersion is the Go version used to build
	GoVersion = runtime.Version()
)

// Info contains full version information
type Info struct {
	Product        string `json:"product"`
	Description    string `json:"description"`
	Version        string `json:"version"`
	OTELSDKVersion string `json:"otel_sdk_version"`
	GitCommit      string `json:"git_commit"`
	GitBranch      string `json:"git_branch"`
	BuildTime      string `json:"build_time"`
	GoVersion      string `json:"go_version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Vendor         string `json:"vendor"`
	VendorURL      string `json:"vendor_url"`
	Developer      string `json:"developer"`
	License        string `json:"license"`
	SupportURL     string `json:"support_url"`
}

// Get returns the full version information
func Get() Info {
	return Info{
		Product:        ProductName,
		Description:    ProductDescription,
		Version:        Version,
		OTELSDKVersion: OTELSDKVersion,
		GitCommit:      GitCommit,
		GitBranch:      GitBranch,
		BuildTime:      BuildTime,
		GoVersion:      GoVersion,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Vendor:         Vendor,
		VendorURL:      VendorURL,
		Developer:      Developer,
		License:        License,
		SupportURL:     SupportURL,
	}
}

// String returns a formatted version string
func String() string {
	return fmt.Sprintf(`%s v%s (OTEL SDK %s)

  Build Information
  ─────────────────────────────────────────────
  Commit:      %s
  Branch:      %s
  Built:       %s
  Go Version:  %s
  Platform:    %s/%s

  Product Information
  ─────────────────────────────────────────────
  Vendor:      %s
  Website:     %s
  Developer:   %s
  License:     %s
  Support:     %s

  %s`,
		ProductName, Version, OTELSDKVersion,
		GitCommit, GitBranch, BuildTime, GoVersion,
		runtime.GOOS, runtime.GOARCH,
		Vendor, VendorURL, Developer, License, SupportURL,
		Copyright)
}

// Short returns just the version number
func Short() string {
	return Version
}

// UserAgent returns the HTTP User-Agent string
func UserAgent() string {
	return fmt.Sprintf("%s/%s (%s; %s)", ProductShortName, Version, runtime.GOOS, runtime.GOARCH)
}

// Banner returns the startup banner for console output
func Banner() string {
	return fmt.Sprintf(`
    ___________    .__                        __
    \__    ___/___ |  |   ____   _____   _____/  |________ ___.__.
      |    |_/ __ \|  | _/ __ \ /     \_/ __ \   __\_  __ <   |  |
      |    |\  ___/|  |_\  ___/|  Y Y  \  ___/|  |  |  | \/\___  |
      |____| \___  >____/\___  >__|_|  /\___  >__|  |__|   / ____|
                 \/          \/      \/     \/             \/
                    ___________.__
                    \_   _____/|  |   ______  _  __
                     |    __)  |  |  /  _ \ \/ \/ /
                     |     \   |  |_(  <_> )     /
                     |___  /   |____/\____/ \/\_/
                         \/
                      _____                         __
                     /  _  \    ____   ____   _____/  |_
                    /  /_\  \  / ___\_/ __ \ /    \   __\
                   /    |    \/ /_/  >  ___/|   |  \  |
                   \____|__  /\___  / \___  >___|  /__|
                           \//_____/      \/     \/

  ══════════════════════════════════════════════════════════════════════════════
    %s v%s (Based on OTEL SDK %s)
    %s
  ══════════════════════════════════════════════════════════════════════════════
    Platform     %s/%s
    Go Version   %s
    Commit       %s
    Built        %s
  ──────────────────────────────────────────────────────────────────────────────
    Vendor       %s (%s)
    Developer    %s
    License      %s
    Support      %s
  ──────────────────────────────────────────────────────────────────────────────
    %s
  ══════════════════════════════════════════════════════════════════════════════

`, ProductName, Version, OTELSDKVersion, Motto,
		runtime.GOOS, runtime.GOARCH, GoVersion, GitCommit, BuildTime,
		Vendor, VendorURL, Developer, License, SupportURL,
		Copyright)
}

// OneLiner returns a single-line version string
func OneLiner() string {
	return fmt.Sprintf("%s v%s (%s/%s) - %s", ProductName, Version, runtime.GOOS, runtime.GOARCH, Motto)
}

// GetMotto returns the product motto
func GetMotto() string {
	return Motto
}

// GetProductInfo returns formatted product information
func GetProductInfo() string {
	return fmt.Sprintf("%s - %s", ProductName, ProductDescription)
}

// GetSupportInfo returns support contact information
func GetSupportInfo() string {
	return fmt.Sprintf("For support, visit: %s", SupportURL)
}

// Full returns the full version string with product name
func Full() string {
	return fmt.Sprintf("%s v%s", ProductName, Version)
}

// BuildInfo returns a map of build information
func BuildInfo() map[string]string {
	return map[string]string{
		"version":          Version,
		"product_name":     ProductName,
		"otel_sdk_version": OTELSDKVersion,
		"git_commit":       GitCommit,
		"git_branch":       GitBranch,
		"build_time":       BuildTime,
		"go_version":       GoVersion,
		"os":               runtime.GOOS,
		"arch":             runtime.GOARCH,
		"vendor":           Vendor,
		"developer":        Developer,
		"license":          License,
	}
}
