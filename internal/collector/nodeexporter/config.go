// Package nodeexporter provides a prometheus/node_exporter-equivalent collector.
// When enabled, it exposes detailed system metrics (per-CPU, per-device,
// per-interface, per-mount) as continuous time-series that flow through
// OTLP export and the Prometheus /metrics endpoint.
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
package nodeexporter

import (
	"regexp"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// collectorConfig holds parsed configuration for sub-collectors.
type collectorConfig struct {
	raw config.NodeExporterConfig

	// Compiled regex filters
	filesystemMountExclude *regexp.Regexp
	filesystemTypeExclude  *regexp.Regexp
	networkDeviceExclude   *regexp.Regexp
	diskDeviceExclude      *regexp.Regexp
}

// newCollectorConfig parses and compiles configuration.
func newCollectorConfig(cfg config.NodeExporterConfig, logger *zap.Logger) *collectorConfig {
	cc := &collectorConfig{raw: cfg}

	cc.filesystemMountExclude = compileRegex(cfg.FilesystemMountExclude, "filesystem_mount_exclude", logger)
	cc.filesystemTypeExclude = compileRegex(cfg.FilesystemTypeExclude, "filesystem_type_exclude", logger)
	cc.networkDeviceExclude = compileRegex(cfg.NetworkDeviceExclude, "network_device_exclude", logger)
	cc.diskDeviceExclude = compileRegex(cfg.DiskDeviceExclude, "disk_device_exclude", logger)

	return cc
}

// compileRegex compiles a regex pattern, returning nil on empty or invalid patterns.
func compileRegex(pattern, name string, logger *zap.Logger) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		logger.Warn("Invalid regex pattern, ignoring",
			zap.String("field", name),
			zap.String("pattern", pattern),
			zap.Error(err),
		)
		return nil
	}
	return re
}

// shouldExcludeDevice checks if a device name matches the exclusion regex.
func (c *collectorConfig) shouldExcludeDisk(device string) bool {
	return c.diskDeviceExclude != nil && c.diskDeviceExclude.MatchString(device)
}

// shouldExcludeNetworkDevice checks if a network interface matches the exclusion regex.
func (c *collectorConfig) shouldExcludeNetworkDevice(device string) bool {
	return c.networkDeviceExclude != nil && c.networkDeviceExclude.MatchString(device)
}

// shouldExcludeMount checks if a mount point matches the exclusion regex.
func (c *collectorConfig) shouldExcludeMount(mountpoint string) bool {
	return c.filesystemMountExclude != nil && c.filesystemMountExclude.MatchString(mountpoint)
}

// shouldExcludeFSType checks if a filesystem type matches the exclusion regex.
func (c *collectorConfig) shouldExcludeFSType(fstype string) bool {
	return c.filesystemTypeExclude != nil && c.filesystemTypeExclude.MatchString(fstype)
}
