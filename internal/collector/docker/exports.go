// Package docker exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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

package docker

import (
	"regexp"

	containertypes "github.com/moby/moby/api/types/container"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func CleanContainerNameExported(names []string) string {
	return cleanContainerName(names)
}

func ContainerLabelsExported(id, name, image, status string) map[string]string {
	return containerLabels(id, name, image, status)
}

func CollectCPUMetricsExported(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	return collectCPUMetrics(stats, labels)
}

func CollectMemoryMetricsExported(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	return collectMemoryMetrics(stats, labels)
}

func CollectNetworkMetricsExported(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	return collectNetworkMetrics(stats, labels)
}

func CollectDiskIOMetricsExported(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	return collectDiskIOMetrics(stats, labels)
}

type CollectorConfigExport struct {
	inner *collectorConfig
}

func NewCollectorConfigExported(cfg config.DockerCollectorConfig, logger *zap.Logger) *CollectorConfigExport {
	return &CollectorConfigExport{inner: newCollectorConfig(cfg, logger)}
}

func (e *CollectorConfigExport) ShouldIncludeContainer(name string) bool {
	return e.inner.shouldIncludeContainer(name)
}

func (e *CollectorConfigExport) IncludeCount() int           { return len(e.inner.includeRe) }
func (e *CollectorConfigExport) ExcludeCount() int           { return len(e.inner.excludeRe) }
func (e *CollectorConfigExport) IncludeRe() []*regexp.Regexp { return e.inner.includeRe }
