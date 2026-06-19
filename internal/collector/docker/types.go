// Package docker collects per-container CPU, memory, network, and block-I/O
// metrics by querying the Docker Engine API, implementing the collector.Collector
// interface for seamless pipeline integration.
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

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// collectorConfig holds parsed configuration for the Docker collector.
type collectorConfig struct {
	raw config.DockerCollectorConfig

	// Compiled container name filter regexes
	includeRe []*regexp.Regexp
	excludeRe []*regexp.Regexp
}

// newCollectorConfig parses and validates the Docker collector configuration.
func newCollectorConfig(cfg config.DockerCollectorConfig, logger *zap.Logger) *collectorConfig {
	cc := &collectorConfig{raw: cfg}

	for _, p := range cfg.IncludeContainers {
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("Invalid include_containers pattern, skipping",
				zap.String("pattern", p), zap.Error(err))
			continue
		}
		cc.includeRe = append(cc.includeRe, re)
	}

	for _, p := range cfg.ExcludeContainers {
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("Invalid exclude_containers pattern, skipping",
				zap.String("pattern", p), zap.Error(err))
			continue
		}
		cc.excludeRe = append(cc.excludeRe, re)
	}

	return cc
}

// shouldIncludeContainer returns true if a container name passes the
// include/exclude filters.
func (cc *collectorConfig) shouldIncludeContainer(name string) bool {
	// Check exclusion list first
	for _, re := range cc.excludeRe {
		if re.MatchString(name) {
			return false
		}
	}
	// If no inclusion filter, include everything
	if len(cc.includeRe) == 0 {
		return true
	}
	for _, re := range cc.includeRe {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// containerLabels returns the standard set of labels for a container metric.
func containerLabels(id, name, image, status string) map[string]string {
	return map[string]string{
		"container_id":   id,
		"container_name": name,
		"image":          image,
		"status":         status,
	}
}
