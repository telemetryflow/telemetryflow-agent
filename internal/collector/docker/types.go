// Package docker provides a Docker container metrics collector that discovers
// and monitors containers via the Docker Engine API.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
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
