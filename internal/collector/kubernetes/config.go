// Package kubernetes implements a Kubernetes metrics collector for TFO-Agent.
package kubernetes

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// Config wraps the user-facing KubernetesCollectorConfig with internal defaults.
type Config struct {
	config.KubernetesCollectorConfig
}

// NewConfig creates a Config from the user-facing config, applying sensible
// internal defaults for any zero-values.
func NewConfig(cfg config.KubernetesCollectorConfig) Config {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 60 * time.Second
	}
	return Config{KubernetesCollectorConfig: cfg}
}

// shouldCollectNamespace returns true if the namespace passes include/exclude filters.
func (c *Config) shouldCollectNamespace(ns string) bool {
	// If explicit namespaces are set, only include those
	if len(c.Namespaces) > 0 {
		for _, n := range c.Namespaces {
			if n == ns {
				return true
			}
		}
		return false
	}
	// Otherwise, check the exclude list
	for _, n := range c.ExcludeNamespaces {
		if n == ns {
			return false
		}
	}
	return true
}
