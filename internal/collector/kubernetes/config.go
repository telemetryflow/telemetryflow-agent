// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
