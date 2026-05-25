// Package aurora implements the Amazon Aurora database monitoring collector.
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

package aurora

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// Config holds the resolved (defaults applied) Aurora collector configuration.
type Config struct {
	config.AuroraCollectorConfig
}

// NewConfig applies defaults to the provided AuroraCollectorConfig and returns a Config.
func NewConfig(cfg config.AuroraCollectorConfig) Config {
	if cfg.CollectionInterval == 0 {
		cfg.CollectionInterval = 60 * time.Second
	}
	if cfg.TopologyInterval == 0 {
		cfg.TopologyInterval = 300 * time.Second
	}
	if cfg.PIInterval == 0 {
		cfg.PIInterval = 60 * time.Second
	}
	if cfg.CloudWatchBatchSize == 0 {
		cfg.CloudWatchBatchSize = 500
	}
	if cfg.CloudWatchRateLimit == 0 {
		cfg.CloudWatchRateLimit = 40
	}
	if cfg.PushBatchSize == 0 {
		cfg.PushBatchSize = 1000
	}
	if cfg.PushFlushInterval == 0 {
		cfg.PushFlushInterval = 10 * time.Second
	}
	if cfg.TopologyInterval == 0 {
		cfg.TopologyInterval = 300 * time.Second
	}

	for i := range cfg.Clusters {
		applyClusterDefaults(&cfg.Clusters[i])
	}
	return Config{AuroraCollectorConfig: cfg}
}

func applyClusterDefaults(c *config.AuroraClusterConfig) {
	if c.Region == "" {
		c.Region = "us-east-1"
	}
}
