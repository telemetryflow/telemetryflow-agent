// Package postgresql implements the PostgreSQL database monitoring collector.
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

package postgresql

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.PostgreSQLCollectorConfig
}

func NewConfig(cfg config.PostgreSQLCollectorConfig) Config {
	if cfg.InstanceInterval == 0 {
		cfg.InstanceInterval = 10 * time.Second
	}
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 60 * time.Second
	}
	if cfg.TableInterval == 0 {
		cfg.TableInterval = 300 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 3
	}
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	if cfg.TopTablesLimit == 0 {
		cfg.TopTablesLimit = 500
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return Config{PostgreSQLCollectorConfig: cfg}
}

func applyInstanceDefaults(inst *config.PostgreSQLInstanceConfig) {
	if inst.Port == 0 {
		inst.Port = 5432
	}
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.User == "" {
		inst.User = "postgres"
	}
	if inst.DBName == "" {
		inst.DBName = "postgres"
	}
	if inst.SSLMode == "" {
		inst.SSLMode = "prefer"
	}
}
