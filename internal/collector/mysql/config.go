// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
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

package mysql

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.MySQLCollectorConfig
}

func NewConfig(cfg config.MySQLCollectorConfig) Config {
	if cfg.StatusInterval == 0 {
		cfg.StatusInterval = 10 * time.Second
	}
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 60 * time.Second
	}
	if cfg.SchemaInterval == 0 {
		cfg.SchemaInterval = 300 * time.Second
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return Config{MySQLCollectorConfig: cfg}
}

func applyInstanceDefaults(inst *config.MySQLInstanceConfig) {
	if inst.Port == 0 {
		inst.Port = 3306
	}
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.Username == "" {
		inst.Username = "root"
	}
	if inst.MaxOpenConns == 0 {
		inst.MaxOpenConns = 3
	}
}
