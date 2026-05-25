// Package clickhouse collects system, storage, replication, and query-log metrics
// from external ClickHouse instances via the HTTP interface (port 8123) and emits
// them as OTLP telemetry.
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
package clickhouse

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// Config wraps the user-facing ClickHouseCollectorConfig with internal defaults.
type Config struct {
	config.ClickHouseCollectorConfig
}

// NewConfig creates a Config from the user-facing config, applying sensible
// internal defaults for any zero-valued fields.
func NewConfig(cfg config.ClickHouseCollectorConfig) Config {
	if cfg.CollectionInterval == 0 {
		cfg.CollectionInterval = 15 * time.Second
	}
	if cfg.QueryLogInterval == 0 {
		cfg.QueryLogInterval = 60 * time.Second
	}
	if cfg.MaxQueryLogRows == 0 {
		cfg.MaxQueryLogRows = 10000
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return Config{ClickHouseCollectorConfig: cfg}
}

// applyInstanceDefaults fills in zero-valued fields on a single instance config.
func applyInstanceDefaults(inst *config.ClickHouseInstanceConfig) {
	if inst.HTTPPort == 0 {
		inst.HTTPPort = 8123
	}
	if inst.NativePort == 0 {
		inst.NativePort = 9000
	}
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.Username == "" {
		inst.Username = "default"
	}
	if inst.Database == "" {
		inst.Database = "default"
	}
	if inst.ConnectTimeout == 0 {
		inst.ConnectTimeout = 10 * time.Second
	}
	if inst.QueryTimeout == 0 {
		inst.QueryTimeout = 30 * time.Second
	}
	if inst.ShardNum == 0 {
		inst.ShardNum = 1
	}
	if inst.ReplicaName == "" {
		inst.ReplicaName = "replica1"
	}
	if inst.ClusterName == "" {
		inst.ClusterName = "default"
	}
}
