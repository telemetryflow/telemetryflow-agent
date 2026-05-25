// Package clickhouse_test contains unit tests for the corresponding collector module.
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

package clickhouse_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/clickhouse"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestNewConfig_Defaults(t *testing.T) {
	cfg := clickhouse.NewConfig(config.ClickHouseCollectorConfig{
		Instances: []config.ClickHouseInstanceConfig{
			{Name: "test"},
		},
	})
	if cfg.CollectionInterval != 15*time.Second {
		t.Errorf("CollectionInterval = %v, want 15s", cfg.CollectionInterval)
	}
	if cfg.QueryLogInterval != 60*time.Second {
		t.Errorf("QueryLogInterval = %v, want 60s", cfg.QueryLogInterval)
	}
	if cfg.MaxQueryLogRows != 10000 {
		t.Errorf("MaxQueryLogRows = %d, want 10000", cfg.MaxQueryLogRows)
	}
	inst := cfg.Instances[0]
	if inst.Host != "localhost" {
		t.Errorf("Host = %q, want localhost", inst.Host)
	}
	if inst.HTTPPort != 8123 {
		t.Errorf("HTTPPort = %d, want 8123", inst.HTTPPort)
	}
	if inst.NativePort != 9000 {
		t.Errorf("NativePort = %d, want 9000", inst.NativePort)
	}
	if inst.Username != "default" {
		t.Errorf("Username = %q, want default", inst.Username)
	}
	if inst.Database != "default" {
		t.Errorf("Database = %q, want default", inst.Database)
	}
	if inst.ConnectTimeout != 10*time.Second {
		t.Errorf("ConnectTimeout = %v, want 10s", inst.ConnectTimeout)
	}
	if inst.QueryTimeout != 30*time.Second {
		t.Errorf("QueryTimeout = %v, want 30s", inst.QueryTimeout)
	}
	if inst.ShardNum != 1 {
		t.Errorf("ShardNum = %d, want 1", inst.ShardNum)
	}
	if inst.ReplicaName != "replica1" {
		t.Errorf("ReplicaName = %q, want replica1", inst.ReplicaName)
	}
	if inst.ClusterName != "default" {
		t.Errorf("ClusterName = %q, want default", inst.ClusterName)
	}
}

func TestNewConfig_CustomValues(t *testing.T) {
	cfg := clickhouse.NewConfig(config.ClickHouseCollectorConfig{
		CollectionInterval: 5 * time.Second,
		QueryLogInterval:   30 * time.Second,
		MaxQueryLogRows:    5000,
		Instances: []config.ClickHouseInstanceConfig{
			{
				Name:        "prod",
				Host:        "ch.prod",
				HTTPPort:    8124,
				NativePort:  9001,
				Username:    "admin",
				Database:    "analytics",
				ShardNum:    3,
				ReplicaName: "replica2",
				ClusterName: "prod_cluster",
			},
		},
	})
	if cfg.CollectionInterval != 5*time.Second {
		t.Errorf("CollectionInterval = %v, want 5s", cfg.CollectionInterval)
	}
	inst := cfg.Instances[0]
	if inst.Host != "ch.prod" {
		t.Errorf("Host = %q, want ch.prod", inst.Host)
	}
	if inst.HTTPPort != 8124 {
		t.Errorf("HTTPPort = %d, want 8124", inst.HTTPPort)
	}
	if inst.ShardNum != 3 {
		t.Errorf("ShardNum = %d, want 3", inst.ShardNum)
	}
}

func TestNewConfig_MultipleInstances(t *testing.T) {
	cfg := clickhouse.NewConfig(config.ClickHouseCollectorConfig{
		Instances: []config.ClickHouseInstanceConfig{
			{Name: "ch1", Host: "node1"},
			{Name: "ch2", Host: "node2", HTTPPort: 8124},
		},
	})
	if len(cfg.Instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(cfg.Instances))
	}
	if cfg.Instances[0].HTTPPort != 8123 {
		t.Errorf("ch1 HTTPPort = %d, want 8123 (default)", cfg.Instances[0].HTTPPort)
	}
	if cfg.Instances[1].HTTPPort != 8124 {
		t.Errorf("ch2 HTTPPort = %d, want 8124 (custom)", cfg.Instances[1].HTTPPort)
	}
}
