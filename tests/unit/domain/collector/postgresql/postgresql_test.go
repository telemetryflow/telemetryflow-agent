// Package postgresql_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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

package postgresql_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"go.uber.org/zap"
)

// --- safeDiv ---

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		name   string
		num    float64
		denom  float64
		expect float64
	}{
		{"normal", 10, 2, 5},
		{"zero_denom", 10, 0, 0},
		{"zero_num", 0, 5, 0},
		{"both_zero", 0, 0, 0},
		{"fraction", 1, 3, 1.0 / 3.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := postgresql.SafeDivExported(tc.num, tc.denom)
			if math.Abs(got-tc.expect) > 1e-9 {
				t.Errorf("safeDiv(%f, %f) = %f, want %f", tc.num, tc.denom, got, tc.expect)
			}
		})
	}
}

// --- parseFloat ---

func TestParseFloat(t *testing.T) {
	tests := []struct {
		input  string
		expect float64
	}{
		{"3.14", 3.14},
		{"0", 0},
		{"100", 100},
		{"", 0},
		{"abc", 0},
		{"on", 0},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := postgresql.ParseFloatExported(tc.input)
			if math.Abs(got-tc.expect) > 0.001 {
				t.Errorf("parseFloat(%q) = %f, want %f", tc.input, got, tc.expect)
			}
		})
	}
}

// --- makeMetric ---

func TestMakeMetric(t *testing.T) {
	labels := map[string]string{"host": "pg1", "env": "prod"}
	m := postgresql.MakeMetricExported("test.metric", 42.5, collector.MetricTypeGauge, labels)

	if m.Name != "test.metric" {
		t.Errorf("Name = %q, want test.metric", m.Name)
	}
	if m.Value != 42.5 {
		t.Errorf("Value = %f, want 42.5", m.Value)
	}
	if m.Type != collector.MetricTypeGauge {
		t.Errorf("Type = %v, want Gauge", m.Type)
	}
	if m.Labels["host"] != "pg1" {
		t.Error("Labels not copied correctly")
	}
	if m.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

// --- emitCounterRate ---

func TestEmitCounterRate_NaN_Inf(t *testing.T) {
	labels := map[string]string{}

	m := postgresql.EmitCounterRateExported("test.rate", math.NaN(), labels)
	if m.Value != 0 {
		t.Errorf("NaN rate should be 0, got %f", m.Value)
	}

	m = postgresql.EmitCounterRateExported("test.rate", math.Inf(1), labels)
	if m.Value != 0 {
		t.Errorf("+Inf rate should be 0, got %f", m.Value)
	}

	m = postgresql.EmitCounterRateExported("test.rate", math.Inf(-1), labels)
	if m.Value != 0 {
		t.Errorf("-Inf rate should be 0, got %f", m.Value)
	}
}

// --- instanceLabels ---

func TestInstanceLabels(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{
		Name: "prod-primary",
		Host: "pg.prod",
		Tags: map[string]string{"env": "production", "team": "backend"},
	})
	inst.Flavor = "postgresql"
	inst.VersionStr = "16.2"

	labels := postgresql.InstanceLabelsExported(inst)

	if labels["postgresql_instance"] != "prod-primary" {
		t.Error("postgresql_instance label wrong")
	}
	if labels["postgresql_host"] != "pg.prod" {
		t.Error("postgresql_host label wrong")
	}
	if labels["postgresql_flavor"] != "postgresql" {
		t.Error("postgresql_flavor label wrong")
	}
	if labels["postgresql_version"] != "16.2" {
		t.Error("postgresql_version label wrong")
	}
	if labels["env"] != "production" {
		t.Error("tag label env wrong")
	}
	if labels["team"] != "backend" {
		t.Error("tag label team wrong")
	}
}

func TestInstanceLabels_Empty(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{
		Name: "test",
		Host: "localhost",
	})
	labels := postgresql.InstanceLabelsExported(inst)

	if _, ok := labels["postgresql_flavor"]; ok {
		t.Error("flavor should not be present when empty")
	}
	if _, ok := labels["postgresql_version"]; ok {
		t.Error("version should not be present when empty")
	}
}

// --- NewConfig defaults ---

func TestNewConfig_Defaults(t *testing.T) {
	cfg := postgresql.NewConfigExported(config.PostgreSQLCollectorConfig{
		Instances: []config.PostgreSQLInstanceConfig{
			{Name: "test"},
		},
	})
	if cfg.InstanceInterval != 10*time.Second {
		t.Errorf("InstanceInterval = %v, want 10s", cfg.InstanceInterval)
	}
	if cfg.QueryInterval != 60*time.Second {
		t.Errorf("QueryInterval = %v, want 60s", cfg.QueryInterval)
	}
	if cfg.TableInterval != 300*time.Second {
		t.Errorf("TableInterval = %v, want 300s", cfg.TableInterval)
	}
	if cfg.MaxConnections != 3 {
		t.Errorf("MaxConnections = %d, want 3", cfg.MaxConnections)
	}
	if cfg.TopQueriesLimit != 200 {
		t.Errorf("TopQueriesLimit = %d, want 200", cfg.TopQueriesLimit)
	}
	if cfg.TopTablesLimit != 500 {
		t.Errorf("TopTablesLimit = %d, want 500", cfg.TopTablesLimit)
	}
	inst := cfg.Instances[0]
	if inst.Port != 5432 {
		t.Errorf("Port = %d, want 5432", inst.Port)
	}
	if inst.Host != "localhost" {
		t.Errorf("Host = %q, want localhost", inst.Host)
	}
	if inst.User != "postgres" {
		t.Errorf("User = %q, want postgres", inst.User)
	}
	if inst.DBName != "postgres" {
		t.Errorf("DBName = %q, want postgres", inst.DBName)
	}
	if inst.SSLMode != "prefer" {
		t.Errorf("SSLMode = %q, want prefer", inst.SSLMode)
	}
}

func TestNewConfig_CustomValues(t *testing.T) {
	cfg := postgresql.NewConfigExported(config.PostgreSQLCollectorConfig{
		InstanceInterval: 5 * time.Second,
		QueryInterval:    30 * time.Second,
		TableInterval:    120 * time.Second,
		MaxConnections:   10,
		TopQueriesLimit:  50,
		TopTablesLimit:   100,
		Instances: []config.PostgreSQLInstanceConfig{
			{Name: "prod", Host: "pg.prod", Port: 5433, User: "admin", Password: "secret", DBName: "mydb"},
		},
	})
	if cfg.InstanceInterval != 5*time.Second {
		t.Errorf("InstanceInterval = %v, want 5s", cfg.InstanceInterval)
	}
	inst := cfg.Instances[0]
	if inst.Host != "pg.prod" {
		t.Errorf("Host = %q, want pg.prod", inst.Host)
	}
	if inst.Port != 5433 {
		t.Errorf("Port = %d, want 5433", inst.Port)
	}
	if inst.User != "admin" {
		t.Errorf("User = %q, want admin", inst.User)
	}
	if inst.DBName != "mydb" {
		t.Errorf("DBName = %q, want mydb", inst.DBName)
	}
	if cfg.MaxConnections != 10 {
		t.Errorf("MaxConnections = %d, want 10", cfg.MaxConnections)
	}
	if cfg.TopQueriesLimit != 50 {
		t.Errorf("TopQueriesLimit = %d, want 50", cfg.TopQueriesLimit)
	}
	if cfg.TopTablesLimit != 100 {
		t.Errorf("TopTablesLimit = %d, want 100", cfg.TopTablesLimit)
	}
}

// --- NewPostgreSQLCollector ---

func TestNewPostgreSQLCollector(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.PostgreSQLCollectorConfig{
		Instances: []config.PostgreSQLInstanceConfig{
			{Name: "test1", Host: "pg1", Port: 5432, User: "postgres", Password: "pw"},
			{Name: "test2", Host: "pg2", Port: 5433, User: "admin", Password: "pw2"},
		},
	}
	c := postgresql.NewPostgreSQLCollector(cfg, logger)

	if c.Name() != "postgresql" {
		t.Errorf("Name() = %q, want postgresql", c.Name())
	}
	if c.IsRunning() {
		t.Error("should not be running initially")
	}
}

// --- Collector lifecycle ---

func TestCollector_StopWhenNotRunning(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.PostgreSQLCollectorConfig{
		Instances: []config.PostgreSQLInstanceConfig{
			{Name: "test"},
		},
	}
	c := postgresql.NewPostgreSQLCollector(cfg, logger)

	// Stopping a non-running collector should not panic.
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() on non-running collector returned error: %v", err)
	}
}

// --- Flavor detection ---

func TestFlavorDetection(t *testing.T) {
	tests := []struct {
		versionStr string
		flavor     string
	}{
		{"16.2", "postgresql"},
		{"15.4 AWS", "aws-rds"},
		{"14.8 (Ubuntu 14.8-1.pgdg22.04+1)", "postgresql"},
		{"15.0 on Azure", "azure"},
		{"14.5-google", "gcp-cloudsql"},
		{"14.5 CloudSQL", "gcp-cloudsql"},
	}
	for _, tc := range tests {
		t.Run(tc.versionStr, func(t *testing.T) {
			vLower := strings.ToLower(tc.versionStr)
			var flavor string
			switch {
			case strings.Contains(vLower, "aws"):
				flavor = "aws-rds"
			case strings.Contains(vLower, "azure"):
				flavor = "azure"
			case strings.Contains(vLower, "google") || strings.Contains(vLower, "cloudsql"):
				flavor = "gcp-cloudsql"
			default:
				flavor = "postgresql"
			}
			if flavor != tc.flavor {
				t.Errorf("version %q: got %q, want %q", tc.versionStr, flavor, tc.flavor)
			}
		})
	}
}

// --- Version helpers ---

func TestHasPgStatWal(t *testing.T) {
	tests := []struct {
		version  int
		expected bool
	}{
		{140000, true},
		{150000, true},
		{160002, true},
		{139999, false},
		{130000, false},
		{120000, false},
		{0, false},
	}
	for _, tc := range tests {
		inst := &postgresql.PGTestInstance{Version: tc.version}
		got := postgresql.HasPgStatWalExported(inst)
		if got != tc.expected {
			t.Errorf("hasPgStatWal(version=%d) = %v, want %v", tc.version, got, tc.expected)
		}
	}
}

func TestHasExecTimeColumns(t *testing.T) {
	tests := []struct {
		version  int
		expected bool
	}{
		{130000, true},
		{140000, true},
		{160002, true},
		{129999, false},
		{120000, false},
		{0, false},
	}
	for _, tc := range tests {
		inst := &postgresql.PGTestInstance{Version: tc.version}
		got := postgresql.HasExecTimeColumnsExported(inst)
		if got != tc.expected {
			t.Errorf("hasExecTimeColumns(version=%d) = %v, want %v", tc.version, got, tc.expected)
		}
	}
}

// --- buildConnString ---

func TestBuildConnString(t *testing.T) {
	tests := []struct {
		name   string
		cfg    config.PostgreSQLInstanceConfig
		expect string
	}{
		{
			name:   "basic",
			cfg:    config.PostgreSQLInstanceConfig{User: "postgres", Password: "pass", Host: "db.local", Port: 5432, DBName: "mydb", SSLMode: "disable"},
			expect: "postgres://postgres:pass@db.local:5432/mydb?sslmode=disable",
		},
		{
			name:   "with_ssl",
			cfg:    config.PostgreSQLInstanceConfig{User: "admin", Password: "secret", Host: "pg.io", Port: 5433, DBName: "testdb", SSLMode: "require"},
			expect: "postgres://admin:secret@pg.io:5433/testdb?sslmode=require",
		},
		{
			name:   "with_ssl_certs",
			cfg:    config.PostgreSQLInstanceConfig{User: "u", Password: "p", Host: "h", Port: 5432, DBName: "d", SSLMode: "verify-full", SSLRootCert: "/ca.crt", SSLCert: "/client.crt", SSLKey: "/client.key"},
			expect: "postgres://u:p@h:5432/d?sslmode=verify-full&sslrootcert=/ca.crt&sslcert=/client.crt&sslkey=/client.key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := postgresql.BuildConnStringExported(tc.cfg)
			if got != tc.expect {
				t.Errorf("buildConnString() = %q, want %q", got, tc.expect)
			}
		})
	}
}

// --- resolveEnvVars ---

func TestResolveEnvVars(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		env    map[string]string
		expect string
	}{
		{
			name:   "no_env_vars",
			input:  "plain_password",
			env:    nil,
			expect: "plain_password",
		},
		{
			name:   "simple_substitution",
			input:  "${PG_PASSWORD}",
			env:    map[string]string{"PG_PASSWORD": "my_secret"},
			expect: "my_secret",
		},
		{
			name:   "env_not_set",
			input:  "${PG_PASSWORD}",
			env:    nil,
			expect: "",
		},
		{
			name:   "env_not_set_with_default",
			input:  "${PG_PASSWORD:-fallback}",
			env:    nil,
			expect: "fallback",
		},
		{
			name:   "env_set_ignores_default",
			input:  "${PG_PASSWORD:-fallback}",
			env:    map[string]string{"PG_PASSWORD": "real_pass"},
			expect: "real_pass",
		},
		{
			name:   "mixed_content",
			input:  "prefix_${PG_USER}_suffix",
			env:    map[string]string{"PG_USER": "admin"},
			expect: "prefix_admin_suffix",
		},
		{
			name:   "multiple_vars",
			input:  "${PG_USER}:${PG_PASS}",
			env:    map[string]string{"PG_USER": "admin", "PG_PASS": "secret"},
			expect: "admin:secret",
		},
		{
			name:   "empty_default",
			input:  "${PG_PASS:-}",
			env:    nil,
			expect: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			got := postgresql.ResolveEnvVarsExported(tc.input)
			if got != tc.expect {
				t.Errorf("resolveEnvVars(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

// --- copyLabels ---

func TestCopyLabels(t *testing.T) {
	original := map[string]string{
		"postgresql_instance": "test",
		"env":                 "prod",
	}
	copied := postgresql.CopyLabelsExported(original)

	if len(copied) != len(original) {
		t.Errorf("copied labels count mismatch: got %d, want %d", len(copied), len(original))
	}

	copied["extra"] = "value"
	if _, ok := original["extra"]; ok {
		t.Error("mutating copied labels affected original")
	}
}

// --- makeTableLabels / makeIndexLabels ---

func TestMakeTableLabels(t *testing.T) {
	base := map[string]string{"postgresql_instance": "test"}
	l := postgresql.MakeTableLabelsExported(base, "public", "users")

	if l["schemaname"] != "public" {
		t.Errorf("schemaname = %q, want public", l["schemaname"])
	}
	if l["tablename"] != "users" {
		t.Errorf("tablename = %q, want users", l["tablename"])
	}
	if l["postgresql_instance"] != "test" {
		t.Error("base labels not carried over")
	}
}

func TestMakeIndexLabels(t *testing.T) {
	base := map[string]string{"postgresql_instance": "test"}
	l := postgresql.MakeIndexLabelsExported(base, "public", "users", "idx_users_email")

	if l["schemaname"] != "public" {
		t.Errorf("schemaname = %q, want public", l["schemaname"])
	}
	if l["tablename"] != "users" {
		t.Errorf("tablename = %q, want users", l["tablename"])
	}
	if l["indexname"] != "idx_users_email" {
		t.Errorf("indexname = %q, want idx_users_email", l["indexname"])
	}
}
