// Package mysql_test contains unit tests for the corresponding collector module.
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

package mysql_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	mysql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"go.uber.org/zap"
)

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

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
			got := mysql.SafeDivExport(tc.num, tc.denom)
			if math.Abs(got-tc.expect) > 1e-9 {
				t.Errorf("safeDiv(%f, %f) = %f, want %f", tc.num, tc.denom, got, tc.expect)
			}
		})
	}
}

func TestParseUint(t *testing.T) {
	tests := []struct {
		input  string
		expect uint64
	}{
		{"12345", 12345},
		{"0", 0},
		{"999999999", 999999999},
		{"", 0},
		{"abc", 0},
		{"42abc", 42},
		{" 100", 0},
		{"100 ", 100},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := mysql.ParseUintExport(tc.input)
			if got != tc.expect {
				t.Errorf("parseUint(%q) = %d, want %d", tc.input, got, tc.expect)
			}
		})
	}
}

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
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := mysql.ParseFloatExport(tc.input)
			if math.Abs(got-tc.expect) > 0.001 {
				t.Errorf("parseFloat(%q) = %f, want %f", tc.input, got, tc.expect)
			}
		})
	}
}

func TestBuildDSN(t *testing.T) {
	tests := []struct {
		name   string
		cfg    config.MySQLInstanceConfig
		expect string
	}{
		{
			name:   "basic",
			cfg:    config.MySQLInstanceConfig{Username: "root", Password: "pass", Host: "db.local", Port: 3306},
			expect: "root:pass@tcp(db.local:3306)/?parseTime=true&timeout=10s",
		},
		{
			name:   "with_database",
			cfg:    config.MySQLInstanceConfig{Username: "admin", Password: "secret", Host: "mysql.io", Port: 3307, Database: "mydb"},
			expect: "admin:secret@tcp(mysql.io:3307)/mydb?parseTime=true&timeout=10s",
		},
		{
			name:   "default_port",
			cfg:    config.MySQLInstanceConfig{Username: "root", Password: "pw", Host: "host", Port: 0},
			expect: "root:pw@tcp(host:3306)/?parseTime=true&timeout=10s",
		},
		{
			name:   "tls_enabled",
			cfg:    config.MySQLInstanceConfig{Username: "u", Password: "p", Host: "h", Port: 3306, TLSEnabled: true},
			expect: "u:p@tcp(h:3306)/?parseTime=true&timeout=10s&tls=true",
		},
		{
			name:   "tls_skip_verify",
			cfg:    config.MySQLInstanceConfig{Username: "u", Password: "p", Host: "h", Port: 3306, TLSEnabled: true, TLSSkipVerify: true},
			expect: "u:p@tcp(h:3306)/?parseTime=true&timeout=10s&tls=skip-verify",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mysql.BuildDSNExport(tc.cfg)
			if got != tc.expect {
				t.Errorf("buildDSN() = %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestNewConfig_Defaults(t *testing.T) {
	cfg := mysql.NewConfig(config.MySQLCollectorConfig{
		Instances: []config.MySQLInstanceConfig{
			{Name: "test"},
		},
	})
	if cfg.StatusInterval != 10*time.Second {
		t.Errorf("StatusInterval = %v, want 10s", cfg.StatusInterval)
	}
	if cfg.QueryInterval != 60*time.Second {
		t.Errorf("QueryInterval = %v, want 60s", cfg.QueryInterval)
	}
	if cfg.SchemaInterval != 300*time.Second {
		t.Errorf("SchemaInterval = %v, want 300s", cfg.SchemaInterval)
	}
	inst := cfg.Instances[0]
	if inst.Port != 3306 {
		t.Errorf("Port = %d, want 3306", inst.Port)
	}
	if inst.Host != "localhost" {
		t.Errorf("Host = %q, want localhost", inst.Host)
	}
	if inst.Username != "root" {
		t.Errorf("Username = %q, want root", inst.Username)
	}
	if inst.MaxOpenConns != 3 {
		t.Errorf("MaxOpenConns = %d, want 3", inst.MaxOpenConns)
	}
}

func TestNewConfig_CustomValues(t *testing.T) {
	cfg := mysql.NewConfig(config.MySQLCollectorConfig{
		StatusInterval: 5 * time.Second,
		QueryInterval:  30 * time.Second,
		SchemaInterval: 120 * time.Second,
		Instances: []config.MySQLInstanceConfig{
			{Name: "prod", Host: "mysql.prod", Port: 3307, Username: "admin", MaxOpenConns: 10},
		},
	})
	if cfg.StatusInterval != 5*time.Second {
		t.Errorf("StatusInterval = %v, want 5s", cfg.StatusInterval)
	}
	inst := cfg.Instances[0]
	if inst.Host != "mysql.prod" {
		t.Errorf("Host = %q, want mysql.prod", inst.Host)
	}
	if inst.Port != 3307 {
		t.Errorf("Port = %d, want 3307", inst.Port)
	}
	if inst.MaxOpenConns != 10 {
		t.Errorf("MaxOpenConns = %d, want 10", inst.MaxOpenConns)
	}
}

func TestComputeRates(t *testing.T) {
	prev := map[string]uint64{
		"Queries":      1000,
		"Com_select":   800,
		"Com_insert":   100,
		"Slow_queries": 5,
	}
	curr := map[string]uint64{
		"Queries":      2000,
		"Com_select":   1600,
		"Com_insert":   150,
		"Slow_queries": 7,
	}
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeRatesExport(prev, curr, 10.0, labels)

	if len(metrics) != 4 {
		t.Fatalf("expected 4 rate metrics, got %d", len(metrics))
	}

	qps := findMetric(metrics, "db.mysql.queries.total")
	if qps == nil {
		t.Fatal("expected qps metric")
	}
	expectedQPS := (2000.0 - 1000.0) / 10.0
	if math.Abs(qps.Value-expectedQPS) > 0.001 {
		t.Errorf("qps = %f, want %f", qps.Value, expectedQPS)
	}

	slowRate := findMetric(metrics, "db.mysql.queries.slow")
	if slowRate == nil {
		t.Fatal("expected slow_queries rate metric")
	}
	expectedSlow := (7.0 - 5.0) / 10.0
	if math.Abs(slowRate.Value-expectedSlow) > 0.001 {
		t.Errorf("slow rate = %f, want %f", slowRate.Value, expectedSlow)
	}
}

func TestComputeRates_CounterReset(t *testing.T) {
	prev := map[string]uint64{"Queries": 9000}
	curr := map[string]uint64{"Queries": 1000}
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeRatesExport(prev, curr, 10.0, labels)

	qps := findMetric(metrics, "db.mysql.queries.total")
	if qps != nil {
		t.Error("should not emit rate on counter reset (curr < prev)")
	}
}

func TestComputeRates_MissingPrev(t *testing.T) {
	prev := map[string]uint64{}
	curr := map[string]uint64{"Queries": 1000}
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeRatesExport(prev, curr, 10.0, labels)
	if len(metrics) != 0 {
		t.Error("should not emit rate when prev is missing")
	}
}

func TestEmitGaugeMetrics(t *testing.T) {
	rawStatus := map[string]uint64{
		"Threads_connected":              42,
		"Threads_running":                5,
		"Innodb_buffer_pool_pages_dirty": 100,
	}
	rows := []mysql.StatusRowExport{
		mysql.NewStatusRowExport("Threads_connected", 42),
		mysql.NewStatusRowExport("Threads_running", 5),
	}
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.EmitGaugeMetricsExport(rawStatus, mysql.ToStatusRows(rows), labels)

	if len(metrics) != 3 {
		t.Fatalf("expected 3 gauge metrics, got %d", len(metrics))
	}

	conn := findMetric(metrics, "db.mysql.threads.connected")
	if conn == nil || conn.Value != 42 {
		t.Error("threads.connected gauge wrong")
	}

	running := findMetric(metrics, "db.mysql.threads.running")
	if running == nil || running.Value != 5 {
		t.Error("threads.running gauge wrong")
	}
}

func TestComputeDerivedMetrics_BufferPoolHitRatio(t *testing.T) {
	status := map[string]uint64{
		"Innodb_buffer_pool_read_requests": 10000,
		"Innodb_buffer_pool_reads":         50,
		"Threads_connected":                10,
		"Created_tmp_tables":               500,
		"Created_tmp_disk_tables":          25,
		"Threads_created":                  2,
		"Connections":                      1000,
	}
	vars := map[string]string{"max_connections": "200"}
	labels := map[string]string{"mysql_instance": "test"}

	metrics := mysql.ComputeDerivedMetricsExport(status, vars, labels)

	hitRatio := findMetric(metrics, "db.mysql.innodb.buffer_pool.hit_ratio")
	if hitRatio == nil {
		t.Fatal("expected buffer_pool.hit_ratio")
	}
	expectedRatio := 1 - 50.0/10000.0
	if math.Abs(hitRatio.Value-expectedRatio) > 0.001 {
		t.Errorf("hit_ratio = %f, want %f", hitRatio.Value, expectedRatio)
	}
}

func TestComputeDerivedMetrics_ConnectionUtilization(t *testing.T) {
	status := map[string]uint64{
		"Innodb_buffer_pool_read_requests": 100,
		"Innodb_buffer_pool_reads":         1,
		"Threads_connected":                150,
		"Created_tmp_tables":               100,
		"Created_tmp_disk_tables":          10,
		"Threads_created":                  5,
		"Connections":                      500,
	}
	vars := map[string]string{"max_connections": "200"}
	labels := map[string]string{"mysql_instance": "test"}

	metrics := mysql.ComputeDerivedMetricsExport(status, vars, labels)

	util := findMetric(metrics, "db.mysql.connections.utilization")
	if util == nil {
		t.Fatal("expected connections.utilization")
	}
	expectedUtil := 150.0 / 200.0
	if math.Abs(util.Value-expectedUtil) > 0.001 {
		t.Errorf("utilization = %f, want %f", util.Value, expectedUtil)
	}
}

func TestComputeDerivedMetrics_TmpDiskRatio(t *testing.T) {
	status := map[string]uint64{
		"Innodb_buffer_pool_read_requests": 100,
		"Innodb_buffer_pool_reads":         1,
		"Threads_connected":                10,
		"Created_tmp_tables":               500,
		"Created_tmp_disk_tables":          125,
		"Threads_created":                  2,
		"Connections":                      100,
	}
	vars := map[string]string{"max_connections": "200"}
	labels := map[string]string{"mysql_instance": "test"}

	metrics := mysql.ComputeDerivedMetricsExport(status, vars, labels)

	ratio := findMetric(metrics, "db.mysql.tmp_tables.disk_ratio")
	if ratio == nil {
		t.Fatal("expected tmp_tables.disk_ratio")
	}
	expectedRatio := 125.0 / 500.0
	if math.Abs(ratio.Value-expectedRatio) > 0.001 {
		t.Errorf("disk_ratio = %f, want %f", ratio.Value, expectedRatio)
	}
}

func TestComputeDerivedMetrics_ThreadCacheHitRate(t *testing.T) {
	status := map[string]uint64{
		"Innodb_buffer_pool_read_requests": 100,
		"Innodb_buffer_pool_reads":         1,
		"Threads_connected":                10,
		"Created_tmp_tables":               100,
		"Created_tmp_disk_tables":          5,
		"Threads_created":                  10,
		"Connections":                      1000,
	}
	vars := map[string]string{"max_connections": "200"}
	labels := map[string]string{"mysql_instance": "test"}

	metrics := mysql.ComputeDerivedMetricsExport(status, vars, labels)

	hitRate := findMetric(metrics, "db.mysql.threads.cache_hit_rate")
	if hitRate == nil {
		t.Fatal("expected threads.cache_hit_rate")
	}
	expectedRate := 1 - 10.0/1000.0
	if math.Abs(hitRate.Value-expectedRate) > 0.001 {
		t.Errorf("cache_hit_rate = %f, want %f", hitRate.Value, expectedRate)
	}
}

func TestComputeDerivedMetrics_ZeroConnections(t *testing.T) {
	status := map[string]uint64{
		"Innodb_buffer_pool_read_requests": 100,
		"Innodb_buffer_pool_reads":         0,
		"Threads_connected":                0,
		"Created_tmp_tables":               0,
		"Created_tmp_disk_tables":          0,
		"Threads_created":                  0,
		"Connections":                      0,
	}
	vars := map[string]string{"max_connections": "200"}
	labels := map[string]string{"mysql_instance": "test"}

	metrics := mysql.ComputeDerivedMetricsExport(status, vars, labels)

	hitRatio := findMetric(metrics, "db.mysql.innodb.buffer_pool.hit_ratio")
	if hitRatio == nil {
		t.Fatal("expected hit_ratio even with zero reads")
	}
	if hitRatio.Value != 1.0 {
		t.Errorf("hit_ratio with zero reads = %f, want 1.0", hitRatio.Value)
	}
}

func TestEmitVariableMetrics(t *testing.T) {
	vars := map[string]string{
		"max_connections":         "500",
		"innodb_buffer_pool_size": "1073741824",
	}
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.EmitVariableMetricsExport(vars, labels)

	if len(metrics) != 2 {
		t.Fatalf("expected 2 variable metrics, got %d", len(metrics))
	}

	maxConn := findMetric(metrics, "db.mysql.connections.max")
	if maxConn == nil || maxConn.Value != 500 {
		t.Error("connections.max wrong")
	}

	bpSize := findMetric(metrics, "db.mysql.innodb.buffer_pool.size")
	if bpSize == nil || bpSize.Value != 1073741824 {
		t.Error("buffer_pool.size wrong")
	}
}

func TestMakeMetric(t *testing.T) {
	labels := map[string]string{"host": "db1", "env": "prod"}
	m := mysql.MakeMetricExport("test.metric", 42.5, collector.MetricTypeGauge, labels)

	if m.Name != "test.metric" {
		t.Errorf("Name = %q, want test.metric", m.Name)
	}
	if m.Value != 42.5 {
		t.Errorf("Value = %f, want 42.5", m.Value)
	}
	if m.Type != collector.MetricTypeGauge {
		t.Errorf("Type = %v, want Gauge", m.Type)
	}
	if m.Labels["host"] != "db1" {
		t.Error("Labels not copied correctly")
	}
	if m.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestEmitCounterRate_NaN_Inf(t *testing.T) {
	labels := map[string]string{}

	m := mysql.EmitCounterRateExport("test.rate", math.NaN(), labels)
	if m.Value != 0 {
		t.Errorf("NaN rate should be 0, got %f", m.Value)
	}

	m = mysql.EmitCounterRateExport("test.rate", math.Inf(1), labels)
	if m.Value != 0 {
		t.Errorf("+Inf rate should be 0, got %f", m.Value)
	}

	m = mysql.EmitCounterRateExport("test.rate", math.Inf(-1), labels)
	if m.Value != 0 {
		t.Errorf("-Inf rate should be 0, got %f", m.Value)
	}
}

func TestInstanceLabels(t *testing.T) {
	inst := mysql.NewMySQLInstanceExport(
		config.MySQLInstanceConfig{
			Name: "prod-primary",
			Host: "mysql.prod",
			Tags: map[string]string{"env": "production", "team": "backend"},
		},
		"mysql",
		"8.0.35",
	)

	labels := mysql.InstanceLabelsExport(inst)

	if labels["mysql_instance"] != "prod-primary" {
		t.Error("mysql_instance label wrong")
	}
	if labels["mysql_host"] != "mysql.prod" {
		t.Error("mysql_host label wrong")
	}
	if labels["mysql_flavor"] != "mysql" {
		t.Error("mysql_flavor label wrong")
	}
	if labels["mysql_version"] != "8.0.35" {
		t.Error("mysql_version label wrong")
	}
	if labels["env"] != "production" {
		t.Error("tag label env wrong")
	}
}

func TestFlavorDetection(t *testing.T) {
	tests := []struct {
		version string
		flavor  string
	}{
		{"8.0.35", "mysql"},
		{"8.0.34-26 Percona Server (GPL), Release 26, Revision 0fe3d7f", "percona"},
		{"11.2.3-MariaDB-1:11.2.3+maria~ubu2204", "mariadb"},
		{"5.7.44-log", "mysql"},
		{"10.6.12-MariaDB-0ubuntu0.22.04.1", "mariadb"},
		{"8.0.33-25 Percona Server (GPL)", "percona"},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			var flavor string
			vLower := strings.ToLower(tc.version)
			switch {
			case strings.Contains(vLower, "mariadb"):
				flavor = "mariadb"
			case strings.Contains(vLower, "percona"):
				flavor = "percona"
			default:
				flavor = "mysql"
			}
			if flavor != tc.flavor {
				t.Errorf("version %q: got %q, want %q", tc.version, flavor, tc.flavor)
			}
		})
	}
}

func TestNewMySQLCollector(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.MySQLCollectorConfig{
		Instances: []config.MySQLInstanceConfig{
			{Name: "test1", Host: "mysql1", Port: 3306, Username: "root", Password: "pw"},
			{Name: "test2", Host: "mysql2", Port: 3307, Username: "admin", Password: "pw2"},
		},
	}
	c := mysql.NewMySQLCollector(cfg, logger)

	if c.Name() != "mysql" {
		t.Errorf("Name() = %q, want mysql", c.Name())
	}
	if c.IsRunning() {
		t.Error("should not be running initially")
	}

	insts := mysql.GetCollectorInstances(c)
	if len(insts) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(insts))
	}
	if insts[0].Name != "test1" {
		t.Error("first instance name wrong")
	}
	if insts[1].Host != "mysql2" {
		t.Error("second instance host wrong")
	}
}
