package timescaledb_test

import (
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	tsdb "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestNewConfig_Defaults(t *testing.T) {
	cfg := tsdb.NewConfigExport(config.TimescaleDBCollectorConfig{})
	if cfg.InstanceInterval == 0 {
		t.Error("expected default InstanceInterval")
	}
	if cfg.HypertableInterval == 0 {
		t.Error("expected default HypertableInterval")
	}
	if cfg.ChunkInterval == 0 {
		t.Error("expected default ChunkInterval")
	}
	if cfg.JobInterval == 0 {
		t.Error("expected default JobInterval")
	}
	if cfg.MaxConnections == 0 {
		t.Error("expected default MaxConnections")
	}
}

func TestNewConfig_InstanceDefaults(t *testing.T) {
	cfg := tsdb.NewConfigExport(config.TimescaleDBCollectorConfig{
		Instances: []config.TimescaleDBInstanceConfig{{}},
	})
	inst := cfg.Instances[0]
	if inst.Port != 5432 {
		t.Errorf("expected port 5432, got %d", inst.Port)
	}
	if inst.Host != "localhost" {
		t.Errorf("expected localhost, got %s", inst.Host)
	}
	if inst.User != "postgres" {
		t.Errorf("expected postgres, got %s", inst.User)
	}
	if inst.SSLMode != "prefer" {
		t.Errorf("expected prefer, got %s", inst.SSLMode)
	}
}

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		num, denom, want float64
	}{
		{10, 2, 5},
		{10, 0, 0},
		{0, 5, 0},
	}
	for _, tt := range tests {
		got := tsdb.SafeDivExport(tt.num, tt.denom)
		if got != tt.want {
			t.Errorf("safeDiv(%v, %v) = %v, want %v", tt.num, tt.denom, got, tt.want)
		}
	}
}

func TestCompressionRatio(t *testing.T) {
	before := float64(1000)
	after := float64(250)
	ratio := tsdb.SafeDivExport(before, after)
	if ratio != 4.0 {
		t.Errorf("expected compression ratio 4.0, got %f", ratio)
	}
}

func TestCompressionRatio_ZeroAfter(t *testing.T) {
	ratio := tsdb.SafeDivExport(float64(1000), 0)
	if ratio != 0 {
		t.Errorf("expected 0 for zero denominator, got %f", ratio)
	}
}

func TestMakeMetric(t *testing.T) {
	labels := map[string]string{"instance": "test"}
	m := tsdb.MakeMetricExport("db.timescaledb.test", 42.0, collector.MetricTypeGauge, labels)
	if m.Name != "db.timescaledb.test" {
		t.Errorf("expected name db.timescaledb.test, got %s", m.Name)
	}
	if m.Value != 42.0 {
		t.Errorf("expected value 42.0, got %f", m.Value)
	}
	if m.Type != collector.MetricTypeGauge {
		t.Error("expected gauge type")
	}
	if m.Labels["instance"] != "test" {
		t.Error("expected label to be copied")
	}
}

func TestMakeMetric_LabelCopy(t *testing.T) {
	labels := map[string]string{"k": "v"}
	m := tsdb.MakeMetricExport("test", 1, collector.MetricTypeGauge, labels)
	labels["k"] = "modified"
	if m.Labels["k"] != "v" {
		t.Error("expected labels to be copied, not referenced")
	}
}

func TestInstanceLabels(t *testing.T) {
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{
		Name: "prod-tsdb",
		Host: "tsdb.example.com",
		Tags: map[string]string{"env": "production"},
	}, "15.4", "2.15.0")

	labels := tsdb.InstanceLabelsExport(inst)
	if labels["timescaledb_instance"] != "prod-tsdb" {
		t.Error("expected instance name label")
	}
	if labels["timescaledb_host"] != "tsdb.example.com" {
		t.Error("expected host label")
	}
	if labels["postgresql_version"] != "15.4" {
		t.Error("expected PG version label")
	}
	if labels["timescaledb_version"] != "2.15.0" {
		t.Error("expected TSDB version label")
	}
	if labels["env"] != "production" {
		t.Error("expected tag label")
	}
}

func TestCopyLabels(t *testing.T) {
	src := map[string]string{"a": "1", "b": "2"}
	dst := tsdb.CopyLabelsExport(src)
	dst["a"] = "modified"
	if src["a"] != "1" {
		t.Error("expected original map to be unmodified")
	}
}

func TestChunkAgeBucketing(t *testing.T) {
	buckets := []int{0, 0, 0, 0, 0}
	ages := []float64{0.5, 1.5, 3, 8, 15, 25, 60}
	for _, age := range ages {
		idx := 0
		switch {
		case age < 1:
			idx = 0
		case age < 7:
			idx = 1
		case age < 30:
			idx = 2
		case age < 90:
			idx = 3
		default:
			idx = 4
		}
		buckets[idx]++
	}
	expected := []int{1, 2, 3, 1, 0}
	for i, got := range buckets {
		if got != expected[i] {
			t.Errorf("bucket %d: got %d, want %d", i, got, expected[i])
		}
	}
}

func TestStuckJobDetection(t *testing.T) {
	tests := []struct {
		name        string
		maxRuntimeS float64
		elapsedS    float64
		stuck       bool
	}{
		{"running within limit", 3600, 1800, false},
		{"running over limit", 3600, 7200, true},
		{"zero max runtime", 0, 99999, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stuck := tt.maxRuntimeS > 0 && tt.elapsedS > tt.maxRuntimeS
			if stuck != tt.stuck {
				t.Errorf("expected stuck=%v, got stuck=%v", tt.stuck, stuck)
			}
		})
	}
}

func TestCollectorName(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	if c.Name() != "timescaledb" {
		t.Errorf("expected collector name 'timescaledb', got %s", c.Name())
	}
	if c.IsRunning() {
		t.Error("expected collector to not be running after creation")
	}
}

func TestResolveEnvVars(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"plain", "plain"},
		{"${UNDEFINED_VAR_TSDB_TEST:-default}", "default"},
	}
	for _, tt := range tests {
		got := tsdb.ResolveEnvVarsExport(tt.input)
		if tt.input == "plain" && got != "plain" {
			t.Errorf("expected %s, got %s", tt.expect, got)
		}
		if tt.input == "${UNDEFINED_VAR_TSDB_TEST:-default}" && got != "default" {
			t.Errorf("expected default, got %s", got)
		}
	}
}

func TestParseFloat(t *testing.T) {
	tests := []struct {
		input interface{}
		want  float64
	}{
		{float64(3.14), 3.14},
		{int(42), 42},
		{"123.45", 123.45},
		{nil, 0},
	}
	for _, tt := range tests {
		got := tsdb.ParseFloatExport(tt.input)
		if got != tt.want {
			t.Errorf("parseFloat(%v) = %f, want %f", tt.input, got, tt.want)
		}
	}
}
