package json_parser_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/json_parser"
)

func TestJSONParser_AllTopLevelKeys(t *testing.T) {
	p := json_parser.New(json_parser.Config{})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: `{"level":"info","service":"api","latency_ms":42.5}`,
	}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 forwarded, got %d", len(acc.added))
	}
	labels := acc.added[0].Labels
	if labels["level"] != "info" {
		t.Errorf("level = %q", labels["level"])
	}
	if labels["service"] != "api" {
		t.Errorf("service = %q", labels["service"])
	}
	if labels["latency_ms"] != "42.5" {
		t.Errorf("latency_ms = %q", labels["latency_ms"])
	}
}

func TestJSONParser_TagKeysSubset(t *testing.T) {
	p := json_parser.New(json_parser.Config{
		TagKeys: []string{"level", "missing"},
	})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: `{"level":"warn","service":"api","msg":"hello"}`,
	}, nil)

	labels := acc.added[0].Labels
	if _, ok := labels["service"]; ok {
		t.Error("service should not be promoted (not in TagKeys)")
	}
	if labels["level"] != "warn" {
		t.Errorf("level = %q", labels["level"])
	}
	if _, ok := labels["missing"]; ok {
		t.Error("missing key should not appear as a label")
	}
}

func TestJSONParser_DottedPathTagKeys(t *testing.T) {
	p := json_parser.New(json_parser.Config{
		TagKeys: []string{"user.id", "user.name"},
	})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: `{"user":{"id":"u-123","name":"alice"},"event":"login"}`,
	}, nil)

	labels := acc.added[0].Labels
	if labels["user.id"] != "u-123" {
		t.Errorf("user.id = %q", labels["user.id"])
	}
	if labels["user.name"] != "alice" {
		t.Errorf("user.name = %q", labels["user.name"])
	}
	if _, ok := labels["event"]; ok {
		t.Error("non-listed top-level key should not be promoted")
	}
}

func TestJSONParser_DottedPathMissing(t *testing.T) {
	p := json_parser.New(json_parser.Config{
		TagKeys: []string{"a.b.c"},
	})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: `{"a":{"b":{"x":1}}}`,
	}, nil)

	if len(acc.added[0].Labels) != 0 {
		t.Errorf("missing path should produce no label, got %v", acc.added[0].Labels)
	}
}

func TestJSONParser_ValueKeyOverride(t *testing.T) {
	p := json_parser.New(json_parser.Config{
		ValueKey: "duration_ms",
	})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "latency",
		Description: `{"duration_ms":123.4,"level":"info"}`,
		Value:       0,
	}, nil)

	if acc.added[0].Value != 123.4 {
		t.Errorf("expected value overridden to 123.4, got %f", acc.added[0].Value)
	}
}

func TestJSONParser_ValueKeyDottedPath(t *testing.T) {
	p := json_parser.New(json_parser.Config{
		ValueKey: "stats.count",
	})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "counter",
		Description: `{"stats":{"count":7}}`,
	}, nil)

	if acc.added[0].Value != 7 {
		t.Errorf("expected value 7, got %f", acc.added[0].Value)
	}
}

func TestJSONParser_InvalidJSON_Passthrough(t *testing.T) {
	p := json_parser.New(json_parser.Config{})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "this is not json",
		Value:       9,
	}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 forwarded (passthrough), got %d", len(acc.added))
	}
	if acc.added[0].Value != 9 {
		t.Errorf("value should be unchanged on parse failure, got %f", acc.added[0].Value)
	}
	if len(acc.added[0].Labels) != 0 {
		t.Errorf("no labels should be added on parse failure, got %v", acc.added[0].Labels)
	}
}

func TestJSONParser_NonObjectJSON_ForwardedUnchanged(t *testing.T) {
	p := json_parser.New(json_parser.Config{})
	acc := &captureAcc{}
	_ = p.Start(acc)

	// JSON array — not an object — should be forwarded unchanged.
	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: `[1,2,3]`,
	}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 forwarded, got %d", len(acc.added))
	}
	if len(acc.added[0].Labels) != 0 {
		t.Errorf("array should not produce labels, got %v", acc.added[0].Labels)
	}
}

func TestJSONParser_ValueKeyStringValueCoerced(t *testing.T) {
	p := json_parser.New(json_parser.Config{
		ValueKey: "count",
	})
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: `{"count":"42"}`,
	}, nil)

	if acc.added[0].Value != 42 {
		t.Errorf("numeric string should coerce to float, got %f", acc.added[0].Value)
	}
}

func TestJSONParser_Name(t *testing.T) {
	if json_parser.New(json_parser.Config{}).Name() != "json_parser" {
		t.Error("name mismatch")
	}
}

// captureAcc records Add calls for assertion.
type captureAcc struct {
	added []plugin.Metric
	errs  []error
}

func (a *captureAcc) Add(m plugin.Metric)                                              { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time)  {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(err error)                                               { a.errs = append(a.errs, err) }
