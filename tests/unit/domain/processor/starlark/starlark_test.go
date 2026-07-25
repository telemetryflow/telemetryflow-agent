package starlark_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/starlark"
)

func TestStarlark_NoScript_Passthrough(t *testing.T) {
	s := starlark.New(starlark.Config{})
	acc := &captureAcc{}
	if err := s.Start(acc); err != nil {
		t.Fatal(err)
	}
	_ = s.Add(plugin.Metric{Name: "a", Value: 1}, nil)
	if len(acc.added) != 1 {
		t.Fatalf("passthrough failed, got %d", len(acc.added))
	}
}

func TestStarlark_AddTag(t *testing.T) {
	s := starlark.New(starlark.Config{Script: `
def apply(metric):
    metric["labels"]["environment"] = "prod"
    return metric
`})
	acc := &captureAcc{}
	if err := s.Start(acc); err != nil {
		t.Fatal(err)
	}
	_ = s.Add(plugin.Metric{Name: "m", Labels: map[string]string{}}, nil)
	if acc.added[0].Labels["environment"] != "prod" {
		t.Errorf("expected environment=prod tag, got %v", acc.added[0].Labels)
	}
}

func TestStarlark_DropMetric(t *testing.T) {
	s := starlark.New(starlark.Config{Script: `
def apply(metric):
    if metric["name"].startswith("debug."):
        return None
    return metric
`})
	acc := &captureAcc{}
	if err := s.Start(acc); err != nil {
		t.Fatal(err)
	}
	_ = s.Add(plugin.Metric{Name: "debug.x"}, nil)
	_ = s.Add(plugin.Metric{Name: "system.cpu"}, nil)
	if len(acc.added) != 1 || acc.added[0].Name != "system.cpu" {
		t.Errorf("expected only system.cpu, got %v", acc.added)
	}
}

func TestStarlark_ComputeField(t *testing.T) {
	s := starlark.New(starlark.Config{Script: `
def apply(metric):
    metric["value"] = metric["value"] * 100
    return metric
`})
	acc := &captureAcc{}
	if err := s.Start(acc); err != nil {
		t.Fatal(err)
	}
	_ = s.Add(plugin.Metric{Name: "m", Value: 0.42}, nil)
	if acc.added[0].Value != 42 {
		t.Errorf("expected 42, got %f", acc.added[0].Value)
	}
}

func TestStarlark_FanOutList(t *testing.T) {
	s := starlark.New(starlark.Config{Script: `
def apply(metric):
    out = []
    metric1 = dict(metric)
    metric1["name"] = metric["name"] + ".primary"
    out.append(metric1)
    metric2 = dict(metric)
    metric2["name"] = metric["name"] + ".secondary"
    out.append(metric2)
    return out
`})
	acc := &captureAcc{}
	if err := s.Start(acc); err != nil {
		t.Fatal(err)
	}
	_ = s.Add(plugin.Metric{Name: "request", Labels: map[string]string{}}, nil)
	if len(acc.added) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(acc.added))
	}
}

func TestStarlark_MissingApply_ReturnsError(t *testing.T) {
	s := starlark.New(starlark.Config{Script: `x = 1`})
	if err := s.Start(&captureAcc{}); err == nil {
		t.Error("expected error when apply() is missing")
	}
}

func TestStarlark_SyntaxError_ReturnsError(t *testing.T) {
	s := starlark.New(starlark.Config{Script: `def apply(`})
	if err := s.Start(&captureAcc{}); err == nil {
		t.Error("expected syntax error")
	}
}

type captureAcc struct {
	added []plugin.Metric
	errs  []error
}

func (a *captureAcc) Add(m plugin.Metric)                                              { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time)  {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(err error)                                               { a.errs = append(a.errs, err) }
