package enum

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func TestEnum_MapsValue(t *testing.T) {
	e := New(Config{Mappings: []Mapping{{
		Tag:    "state",
		Values: map[string]string{"0": "stopped", "1": "running"},
	}}})
	acc := &captureAcc{}
	e.Start(acc)
	_ = e.Add(plugin.Metric{Name: "m", Labels: map[string]string{"state": "1"}}, nil)
	if acc.added[0].Labels["state"] != "running" {
		t.Errorf("expected 'running', got %q", acc.added[0].Labels["state"])
	}
}

func TestEnum_DefaultApplied(t *testing.T) {
	e := New(Config{Mappings: []Mapping{{
		Tag:     "state",
		Values:  map[string]string{"0": "stopped"},
		Default: "unknown",
	}}})
	acc := &captureAcc{}
	e.Start(acc)
	_ = e.Add(plugin.Metric{Name: "m", Labels: map[string]string{"state": "99"}}, nil)
	if acc.added[0].Labels["state"] != "unknown" {
		t.Errorf("expected 'unknown', got %q", acc.added[0].Labels["state"])
	}
}

func TestEnum_NoMappingForValue_LeavesUnchanged(t *testing.T) {
	e := New(Config{Mappings: []Mapping{{
		Tag:    "state",
		Values: map[string]string{"0": "stopped"},
	}}})
	acc := &captureAcc{}
	e.Start(acc)
	_ = e.Add(plugin.Metric{Name: "m", Labels: map[string]string{"state": "99"}}, nil)
	if acc.added[0].Labels["state"] != "99" {
		t.Errorf("expected unchanged, got %q", acc.added[0].Labels["state"])
	}
}

func TestEnum_TagAbsent_NoOp(t *testing.T) {
	e := New(Config{Mappings: []Mapping{{Tag: "state", Values: map[string]string{"0": "stopped"}}}})
	acc := &captureAcc{}
	e.Start(acc)
	_ = e.Add(plugin.Metric{Name: "m", Labels: map[string]string{"other": "x"}}, nil)
	if len(acc.added) != 1 {
		t.Fatal("metric should still be forwarded")
	}
}

type captureAcc struct{ added []plugin.Metric }

func (a *captureAcc) Add(m plugin.Metric)                                       { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(_ error)                                           {}
