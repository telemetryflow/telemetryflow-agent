package defaults_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/defaults"
)

func TestDefaults_FillsMissing(t *testing.T) {
	d := defaults.New(defaults.Config{Tags: map[string]string{"region": "us-east-1", "env": "prod"}})
	acc := &captureAcc{}
	_ = d.Start(acc)
	_ = d.Add(plugin.Metric{Name: "m", Labels: map[string]string{"env": "staging"}}, nil)

	if acc.added[0].Labels["region"] != "us-east-1" {
		t.Errorf("expected region default, got %q", acc.added[0].Labels["region"])
	}
	if acc.added[0].Labels["env"] != "staging" {
		t.Errorf("existing tag should NOT be overwritten, got %q", acc.added[0].Labels["env"])
	}
}

func TestDefaults_FillsWhenEmpty(t *testing.T) {
	d := defaults.New(defaults.Config{Tags: map[string]string{"env": "prod"}})
	acc := &captureAcc{}
	_ = d.Start(acc)
	_ = d.Add(plugin.Metric{Name: "m", Labels: map[string]string{"env": ""}}, nil)
	if acc.added[0].Labels["env"] != "prod" {
		t.Errorf("empty value should be replaced with default, got %q", acc.added[0].Labels["env"])
	}
}

func TestDefaults_NilLabelsMap(t *testing.T) {
	d := defaults.New(defaults.Config{Tags: map[string]string{"env": "prod"}})
	acc := &captureAcc{}
	_ = d.Start(acc)
	_ = d.Add(plugin.Metric{Name: "m"}, nil)
	if acc.added[0].Labels["env"] != "prod" {
		t.Errorf("default should be applied to nil labels, got %q", acc.added[0].Labels["env"])
	}
}

type captureAcc struct{ added []plugin.Metric }

func (a *captureAcc) Add(m plugin.Metric)                                              { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time)  {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(_ error)                                                 {}
