package filter

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func TestFilter_DefaultKeep_Forwards(t *testing.T) {
	f := New(Config{DefaultAction: ActionKeep})
	acc := &captureAcc{}
	f.Start(acc)

	_ = f.Add(plugin.Metric{Name: "a"}, nil)
	_ = f.Add(plugin.Metric{Name: "b"}, nil)

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 forwarded, got %d", got)
	}
}

func TestFilter_DefaultDrop_DropsAll(t *testing.T) {
	f := New(Config{DefaultAction: ActionDrop})
	acc := &captureAcc{}
	f.Start(acc)

	_ = f.Add(plugin.Metric{Name: "a"}, nil)

	if got := len(acc.added); got != 0 {
		t.Fatalf("expected 0 forwarded with default drop, got %d", got)
	}
}

func TestFilter_RuleKeepByNameRegex(t *testing.T) {
	f := New(Config{
		Rules: []Rule{
			{Action: ActionKeep, MetricName: "^keep\\..*"},
			{Action: ActionDrop, MetricName: ".*"},
		},
	})
	acc := &captureAcc{}
	f.Start(acc)

	_ = f.Add(plugin.Metric{Name: "keep.this"}, nil)
	_ = f.Add(plugin.Metric{Name: "drop.me"}, nil)
	_ = f.Add(plugin.Metric{Name: "keep.also"}, nil)

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 kept, got %d", got)
	}
	if acc.added[0].Name != "keep.this" || acc.added[1].Name != "keep.also" {
		t.Errorf("unexpected names: %v %v", acc.added[0].Name, acc.added[1].Name)
	}
}

func TestFilter_RuleByTagPresence(t *testing.T) {
	f := New(Config{
		Rules: []Rule{
			{Action: ActionKeep, Tag: &TagMatch{Key: "service"}},
			{Action: ActionDrop, MetricName: ".*"},
		},
	})
	acc := &captureAcc{}
	f.Start(acc)

	_ = f.Add(plugin.Metric{Name: "a", Labels: map[string]string{"service": "x"}}, nil)
	_ = f.Add(plugin.Metric{Name: "b", Labels: map[string]string{"other": "y"}}, nil)

	if got := len(acc.added); got != 1 {
		t.Fatalf("expected 1 kept (tag match), got %d", got)
	}
	if acc.added[0].Name != "a" {
		t.Errorf("unexpected name kept: %s", acc.added[0].Name)
	}
}

func TestFilter_RuleByTagValueRegex(t *testing.T) {
	f := New(Config{
		Rules: []Rule{
			{Action: ActionKeep, Tag: &TagMatch{Key: "env", ValueMatch: "^prod.*"}},
			{Action: ActionDrop, MetricName: ".*"},
		},
	})
	acc := &captureAcc{}
	f.Start(acc)

	_ = f.Add(plugin.Metric{Name: "a", Labels: map[string]string{"env": "prod-us-east"}}, nil)
	_ = f.Add(plugin.Metric{Name: "b", Labels: map[string]string{"env": "staging"}}, nil)
	_ = f.Add(plugin.Metric{Name: "c", Labels: map[string]string{"env": "production"}}, nil)

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 kept (env=prod*), got %d", got)
	}
}

func TestFilter_FirstMatchingRuleWins(t *testing.T) {
	f := New(Config{
		Rules: []Rule{
			{Action: ActionDrop, MetricName: "^drop"},
			{Action: ActionKeep, MetricName: "^drop"}, // unreachable
		},
	})
	acc := &captureAcc{}
	f.Start(acc)

	_ = f.Add(plugin.Metric{Name: "drop.this"}, nil)
	if got := len(acc.added); got != 0 {
		t.Fatalf("expected drop to win, got %d forwarded", got)
	}
}

func TestFilter_Name(t *testing.T) {
	if New(DefaultConfig()).Name() != "filter" {
		t.Error("name mismatch")
	}
}

// captureAcc records Add calls for assertion.
type captureAcc struct {
	added []plugin.Metric
	errs  []error
}

func (a *captureAcc) Add(m plugin.Metric)                                       { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(err error)                                        { a.errs = append(a.errs, err) }
