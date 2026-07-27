package drop_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/drop"
)

func TestDrop_NoPatterns_ForwardsAll(t *testing.T) {
	d, err := drop.New(drop.Config{})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = d.Start(acc)
	_ = d.Add(plugin.Metric{Name: "a"}, nil)
	_ = d.Add(plugin.Metric{Name: "b"}, nil)
	if len(acc.added) != 2 {
		t.Fatalf("expected 2 forwarded, got %d", len(acc.added))
	}
}

func TestDrop_MatchDrops(t *testing.T) {
	d, err := drop.New(drop.Config{Patterns: []string{"^debug\\."}})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = d.Start(acc)
	_ = d.Add(plugin.Metric{Name: "debug.something"}, nil)
	_ = d.Add(plugin.Metric{Name: "system.cpu"}, nil)
	if len(acc.added) != 1 || acc.added[0].Name != "system.cpu" {
		t.Fatalf("expected only system.cpu to survive, got %v", acc.added)
	}
}

func TestDrop_InvalidRegex_ReturnsError(t *testing.T) {
	if _, err := drop.New(drop.Config{Patterns: []string{"["}}); err == nil {
		t.Error("expected regex compile error")
	}
}

func TestDrop_Name(t *testing.T) {
	d, _ := drop.New(drop.Config{})
	if d.Name() != "drop" {
		t.Error("name mismatch")
	}
}

type captureAcc struct {
	added []plugin.Metric
}

func (a *captureAcc) Add(m plugin.Metric)                                              { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time)  {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(_ error)                                                 {}
