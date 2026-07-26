package keep_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/keep"
)

func TestKeep_ForwardsOnlyMatching(t *testing.T) {
	k, err := keep.New(keep.Config{Patterns: []string{"^system\\..*"}})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = k.Start(acc)
	_ = k.Add(plugin.Metric{Name: "system.cpu"}, nil)
	_ = k.Add(plugin.Metric{Name: "debug.log"}, nil)
	_ = k.Add(plugin.Metric{Name: "system.mem"}, nil)
	if len(acc.added) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(acc.added))
	}
}

func TestKeep_NoPatterns_KeepsNothing(t *testing.T) {
	k, _ := keep.New(keep.Config{})
	acc := &captureAcc{}
	_ = k.Start(acc)
	_ = k.Add(plugin.Metric{Name: "anything"}, nil)
	if len(acc.added) != 0 {
		t.Fatalf("expected nothing kept, got %d", len(acc.added))
	}
}

func TestKeep_InvalidRegex(t *testing.T) {
	if _, err := keep.New(keep.Config{Patterns: []string{"("}}); err == nil {
		t.Error("expected regex error")
	}
}

type captureAcc struct{ added []plugin.Metric }

func (a *captureAcc) Add(m plugin.Metric)                                              { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time)  {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(_ error)                                                 {}
