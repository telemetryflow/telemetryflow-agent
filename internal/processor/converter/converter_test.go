package converter

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func TestConverter_RoundAll(t *testing.T) {
	c, err := New(Config{Round: []RoundingSpec{{Decimals: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	c.Start(acc)
	_ = c.Add(plugin.Metric{Name: "m", Value: 1.23456}, nil)
	if acc.added[0].Value != 1.23 {
		t.Errorf("expected 1.23, got %f", acc.added[0].Value)
	}
}

func TestConverter_RoundByRegex(t *testing.T) {
	c, err := New(Config{Round: []RoundingSpec{
		{NameRegex: "^latency\\.", Decimals: 0},
	}})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	c.Start(acc)
	_ = c.Add(plugin.Metric{Name: "latency.http", Value: 12.7}, nil)
	_ = c.Add(plugin.Metric{Name: "size.db", Value: 12.7}, nil)
	if acc.added[0].Value != 13 {
		t.Errorf("expected 13, got %f", acc.added[0].Value)
	}
	if acc.added[1].Value != 12.7 {
		t.Errorf("unmatched metric should be unchanged, got %f", acc.added[1].Value)
	}
}

func TestConverter_InvalidRegex(t *testing.T) {
	if _, err := New(Config{Round: []RoundingSpec{{NameRegex: "["}}}); err == nil {
		t.Error("expected regex error")
	}
}

type captureAcc struct{ added []plugin.Metric }

func (a *captureAcc) Add(m plugin.Metric)                                       { a.added = append(a.added, m) }
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(_ error)                                           {}
