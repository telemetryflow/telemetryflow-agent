package regex_parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/regex_parser"
)

func TestRegexParser_NamedCaptures(t *testing.T) {
	p, err := regex_parser.New(regex_parser.Config{
		Pattern: `^(?P<timestamp>\S+) (?P<level>\w+) (?P<message>.*)$`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "2026-07-25T12:34:56Z INFO service started",
	}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 forwarded, got %d", len(acc.added))
	}
	got := acc.added[0]
	if got.Labels["timestamp"] != "2026-07-25T12:34:56Z" {
		t.Errorf("timestamp label = %q", got.Labels["timestamp"])
	}
	if got.Labels["level"] != "INFO" {
		t.Errorf("level label = %q", got.Labels["level"])
	}
	if got.Labels["message"] != "service started" {
		t.Errorf("message label = %q", got.Labels["message"])
	}
}

func TestRegexParser_NoMatch_ForwardsByDefault(t *testing.T) {
	p, err := regex_parser.New(regex_parser.Config{
		Pattern: `^(?P<level>INFO|ERROR) (?P<msg>.*)$`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	p.Start(acc)

	_ = p.Add(plugin.Metric{Name: "log", Description: "not a match"}, nil)
	if len(acc.added) != 1 {
		t.Fatalf("expected 1 forwarded (passthrough), got %d", len(acc.added))
	}
	if len(acc.added[0].Labels) != 0 {
		t.Errorf("expected no labels on passthrough, got %v", acc.added[0].Labels)
	}
}

func TestRegexParser_NoMatch_DropWhenNoMatch(t *testing.T) {
	p, err := regex_parser.New(regex_parser.Config{
		Pattern:         `^(?P<level>INFO|ERROR) (?P<msg>.*)$`,
		DropWhenNoMatch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	p.Start(acc)

	_ = p.Add(plugin.Metric{Name: "log", Description: "nope"}, nil)
	_ = p.Add(plugin.Metric{Name: "log", Description: "INFO ok"}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 (drop+forward), got %d", len(acc.added))
	}
	if acc.added[0].Labels["level"] != "INFO" {
		t.Errorf("level label = %q", acc.added[0].Labels["level"])
	}
}

func TestRegexParser_PreservesExistingLabels(t *testing.T) {
	p, err := regex_parser.New(regex_parser.Config{
		Pattern: `^(?P<level>\w+) (?P<msg>.*)$`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "ERROR boom",
		Labels:      map[string]string{"host": "node-1"},
	}, nil)

	got := acc.added[0]
	if got.Labels["host"] != "node-1" {
		t.Errorf("existing label lost: %v", got.Labels)
	}
	if got.Labels["level"] != "ERROR" {
		t.Errorf("level label = %q", got.Labels["level"])
	}
}

func TestRegexParser_InvalidPattern(t *testing.T) {
	if _, err := regex_parser.New(regex_parser.Config{Pattern: "["}); err == nil {
		t.Error("expected regex compile error")
	}
}

func TestRegexParser_EmptyPattern(t *testing.T) {
	if _, err := regex_parser.New(regex_parser.Config{}); err == nil {
		t.Error("expected empty pattern error")
	}
}

func TestRegexParser_Name(t *testing.T) {
	p, err := regex_parser.New(regex_parser.Config{Pattern: `^(?P<x>.*)$`})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "regex_parser" {
		t.Errorf("name = %q", p.Name())
	}
}

func TestRegexParser_StopReturns(t *testing.T) {
	p, err := regex_parser.New(regex_parser.Config{Pattern: `^(?P<x>.*)$`})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Errorf("stop returned error: %v", err)
	}
}

func TestRegexParser_TranslationTraceFriendly(t *testing.T) {
	// Ensure description carries forward unchanged when the pattern matches
	// and labels are added (no surprising mutation).
	p, err := regex_parser.New(regex_parser.Config{
		Pattern: `^(?P<k>v)$`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	p.Start(acc)
	_ = p.Add(plugin.Metric{Name: "m", Description: "v"}, nil)
	if !strings.Contains(acc.added[0].Description, "v") {
		t.Errorf("description should be preserved, got %q", acc.added[0].Description)
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
