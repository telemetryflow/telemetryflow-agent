package grok_parser_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/grok_parser"
)

func TestGrokParser_Translate_TimestampLevelGreedy(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "app.log",
		Description: "2026-07-25T12:34:56Z INFO service started on port 8080",
	}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 forwarded, got %d", len(acc.added))
	}
	got := acc.added[0]
	if got.Labels["timestamp"] != "2026-07-25T12:34:56Z" {
		t.Errorf("timestamp = %q", got.Labels["timestamp"])
	}
	if got.Labels["level"] != "INFO" {
		t.Errorf("level = %q", got.Labels["level"])
	}
	if got.Labels["message"] != "service started on port 8080" {
		t.Errorf("message = %q", got.Labels["message"])
	}
}

func TestGrokParser_UnlabelledPatternNonCapturing(t *testing.T) {
	// An unlabelled %{SPACE} should not produce a label even when matched.
	p, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{WORD:first}%{SPACE}%{WORD:second}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "alpha beta",
	}, nil)

	got := acc.added[0]
	if got.Labels["first"] != "alpha" {
		t.Errorf("first = %q", got.Labels["first"])
	}
	if got.Labels["second"] != "beta" {
		t.Errorf("second = %q", got.Labels["second"])
	}
	for k := range got.Labels {
		if k != "first" && k != "second" {
			t.Errorf("unexpected label %q", k)
		}
	}
}

func TestGrokParser_NoMatch_DropsByDefault(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{LOGLEVEL:level} %{GREEDYDATA:msg}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "no leading log level here",
	}, nil)

	if len(acc.added) != 0 {
		t.Fatalf("expected drop (0 forwarded), got %d", len(acc.added))
	}
}

func TestGrokParser_NoMatch_KeepOriginal(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern:      `%{LOGLEVEL:level} %{GREEDYDATA:msg}`,
		KeepOriginal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "no level",
	}, nil)

	if len(acc.added) != 1 {
		t.Fatalf("expected passthrough, got %d", len(acc.added))
	}
	if len(acc.added[0].Labels) != 0 {
		t.Errorf("no labels should be added on mismatch, got %v", acc.added[0].Labels)
	}
}

func TestGrokParser_KeepOriginal_PreservesDescription(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern:      `%{LOGLEVEL:level}`,
		KeepOriginal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "INFO something",
	}, nil)

	if acc.added[0].Description != "INFO something" {
		t.Errorf("description should be preserved, got %q", acc.added[0].Description)
	}
}

func TestGrokParser_DefaultClearsDescription(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{LOGLEVEL:level}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "log",
		Description: "INFO something",
	}, nil)

	if acc.added[0].Description != "" {
		t.Errorf("description should be cleared by default, got %q", acc.added[0].Description)
	}
}

func TestGrokParser_MetricNamePrefix(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern:          `%{LOGLEVEL:level}`,
		MetricNamePrefix: "logs.parsed",
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "input",
		Description: "INFO something",
	}, nil)

	if acc.added[0].Name != "logs.parsed" {
		t.Errorf("name = %q, want logs.parsed", acc.added[0].Name)
	}
}

func TestGrokParser_NumberAndIP(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{IP:client} %{NUMBER:status} %{GREEDYDATA:path}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{
		Name:        "http",
		Description: "10.0.0.1 200 /index.html",
	}, nil)

	got := acc.added[0]
	if got.Labels["client"] != "10.0.0.1" {
		t.Errorf("client = %q", got.Labels["client"])
	}
	if got.Labels["status"] != "200" {
		t.Errorf("status = %q", got.Labels["status"])
	}
	if got.Labels["path"] != "/index.html" {
		t.Errorf("path = %q", got.Labels["path"])
	}
}

func TestGrokParser_TypeAnnotationIgnored(t *testing.T) {
	// Telegraf-style %{NUMBER:bytes:int} should compile; the type is ignored
	// (labels are always strings, matching Telegraf behaviour).
	p, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{NUMBER:bytes:int}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	_ = p.Start(acc)

	_ = p.Add(plugin.Metric{Name: "log", Description: "128"}, nil)
	if acc.added[0].Labels["bytes"] != "128" {
		t.Errorf("bytes = %q", acc.added[0].Labels["bytes"])
	}
}

func TestGrokParser_UnknownPatternRejected(t *testing.T) {
	if _, err := grok_parser.New(grok_parser.Config{
		Pattern: `%{NONEXISTENT:label}`,
	}); err == nil {
		t.Error("expected error for unknown grok pattern")
	}
}

func TestGrokParser_EmptyPattern(t *testing.T) {
	if _, err := grok_parser.New(grok_parser.Config{}); err == nil {
		t.Error("expected error for empty pattern")
	}
}

func TestGrokParser_Name(t *testing.T) {
	p, err := grok_parser.New(grok_parser.Config{Pattern: `%{GREEDYDATA:m}`})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "grok_parser" {
		t.Errorf("name = %q", p.Name())
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
