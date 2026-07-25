// Tests for the log_to_metric extractor processor.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package log_to_metric_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/log_to_metric"
)

func TestLogToMetric_CounterOnMatch(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{Name: "app.http.request", Pattern: `GET.*`},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{
		Name:        "log.nginx",
		Description: "GET /health 200",
	}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// First emitted: original log forward; second: derived counter.
	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 metrics (1 log + 1 derived), got %d", got)
	}
	derived := acc.added[1]
	if derived.Name != "app.http.request" {
		t.Errorf("derived name = %q, want app.http.request", derived.Name)
	}
	if derived.Type != plugin.MetricTypeCounter {
		t.Errorf("derived type = %q, want counter", derived.Type)
	}
	if derived.Value != 1 {
		t.Errorf("derived value = %v, want 1", derived.Value)
	}
}

func TestLogToMetric_NoMatch_NoDerivedMetric(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{Name: "app.http.get", Pattern: `^GET`},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{
		Name:        "log.nginx",
		Description: "POST /api",
	}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Only the forwarded original log should be present.
	if got := len(acc.added); got != 1 {
		t.Fatalf("expected 1 metric (original only), got %d", got)
	}
	if acc.added[0].Description != "POST /api" {
		t.Errorf("original log not forwarded: %v", acc.added[0])
	}
}

func TestLogToMetric_GaugeFromGroup(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{
				Name:           "app.request.duration_ms",
				Pattern:        `duration=(\d+)ms`,
				MetricType:     "gauge",
				ValueFromGroup: 1,
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{
		Name:        "log.app",
		Description: "duration=1234ms",
	}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 metrics, got %d", got)
	}
	derived := acc.added[1]
	if derived.Type != plugin.MetricTypeGauge {
		t.Errorf("type = %q, want gauge", derived.Type)
	}
	if derived.Value != 1234 {
		t.Errorf("value = %v, want 1234", derived.Value)
	}
}

func TestLogToMetric_TagFromGroup(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{
				Name:       "app.http.tagged",
				Pattern:    `method=(\w+)\s+status=(\d+)`,
				MetricType: "counter",
				TagFromGroup: map[int]string{
					1: "method",
					2: "status",
				},
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{
		Name:        "log.app",
		Description: "method=GET status=200",
		Labels:      map[string]string{"host": "node-1"},
	}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	derived := acc.added[1]
	if got := derived.Labels["method"]; got != "GET" {
		t.Errorf("method label = %q, want GET", got)
	}
	if got := derived.Labels["status"]; got != "200" {
		t.Errorf("status label = %q, want 200", got)
	}
	// Original labels must be preserved.
	if got := derived.Labels["host"]; got != "node-1" {
		t.Errorf("host label = %q, want node-1", got)
	}
}

func TestLogToMetric_StaticTagsMerged(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{
				Name:       "app.hit",
				Pattern:    `hit`,
				MetricType: "counter",
				Tags:       map[string]string{"source": "log_to_metric"},
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{Description: "hit"}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	derived := acc.added[1]
	if got := derived.Labels["source"]; got != "log_to_metric" {
		t.Errorf("source label = %q, want log_to_metric", got)
	}
}

func TestLogToMetric_BadRegexReturnsErrorOnStart(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{Name: "bad", Pattern: `(?P<broken>`},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err == nil {
		t.Fatal("expected error from Start for bad regex, got nil")
	}
}

func TestLogToMetric_OriginalLogForwarded(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{Name: "app.hit", Pattern: `hit`},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	orig := plugin.Metric{
		Name:        "log.nginx",
		Description: "this line hit the regex",
		Labels:      map[string]string{"file": "/var/log/nginx.log"},
	}
	if err := p.Add(orig, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if len(acc.added) == 0 {
		t.Fatal("expected at least one forwarded metric")
	}
	first := acc.added[0]
	if first.Name != orig.Name || first.Description != orig.Description {
		t.Errorf("original metric not preserved: got %+v", first)
	}
	if first.Labels["file"] != "/var/log/nginx.log" {
		t.Errorf("original labels not preserved: %+v", first.Labels)
	}
}

func TestLogToMetric_DefaultTypeIsCounter(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{Name: "app.default", Pattern: `.+`}, // MetricType omitted
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{Description: "anything"}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	derived := acc.added[1]
	if derived.Type != plugin.MetricTypeCounter {
		t.Errorf("default type = %q, want counter", derived.Type)
	}
	if derived.Value != 1 {
		t.Errorf("default value = %v, want 1", derived.Value)
	}
}

func TestLogToMetric_MultipleRulesAllMatch(t *testing.T) {
	p := log_to_metric.New(log_to_metric.Config{
		Rules: []log_to_metric.Rule{
			{Name: "app.r1", Pattern: `foo`},
			{Name: "app.r2", Pattern: `bar`},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := p.Add(plugin.Metric{Description: "foo bar"}, nil); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// 1 original + 2 derived.
	if got := len(acc.added); got != 3 {
		t.Fatalf("expected 3 metrics, got %d", got)
	}
	names := map[string]bool{
		acc.added[1].Name: true,
		acc.added[2].Name: true,
	}
	if !names["app.r1"] || !names["app.r2"] {
		t.Errorf("expected both app.r1 and app.r2 derived, got %v", names)
	}
}

func TestLogToMetric_Name(t *testing.T) {
	if log_to_metric.New(log_to_metric.DefaultConfig()).Name() != "log_to_metric" {
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
