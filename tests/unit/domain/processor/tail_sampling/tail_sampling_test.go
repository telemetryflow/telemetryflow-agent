// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package tail_sampling_test

import (
	"fmt"
	"hash/fnv"
	"sort"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/tail_sampling"
)

func TestTailSampling_AlwaysEmptyFilter_ForwardsAll(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{Name: "all", Type: tail_sampling.PolicyAlways},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "a"}, nil)
	_ = p.Add(plugin.Metric{Name: "b"}, nil)
	_ = p.Add(plugin.Metric{Name: "c"}, nil)

	if got := len(acc.added); got != 3 {
		t.Fatalf("expected 3 forwarded, got %d", got)
	}
}

func TestTailSampling_DropByNameRegex_DropsMatching(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{Name: "drop-debug", Type: tail_sampling.PolicyDrop, Filter: tail_sampling.FilterSpec{MetricName: "^debug\\."}},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "debug.foo"}, nil)
	_ = p.Add(plugin.Metric{Name: "system.cpu"}, nil)
	_ = p.Add(plugin.Metric{Name: "debug.bar"}, nil)
	_ = p.Add(plugin.Metric{Name: "system.mem"}, nil)

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 forwarded, got %d", got)
	}
	if acc.added[0].Name != "system.cpu" || acc.added[1].Name != "system.mem" {
		t.Errorf("unexpected names: %v", acc.added)
	}
}

func TestTailSampling_Probabilistic_Zero_DropsAll(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name:               "p0",
				Type:               tail_sampling.PolicyProbabilistic,
				SamplingPercentage: 0,
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 100; i++ {
		_ = p.Add(plugin.Metric{Name: fmt.Sprintf("m.%d", i)}, nil)
	}

	if got := len(acc.added); got != 0 {
		t.Fatalf("expected 0 forwarded at 0%%, got %d", got)
	}
}

func TestTailSampling_Probabilistic_Hundred_ForwardsAll(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name:               "p100",
				Type:               tail_sampling.PolicyProbabilistic,
				SamplingPercentage: 100,
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for i := 0; i < 100; i++ {
		_ = p.Add(plugin.Metric{Name: fmt.Sprintf("m.%d", i)}, nil)
	}

	if got := len(acc.added); got != 100 {
		t.Fatalf("expected 100 forwarded at 100%%, got %d", got)
	}
}

func TestTailSampling_Probabilistic_Fifty_AboutHalfAndDeterministic(t *testing.T) {
	const n = 200
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = fmt.Sprintf("metric.series.%d", i)
	}

	cfg := tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name:               "p50",
				Type:               tail_sampling.PolicyProbabilistic,
				SamplingPercentage: 50,
			},
		},
	}

	// First pass: collect outcomes.
	p := tail_sampling.New(cfg)
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, name := range names {
		_ = p.Add(plugin.Metric{Name: name}, nil)
	}
	firstPass := make(map[string]bool, n)
	for _, m := range acc.added {
		firstPass[m.Name] = true
	}

	kept := len(acc.added)
	// Allow ±20% tolerance around the expected 100 / 200.
	if kept < 60 || kept > 140 {
		t.Fatalf("expected ~50%% of %d forwarded (60..140), got %d", n, kept)
	}

	// Determinism: re-run and compare decisions.
	p2 := tail_sampling.New(cfg)
	acc2 := &captureAcc{}
	if err := p2.Start(acc2); err != nil {
		t.Fatalf("Start (run 2): %v", err)
	}
	for _, name := range names {
		_ = p2.Add(plugin.Metric{Name: name}, nil)
	}
	if len(acc2.added) != kept {
		t.Fatalf("non-deterministic: run 1 kept %d, run 2 kept %d", kept, len(acc2.added))
	}
	for _, m := range acc2.added {
		if !firstPass[m.Name] {
			t.Fatalf("non-deterministic: %q kept on run 2 but dropped on run 1", m.Name)
		}
	}

	// Spot-check that specific decisions match the documented hash.
	for _, name := range names[:10] {
		wantKept := hashBucket(name, nil) < 50
		if gotKept := firstPass[name]; gotKept != wantKept {
			t.Errorf("metric %q: got kept=%v, want %v (hash bucket mismatch)", name, gotKept, wantKept)
		}
	}
}

func TestTailSampling_LabelFilter_OnlyMatchingAffected(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name: "drop-prod",
				Type: tail_sampling.PolicyDrop,
				Filter: tail_sampling.FilterSpec{
					Label: &tail_sampling.LabelMatch{Key: "env", ValueRegex: "^prod$"},
				},
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "m", Labels: map[string]string{"env": "prod"}}, nil)
	_ = p.Add(plugin.Metric{Name: "m", Labels: map[string]string{"env": "staging"}}, nil)
	_ = p.Add(plugin.Metric{Name: "m", Labels: map[string]string{"env": "production"}}, nil) // regex is anchored to ^prod$
	_ = p.Add(plugin.Metric{Name: "m"}, nil)                                                 // no env label

	if got := len(acc.added); got != 3 {
		t.Fatalf("expected 3 forwarded (only env=prod dropped), got %d", got)
	}
	for _, m := range acc.added {
		if m.Labels["env"] == "prod" {
			t.Errorf("env=prod should have been dropped: %v", m)
		}
	}
}

func TestTailSampling_LabelPresenceFilter(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name: "tagged-drop",
				Type: tail_sampling.PolicyDrop,
				Filter: tail_sampling.FilterSpec{
					Label: &tail_sampling.LabelMatch{Key: "service"}, // empty regex = presence
				},
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "a", Labels: map[string]string{"service": "x"}}, nil) // dropped
	_ = p.Add(plugin.Metric{Name: "b", Labels: map[string]string{"other": "y"}}, nil)   // kept
	_ = p.Add(plugin.Metric{Name: "c"}, nil)                                            // kept

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 forwarded, got %d", got)
	}
	if acc.added[0].Name != "b" || acc.added[1].Name != "c" {
		t.Errorf("unexpected names: %v", acc.added)
	}
}

func TestTailSampling_FirstMatchingPolicyWins(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name:   "always-first",
				Type:   tail_sampling.PolicyAlways,
				Filter: tail_sampling.FilterSpec{MetricName: "^critical\\."},
			},
			{
				Name:   "drop-second",
				Type:   tail_sampling.PolicyDrop,
				Filter: tail_sampling.FilterSpec{MetricName: "^critical\\."}, // unreachable
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "critical.thing"}, nil)
	if got := len(acc.added); got != 1 {
		t.Fatalf("expected first-match (always) to win -> 1 forwarded, got %d", got)
	}
}

func TestTailSampling_NoPolicyMatch_DefaultKeep(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name:   "drop-rare",
				Type:   tail_sampling.PolicyDrop,
				Filter: tail_sampling.FilterSpec{MetricName: "^rare\\."},
			},
		},
	})
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "common.metric"}, nil) // no policy matches
	_ = p.Add(plugin.Metric{Name: "rare.thing"}, nil)    // dropped

	if got := len(acc.added); got != 1 {
		t.Fatalf("expected default-keep for non-matching, got %d", got)
	}
	if acc.added[0].Name != "common.metric" {
		t.Errorf("unexpected name: %v", acc.added[0])
	}
}

func TestTailSampling_EmptyConfig_ForwardsAll(t *testing.T) {
	p := tail_sampling.New(tail_sampling.DefaultConfig())
	acc := &captureAcc{}
	if err := p.Start(acc); err != nil {
		t.Fatalf("Start: %v", err)
	}

	_ = p.Add(plugin.Metric{Name: "a"}, nil)
	_ = p.Add(plugin.Metric{Name: "b"}, nil)

	if got := len(acc.added); got != 2 {
		t.Fatalf("expected 2 forwarded with empty config, got %d", got)
	}
}

func TestTailSampling_BadRegex_ReturnsError(t *testing.T) {
	p := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{Name: "bad", Type: tail_sampling.PolicyDrop, Filter: tail_sampling.FilterSpec{MetricName: "["}},
		},
	})
	if err := p.Start(&captureAcc{}); err == nil {
		t.Fatal("expected compile error on bad metric_name regex")
	}

	p2 := tail_sampling.New(tail_sampling.Config{
		Policies: []tail_sampling.Policy{
			{
				Name:   "bad-label",
				Type:   tail_sampling.PolicyDrop,
				Filter: tail_sampling.FilterSpec{Label: &tail_sampling.LabelMatch{Key: "env", ValueRegex: "("}},
			},
		},
	})
	if err := p2.Start(&captureAcc{}); err == nil {
		t.Fatal("expected compile error on bad label value_regex")
	}
}

func TestTailSampling_Name(t *testing.T) {
	if got := tail_sampling.New(tail_sampling.DefaultConfig()).Name(); got != "tail_sampling" {
		t.Errorf("name mismatch: %q", got)
	}
}

// hashBucket replicates the documented sampling hash so tests can predict the
// decision for a specific (name, labels) pair without exposing internals.
// MUST stay in sync with sampleHash in tail_sampling.go.
func hashBucket(name string, labels map[string]string) float64 {
	h := fnv.New64a()
	h.Write([]byte(name))
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(labels[k]))
	}
	return float64(h.Sum64() % 100)
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
