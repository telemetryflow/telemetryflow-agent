// Package tail_sampling implements a StreamingProcessor that applies
// probabilistic + policy-based sampling to high-volume metric streams. Policies
// are evaluated in declaration order; the first matching policy determines the
// fate of each metric (forward, drop, or sample). Metrics that match no policy
// are forwarded unchanged (default keep).
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package tail_sampling

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("tail_sampling", func() plugin.StreamingProcessor {
		return New(DefaultConfig())
	})
}

// PolicyType selects the action taken when a policy's filter matches.
type PolicyType string

const (
	// PolicyAlways forwards every metric matched by the policy's filter.
	PolicyAlways PolicyType = "always"
	// PolicyProbabilistic forwards a metric matched by the policy's filter
	// with probability SamplingPercentage / 100, using a deterministic hash
	// so the same metric always produces the same decision.
	PolicyProbabilistic PolicyType = "probabilistic"
	// PolicyDrop drops every metric matched by the policy's filter.
	PolicyDrop PolicyType = "drop"
)

// Config controls the tail_sampling processor.
type Config struct {
	// Policies is an ordered list. The first matching policy wins; metrics
	// that match no policy are forwarded unchanged.
	Policies []Policy `yaml:"policies" json:"policies"`
}

// DefaultConfig returns a Config with no policies (forwards everything).
func DefaultConfig() Config { return Config{} }

// Policy is a single sampling rule.
type Policy struct {
	// Name is a human-readable identifier used in error messages and logs.
	Name string `yaml:"name" json:"name"`

	// Type selects the action taken when Filter matches.
	Type PolicyType `yaml:"type" json:"type"`

	// SamplingPercentage is used when Type == PolicyProbabilistic. Range
	// 0.0–100.0. 0 drops everything; 100 forwards everything.
	SamplingPercentage float64 `yaml:"sampling_percentage" json:"sampling_percentage"`

	// Filter selects which metrics the policy applies to. An empty filter
	// matches every metric.
	Filter FilterSpec `yaml:"filter" json:"filter"`
}

// FilterSpec selects the metrics a policy applies to. All non-zero fields in
// a filter must match (AND within a filter).
type FilterSpec struct {
	// MetricName is a regex matched against metric.Name. Empty = any.
	MetricName string `yaml:"metric_name,omitempty" json:"metric_name,omitempty"`

	// Label is a tag key+value pair that must be present. Empty Key = any.
	Label *LabelMatch `yaml:"label,omitempty" json:"label,omitempty"`
}

// LabelMatch matches a tag key with an optional value regex. A non-empty
// ValueRegex anchors on the value; an empty ValueRegex requires only key
// presence.
type LabelMatch struct {
	Key        string `yaml:"key" json:"key"`
	ValueRegex string `yaml:"value_regex,omitempty" json:"value_regex,omitempty"`
}

// compiledPolicy is a Policy with its regexes pre-compiled.
type compiledPolicy struct {
	name       string
	typ        PolicyType
	percentage float64
	nameRe     *regexp.Regexp
	labelKey   string
	labelValRe *regexp.Regexp
}

// TailSampling is a StreamingProcessor that applies policy-based sampling.
type TailSampling struct {
	cfg      Config
	policies []compiledPolicy
	acc      plugin.Accumulator
}

// New returns a processor that will compile its filters on Start.
func New(cfg Config) *TailSampling { return &TailSampling{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (t *TailSampling) Name() string { return "tail_sampling" }

// Start compiles all filter regexes and stores the downstream accumulator.
// Returns the first compile error encountered; remaining policies are not
// compiled.
func (t *TailSampling) Start(acc plugin.Accumulator) error {
	t.acc = acc
	t.policies = t.policies[:0]
	for _, p := range t.cfg.Policies {
		cp := compiledPolicy{
			name:       p.Name,
			typ:        p.Type,
			percentage: p.SamplingPercentage,
		}
		if p.Filter.MetricName != "" {
			re, err := regexp.Compile(p.Filter.MetricName)
			if err != nil {
				return fmt.Errorf("tail_sampling: policy %q: bad metric_name regex %q: %w", p.Name, p.Filter.MetricName, err)
			}
			cp.nameRe = re
		}
		if p.Filter.Label != nil && p.Filter.Label.Key != "" {
			cp.labelKey = p.Filter.Label.Key
			if p.Filter.Label.ValueRegex != "" {
				re, err := regexp.Compile(p.Filter.Label.ValueRegex)
				if err != nil {
					return fmt.Errorf("tail_sampling: policy %q: bad label value_regex %q: %w", p.Name, p.Filter.Label.ValueRegex, err)
				}
				cp.labelValRe = re
			}
		}
		t.policies = append(t.policies, cp)
	}
	return nil
}

// Add walks policies in order; the first matching policy decides. If no
// policy matches, the metric is forwarded unchanged.
func (t *TailSampling) Add(m plugin.Metric, _ plugin.Accumulator) error {
	for _, p := range t.policies {
		if !p.matchMetric(m) {
			continue
		}
		if p.shouldKeep(m) && t.acc != nil {
			t.acc.Add(m)
		}
		return nil
	}
	if t.acc != nil {
		t.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (t *TailSampling) Stop() error { return nil }

// matchMetric reports whether the policy's filter matches the metric.
func (p compiledPolicy) matchMetric(m plugin.Metric) bool {
	if p.nameRe != nil && !p.nameRe.MatchString(m.Name) {
		return false
	}
	if p.labelKey != "" {
		v, ok := m.Labels[p.labelKey]
		if !ok {
			return false
		}
		if p.labelValRe != nil && !p.labelValRe.MatchString(v) {
			return false
		}
	}
	return true
}

// shouldKeep applies the policy action to a metric that already matched the
// filter.
func (p compiledPolicy) shouldKeep(m plugin.Metric) bool {
	switch p.typ {
	case PolicyAlways:
		return true
	case PolicyDrop:
		return false
	case PolicyProbabilistic:
		return sampleHash(m, p.percentage)
	default:
		return true
	}
}

// sampleHash returns true when the metric should be forwarded based on a
// deterministic FNV-1a hash of (name + sorted label key/value pairs) modulo
// 100. The same input always yields the same decision, so re-running the
// pipeline produces identical sampling outcomes.
func sampleHash(m plugin.Metric, percentage float64) bool {
	if percentage <= 0 {
		return false
	}
	if percentage >= 100 {
		return true
	}
	h := fnv.New64a()
	h.Write([]byte(m.Name))
	// Sorted label keys for cross-iteration determinism.
	keys := make([]string, 0, len(m.Labels))
	for k := range m.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(m.Labels[k]))
	}
	bucket := float64(h.Sum64() % 100)
	return bucket < percentage
}
