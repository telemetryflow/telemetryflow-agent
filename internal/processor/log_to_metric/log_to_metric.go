// Package log_to_metric implements a StreamingProcessor that extracts metrics
// from log lines stored in metric.Description. Each rule applies a regex to
// the log line; on match it emits a new counter or gauge metric derived from
// capture groups and static tags. The original log metric is forwarded
// unchanged so the log keeps flowing downstream.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package log_to_metric

import (
	"regexp"
	"strconv"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("log_to_metric", func() plugin.StreamingProcessor {
		return New(DefaultConfig())
	})
}

// Rule defines one extraction rule.
type Rule struct {
	// Name is the output metric name (e.g. "app.http.5xx").
	Name string `yaml:"name" json:"name"`

	// Pattern is a regex applied to metric.Description (the log line).
	// If the pattern has no captures, presence of any match increments
	// the counter by 1. If it has group captures, the first capture
	// group is parsed as float for gauge metrics (see ValueFromGroup).
	Pattern string `yaml:"pattern" json:"pattern"`

	// MetricType: "counter" (default) or "gauge".
	MetricType string `yaml:"metric_type" json:"metric_type"`

	// ValueFromGroup is the regex capture group index (1-based) to use as
	// the metric value for gauges. 0 = no extraction (use counter=1).
	ValueFromGroup int `yaml:"value_from_group" json:"value_from_group"`

	// Tags is static tags added to every emitted metric.
	Tags map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// TagFromGroup maps group index to tag name. e.g. {1: "method"} makes
	// group 1's value available as the "method" label.
	TagFromGroup map[int]string `yaml:"tag_from_group,omitempty" json:"tag_from_group,omitempty"`

	compiled *regexp.Regexp `yaml:"-" json:"-"`
}

// Config holds extraction rules.
type Config struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// DefaultConfig returns an empty (no-op) config.
func DefaultConfig() Config { return Config{} }

// LogToMetric is a StreamingProcessor that derives metrics from log lines.
type LogToMetric struct {
	cfg Config
	acc plugin.Accumulator
}

// New returns a new LogToMetric processor.
func New(cfg Config) *LogToMetric { return &LogToMetric{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (p *LogToMetric) Name() string { return "log_to_metric" }

// Start compiles patterns and stores the accumulator.
func (p *LogToMetric) Start(acc plugin.Accumulator) error {
	p.acc = acc
	for i := range p.cfg.Rules {
		re, err := regexp.Compile(p.cfg.Rules[i].Pattern)
		if err != nil {
			return err
		}
		p.cfg.Rules[i].compiled = re
	}
	return nil
}

// Add applies every rule to metric.Description; on match it emits a new metric.
// The input metric is forwarded unchanged (so the log keeps flowing downstream).
func (p *LogToMetric) Add(m plugin.Metric, _ plugin.Accumulator) error {
	// Forward the original log metric.
	if p.acc != nil {
		p.acc.Add(m)
	}

	// Apply each rule.
	for _, rule := range p.cfg.Rules {
		if rule.compiled == nil {
			continue
		}
		matches := rule.compiled.FindStringSubmatch(m.Description)
		if matches == nil {
			continue
		}
		out := plugin.Metric{
			Name:      rule.Name,
			Timestamp: time.Now(),
			Labels:    make(map[string]string),
		}
		// Copy original labels.
		for k, v := range m.Labels {
			out.Labels[k] = v
		}
		// Apply static tags.
		for k, v := range rule.Tags {
			out.Labels[k] = v
		}
		// Apply tag-from-group.
		for idx, tagName := range rule.TagFromGroup {
			if idx > 0 && idx < len(matches) {
				out.Labels[tagName] = matches[idx]
			}
		}
		// Determine value.
		switch rule.MetricType {
		case "gauge":
			out.Type = plugin.MetricTypeGauge
			if rule.ValueFromGroup > 0 && rule.ValueFromGroup < len(matches) {
				out.Value = parseFloat(matches[rule.ValueFromGroup])
			}
		default: // counter
			out.Type = plugin.MetricTypeCounter
			out.Value = 1
		}
		if p.acc != nil {
			p.acc.Add(out)
		}
	}
	return nil
}

// Stop is a no-op.
func (p *LogToMetric) Stop() error { return nil }

// parseFloat parses a float from s, returning 0 on parse failure.
func parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
