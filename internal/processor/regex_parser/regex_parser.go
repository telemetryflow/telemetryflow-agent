// Package regex_parser implements a StreamingProcessor that parses the log
// line stored in metric.Description using a Go RE2 regex with named captures.
// Each named capture becomes a new metric label.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package regex_parser

import (
	"fmt"
	"regexp"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("regex_parser", func() plugin.StreamingProcessor {
		p, _ := New(DefaultConfig())
		return p
	})
}

// Config controls the regex_parser processor.
type Config struct {
	// Pattern is a Go RE2 regex with named captures, e.g.
	// `^(?P<timestamp>\S+) (?P<level>\w+) (?P<message>.*)$`. Required.
	Pattern string `yaml:"pattern" json:"pattern"`

	// DropWhenNoMatch drops metrics whose Description does not match. Default
	// false: non-matching metrics are forwarded unchanged.
	DropWhenNoMatch bool `yaml:"drop_when_no_match" json:"drop_when_no_match"`
}

// DefaultConfig returns an empty Config. New will reject it via Init/Start.
func DefaultConfig() Config { return Config{} }

// RegexParser is a StreamingProcessor.
type RegexParser struct {
	cfg Config
	re  *regexp.Regexp
	acc plugin.Accumulator
}

// New compiles the regex and returns the processor. Returns an error if the
// pattern is empty or invalid.
func New(cfg Config) (*RegexParser, error) {
	if cfg.Pattern == "" {
		return nil, fmt.Errorf("regex_parser: pattern is required")
	}
	re, err := regexp.Compile(cfg.Pattern)
	if err != nil {
		return nil, fmt.Errorf("regex_parser: invalid pattern %q: %w", cfg.Pattern, err)
	}
	return &RegexParser{cfg: cfg, re: re}, nil
}

// Name implements plugin.StreamingProcessor.
func (p *RegexParser) Name() string { return "regex_parser" }

// Start stores the downstream accumulator.
func (p *RegexParser) Start(acc plugin.Accumulator) error { p.acc = acc; return nil }

// Add parses m.Description, sets labels from named captures, and forwards.
func (p *RegexParser) Add(m plugin.Metric, _ plugin.Accumulator) error {
	match := p.re.FindStringSubmatch(m.Description)
	if match == nil {
		if p.cfg.DropWhenNoMatch {
			return nil
		}
		if p.acc != nil {
			p.acc.Add(m)
		}
		return nil
	}
	names := p.re.SubexpNames()
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		m.AddLabel(name, match[i])
	}
	if p.acc != nil {
		p.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (p *RegexParser) Stop() error { return nil }
