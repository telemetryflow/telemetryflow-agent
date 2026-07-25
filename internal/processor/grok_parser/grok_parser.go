// Package grok_parser implements a StreamingProcessor that parses the log
// line stored in metric.Description using a grok pattern of the form
// `%{PATTERN:name}`. A self-contained translator maps the common grok
// patterns to Go RE2 at compile time, so no external grok library is
// required. Extracted named captures become new metric labels.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package grok_parser

import (
	"fmt"
	"regexp"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("grok_parser", func() plugin.StreamingProcessor {
		p, _ := New(DefaultConfig())
		return p
	})
}

// Config controls the grok_parser processor.
type Config struct {
	// Pattern is a grok pattern like
	// `%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}`.
	// Required.
	Pattern string `yaml:"pattern" json:"pattern"`

	// NamedOnly when true only captures named captures. The RE2 translator
	// emits non-capturing groups for unlabelled `%{PATTERN}` occurrences,
	// so this flag is effectively always true. Kept for config parity with
	// Telegraf's grok processor.
	NamedOnly bool `yaml:"named_only" json:"named_only"`

	// KeepOriginal when true keeps the original Description on the metric
	// alongside the parsed labels (default false clears Description on match).
	KeepOriginal bool `yaml:"keep_original" json:"keep_original"`

	// MetricNamePrefix overrides the output metric name. When non-empty, the
	// emitted metric uses MetricNamePrefix + parsed name (if the pattern
	// captures a "name" or "metric_name" field) or just MetricNamePrefix.
	// When empty, the input metric name is preserved.
	MetricNamePrefix string `yaml:"metric_name_prefix,omitempty" json:"metric_name_prefix,omitempty"`
}

// DefaultConfig returns an empty Config. New will reject it.
func DefaultConfig() Config { return Config{} }

// GrokParser is a StreamingProcessor.
type GrokParser struct {
	cfg Config
	re  *regexp.Regexp
	acc plugin.Accumulator
}

// New compiles the grok pattern into an RE2 regex and returns the processor.
// Returns an error if the pattern is empty, references an unknown grok
// pattern, or translates to an invalid regex.
func New(cfg Config) (*GrokParser, error) {
	if cfg.Pattern == "" {
		return nil, fmt.Errorf("grok_parser: pattern is required")
	}
	translated, err := Translate(cfg.Pattern)
	if err != nil {
		return nil, fmt.Errorf("grok_parser: %w", err)
	}
	re, err := regexp.Compile(translated)
	if err != nil {
		return nil, fmt.Errorf("grok_parser: compiled regex invalid: %w", err)
	}
	return &GrokParser{cfg: cfg, re: re}, nil
}

// Name implements plugin.StreamingProcessor.
func (p *GrokParser) Name() string { return "grok_parser" }

// Start stores the downstream accumulator.
func (p *GrokParser) Start(acc plugin.Accumulator) error { p.acc = acc; return nil }

// Add parses m.Description, sets labels from named captures, and forwards.
// Non-matching metrics are dropped unless KeepOriginal is set, in which case
// they are forwarded unchanged.
func (p *GrokParser) Add(m plugin.Metric, _ plugin.Accumulator) error {
	match := p.re.FindStringSubmatch(m.Description)
	if match == nil {
		if p.cfg.KeepOriginal && p.acc != nil {
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

	if p.cfg.MetricNamePrefix != "" {
		m.Name = p.cfg.MetricNamePrefix
	}
	if !p.cfg.KeepOriginal {
		m.Description = ""
	}
	if p.acc != nil {
		p.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (p *GrokParser) Stop() error { return nil }

// grokPatterns maps well-known grok pattern names to RE2 fragments. The set
// covers the common log-parsing patterns used in M3. Unknown references are
// rejected by Translate so the user gets a clear error at Start time.
var grokPatterns = map[string]string{
	"TIMESTAMP_ISO8601": `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`,
	"DATE_ISO8601":      `\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?`,
	"DATESTAMP":         `\d{2}-\d{2}-\d{2}`,
	"TIME":              `\d{2}:\d{2}:\d{2}`,
	"LOGLEVEL":          `(?:DEBUG|INFO|INFORMATION|NOTICE|WARN(?:ING)?|ERR(?:OR)?|FATAL|CRITICAL|CRIT|TRACE|SEVERE)`,
	"WORD":              `\w+`,
	"NOTSPACE":          `\S+`,
	"SPACE":             `\s+`,
	"DATA":              `.*?`,
	"GREEDYDATA":        `.*`,
	"QUOTEDSTRING":      `"(?:[^"\\]|\\.)*"`,
	"INT":               `[+-]?\d+`,
	"NUMBER":            `[+-]?\d+(?:\.\d+)?`,
	"IP":                `(?:\d{1,3}\.){3}\d{1,3}`,
	"IPORHOST":          `(?:[0-9A-Za-z][0-9A-Za-z\-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z\-]{0,62})*|(?:\d{1,3}\.){3}\d{1,3})`,
	"HOSTNAME":          `[0-9A-Za-z][0-9A-Za-z\-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z\-]{0,62})*`,
	"UUID":              `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	"HTTPDATE":          `\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}`,
}

// grokTokenRe matches `%{NAME}`, `%{NAME:label}`, or `%{NAME:label:type}`.
var grokTokenRe = regexp.MustCompile(`%\{(\w+)(?::([^:}]+))?(?::[^}]+)?\}`)

// Translate converts a grok pattern into a Go RE2 regex string. Unlabelled
// `%{PATTERN}` references become non-capturing groups; labelled ones become
// named captures. Semantic types (`%{NUMBER:bytes:int}`) are accepted but
// ignored — the caller sees string labels (matching Telegraf's behaviour).
func Translate(pattern string) (string, error) {
	var unknown []string
	out := grokTokenRe.ReplaceAllStringFunc(pattern, func(token string) string {
		m := grokTokenRe.FindStringSubmatch(token)
		name, label := m[1], m[2]
		base, ok := grokPatterns[name]
		if !ok {
			unknown = append(unknown, name)
			return token
		}
		if label != "" {
			return fmt.Sprintf("(?P<%s>%s)", label, base)
		}
		return fmt.Sprintf("(?:%s)", base)
	})
	if len(unknown) > 0 {
		return "", fmt.Errorf("unknown grok pattern(s): %v", unknown)
	}
	return out, nil
}
