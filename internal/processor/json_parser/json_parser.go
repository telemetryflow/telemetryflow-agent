// Package json_parser implements a StreamingProcessor that parses the log
// line stored in metric.Description as a JSON object and promotes selected
// keys (or all top-level keys) to metric labels. Optionally overrides the
// metric Value from a numeric JSON field.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package json_parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("json_parser", func() plugin.StreamingProcessor { return New(DefaultConfig()) })
}

// Config controls the json_parser processor.
type Config struct {
	// TagKeys is a list of JSON keys to promote to labels. Dotted paths are
	// supported (e.g. "user.id" traverses nested objects). Empty = promote
	// all top-level keys as labels (stringified).
	TagKeys []string `yaml:"tag_keys" json:"tag_keys"`

	// ValueKey is an optional JSON key whose numeric value overrides
	// metric.Value. Dotted paths are supported.
	ValueKey string `yaml:"value_key,omitempty" json:"value_key,omitempty"`
}

// DefaultConfig returns an empty Config that promotes all top-level keys.
func DefaultConfig() Config { return Config{} }

// JSONParser is a StreamingProcessor.
type JSONParser struct {
	cfg Config
	acc plugin.Accumulator
}

// New returns the processor.
func New(cfg Config) *JSONParser { return &JSONParser{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (p *JSONParser) Name() string { return "json_parser" }

// Start stores the downstream accumulator.
func (p *JSONParser) Start(acc plugin.Accumulator) error { p.acc = acc; return nil }

// Add parses m.Description as JSON and forwards. Non-JSON input is forwarded
// unchanged (the processor never drops on parse error).
func (p *JSONParser) Add(m plugin.Metric, _ plugin.Accumulator) error {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(m.Description), &raw); err != nil {
		if p.acc != nil {
			p.acc.Add(m)
		}
		return nil
	}

	if len(p.cfg.TagKeys) > 0 {
		for _, key := range p.cfg.TagKeys {
			val, ok := lookupPath(raw, key)
			if !ok {
				continue
			}
			m.AddLabel(key, stringify(val))
		}
	} else {
		for k, v := range raw {
			m.AddLabel(k, stringify(v))
		}
	}

	if p.cfg.ValueKey != "" {
		if val, ok := lookupPath(raw, p.cfg.ValueKey); ok {
			if f, ok := toFloat(val); ok {
				m.Value = f
			}
		}
	}

	if p.acc != nil {
		p.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (p *JSONParser) Stop() error { return nil }

// lookupPath traverses a decoded JSON object following dotted-path segments.
// Returns the value and true on success.
func lookupPath(root map[string]interface{}, path string) (interface{}, bool) {
	if path == "" {
		return nil, false
	}
	var cur interface{} = root
	for _, part := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			cur = val
		default:
			return nil, false
		}
	}
	return cur, true
}

// stringify renders a decoded JSON scalar/array/object as a label string.
func stringify(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprintf("%v", x)
		}
		return string(b)
	}
}

// toFloat coerces a decoded JSON value to float64 (the metric.Value type).
func toFloat(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}
