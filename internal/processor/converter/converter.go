// Package converter implements a StreamingProcessor that rounds float values
// for selected metrics. Equivalent to a subset of Telegraf's converter
// processor (tfo-agent Metric values are float64-only at present, so type
// conversion reduces to rounding + scale).
package converter

import (
	"math"
	"regexp"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("converter", func() plugin.StreamingProcessor {
		c, _ := New(DefaultConfig())
		return c
	})
}

// RoundingSpec rounds values for metrics whose Name matches the regex.
type RoundingSpec struct {
	// NameRegex selects which metrics to round. Empty = apply to all.
	NameRegex string `yaml:"name_regex,omitempty" json:"name_regex,omitempty"`

	// Decimals is the number of decimal places to round to.
	Decimals int `yaml:"decimals" json:"decimals"`

	// compiled is set by New for fast matching.
	compiled *regexp.Regexp `yaml:"-" json:"-"`
}

// Config controls the converter processor.
type Config struct {
	Round []RoundingSpec `yaml:"round" json:"round"`
}

// DefaultConfig does no conversion.
func DefaultConfig() Config { return Config{} }

// New compiles regex patterns and returns the processor.
func New(cfg Config) (*Converter, error) {
	for i := range cfg.Round {
		if cfg.Round[i].NameRegex == "" {
			continue
		}
		re, err := regexp.Compile(cfg.Round[i].NameRegex)
		if err != nil {
			return nil, err
		}
		cfg.Round[i].compiled = re
	}
	return &Converter{cfg: cfg}, nil
}

// Converter is a StreamingProcessor.
type Converter struct {
	cfg Config
	acc plugin.Accumulator
}

// Name implements plugin.StreamingProcessor.
func (c *Converter) Name() string { return "converter" }

// Start stores the accumulator.
func (c *Converter) Start(acc plugin.Accumulator) error { c.acc = acc; return nil }

// Add applies rounding to the metric value and forwards.
func (c *Converter) Add(m plugin.Metric, _ plugin.Accumulator) error {
	for _, spec := range c.cfg.Round {
		if spec.compiled != nil && !spec.compiled.MatchString(m.Name) {
			continue
		}
		m.Value = roundFloat(m.Value, spec.Decimals)
	}
	if c.acc != nil {
		c.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (c *Converter) Stop() error { return nil }

// roundFloat rounds to N decimals. Decimals < 0 = round to integer.
func roundFloat(v float64, decimals int) float64 {
	if decimals < 0 {
		decimals = 0
	}
	mul := math.Pow(10, float64(decimals))
	return math.Round(v*mul) / mul
}
