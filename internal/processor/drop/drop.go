// Package drop implements a StreamingProcessor that drops metrics whose name
// matches any of the configured regex patterns. Equivalent to Telegraf's
// `processor + filter` shorthand for the common case of "drop noisy metrics".
package drop

import (
	"regexp"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("drop", func() plugin.StreamingProcessor {
		d, _ := New(DefaultConfig())
		return d
	})
}

// Config lists the regex patterns; a metric is dropped if any matches.
type Config struct {
	Patterns []string `yaml:"patterns" json:"patterns"`
}

// DefaultConfig drops nothing.
func DefaultConfig() Config { return Config{} }

// Drop is a StreamingProcessor.
type Drop struct {
	cfg Config
	res []*regexp.Regexp
	acc plugin.Accumulator
}

// New compiles patterns and returns the processor.
func New(cfg Config) (*Drop, error) {
	d := &Drop{cfg: cfg}
	for _, p := range cfg.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		d.res = append(d.res, re)
	}
	return d, nil
}

// Name implements plugin.StreamingProcessor.
func (d *Drop) Name() string { return "drop" }

// Start stores the accumulator.
func (d *Drop) Start(acc plugin.Accumulator) error { d.acc = acc; return nil }

// Add drops on match, forwards otherwise.
func (d *Drop) Add(m plugin.Metric, _ plugin.Accumulator) error {
	for _, re := range d.res {
		if re.MatchString(m.Name) {
			return nil // dropped
		}
	}
	if d.acc != nil {
		d.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (d *Drop) Stop() error { return nil }
