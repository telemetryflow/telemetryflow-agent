// Package enum implements a StreamingProcessor that maps label values via
// configurable enumeration tables. Equivalent to Telegraf's enum processor.
//
// Example use case: convert numeric state codes to human-readable strings,
// e.g. {"0": "stopped", "1": "running"}.
package enum

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("enum", func() plugin.StreamingProcessor { return New(DefaultConfig()) })
}

// Mapping defines a single value-translation table scoped to one label key.
type Mapping struct {
	// Tag is the label key whose values should be mapped.
	Tag string `yaml:"tag" json:"tag"`

	// Values maps the original value → replacement value.
	Values map[string]string `yaml:"values" json:"values"`

	// Default is applied when the value is not in Values. Empty = leave
	// unchanged.
	Default string `yaml:"default,omitempty" json:"default,omitempty"`
}

// Config groups one or more mappings.
type Config struct {
	Mappings []Mapping `yaml:"mappings" json:"mappings"`
}

// DefaultConfig applies no mappings.
func DefaultConfig() Config { return Config{} }

// Enum is a StreamingProcessor.
type Enum struct {
	cfg Config
	acc plugin.Accumulator
}

// New returns the processor.
func New(cfg Config) *Enum { return &Enum{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (e *Enum) Name() string { return "enum" }

// Start stores the accumulator.
func (e *Enum) Start(acc plugin.Accumulator) error { e.acc = acc; return nil }

// Add applies every mapping whose tag key exists on the metric.
func (e *Enum) Add(m plugin.Metric, _ plugin.Accumulator) error {
	if len(e.cfg.Mappings) == 0 || m.Labels == nil {
		if e.acc != nil {
			e.acc.Add(m)
		}
		return nil
	}
	for _, mp := range e.cfg.Mappings {
		cur, ok := m.Labels[mp.Tag]
		if !ok {
			continue
		}
		if newVal, ok := mp.Values[cur]; ok {
			m.Labels[mp.Tag] = newVal
			continue
		}
		if mp.Default != "" {
			m.Labels[mp.Tag] = mp.Default
		}
	}
	if e.acc != nil {
		e.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (e *Enum) Stop() error { return nil }
