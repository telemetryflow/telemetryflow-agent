// Package defaults implements a StreamingProcessor that fills in missing
// tags on every metric. Useful for stamping a fixed region/environment tag
// onto every metric from a collector that does not set it.
package defaults

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("defaults", func() plugin.StreamingProcessor { return New(DefaultConfig()) })
}

// Config maps tag keys to their default values. A default is only applied
// when the key is absent (or empty) on the incoming metric.
type Config struct {
	Tags map[string]string `yaml:"tags" json:"tags"`
}

// DefaultConfig applies no defaults.
func DefaultConfig() Config { return Config{} }

// Defaults is a StreamingProcessor.
type Defaults struct {
	cfg Config
	acc plugin.Accumulator
}

// New returns the processor.
func New(cfg Config) *Defaults { return &Defaults{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (d *Defaults) Name() string { return "defaults" }

// Start stores the accumulator.
func (d *Defaults) Start(acc plugin.Accumulator) error { d.acc = acc; return nil }

// Add applies default tags and forwards.
func (d *Defaults) Add(m plugin.Metric, _ plugin.Accumulator) error {
	if len(d.cfg.Tags) > 0 {
		if m.Labels == nil {
			m.Labels = make(map[string]string, len(d.cfg.Tags))
		}
		for k, v := range d.cfg.Tags {
			if cur, ok := m.Labels[k]; !ok || cur == "" {
				m.Labels[k] = v
			}
		}
	}
	if d.acc != nil {
		d.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (d *Defaults) Stop() error { return nil }
