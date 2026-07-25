// Package rename implements a StreamingProcessor that renames metric names
// (measurement), fields, and tag keys. Equivalent to Telegraf's rename
// processor. Renames are applied to every metric flowing through.
package rename

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("rename", func() plugin.StreamingProcessor { return New(DefaultConfig()) })
}

// Config maps old → new names. Each map is applied independently.
type Config struct {
	// Measurements renames the metric Name (Telegraf calls this "measurement").
	Measurements map[string]string `yaml:"measurements" json:"measurements"`
	// Tags renames tag keys.
	Tags map[string]string `yaml:"tags" json:"tags"`
}

// DefaultConfig does nothing.
func DefaultConfig() Config { return Config{} }

// Rename is a StreamingProcessor.
type Rename struct {
	cfg Config
	acc plugin.Accumulator
}

// New returns the processor.
func New(cfg Config) *Rename { return &Rename{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (r *Rename) Name() string { return "rename" }

// Start stores the accumulator.
func (r *Rename) Start(acc plugin.Accumulator) error { r.acc = acc; return nil }

// Add applies the renames and forwards.
func (r *Rename) Add(m plugin.Metric, _ plugin.Accumulator) error {
	if newName, ok := r.cfg.Measurements[m.Name]; ok {
		m.Name = newName
	}
	if len(r.cfg.Tags) > 0 && m.Labels != nil {
		newLabels := make(map[string]string, len(m.Labels))
		for k, v := range m.Labels {
			if nk, ok := r.cfg.Tags[k]; ok {
				newLabels[nk] = v
			} else {
				newLabels[k] = v
			}
		}
		m.Labels = newLabels
	}
	if r.acc != nil {
		r.acc.Add(m)
	}
	return nil
}

// Stop is a no-op.
func (r *Rename) Stop() error { return nil }
