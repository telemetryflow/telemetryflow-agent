// Package keep implements a StreamingProcessor that forwards only metrics
// whose name matches at least one of the configured regex patterns. The
// inverse of the drop processor.
package keep

import (
	"regexp"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("keep", func() plugin.StreamingProcessor {
		k, _ := New(DefaultConfig())
		return k
	})
}

// Config lists the regex patterns; a metric is forwarded if any matches.
// Empty Patterns = keep nothing (use the opposite: drop processor instead).
type Config struct {
	Patterns []string `yaml:"patterns" json:"patterns"`
}

// DefaultConfig keeps nothing.
func DefaultConfig() Config { return Config{} }

// Keep is a StreamingProcessor.
type Keep struct {
	cfg Config
	res []*regexp.Regexp
	acc plugin.Accumulator
}

// New compiles patterns.
func New(cfg Config) (*Keep, error) {
	k := &Keep{cfg: cfg}
	for _, p := range cfg.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		k.res = append(k.res, re)
	}
	return k, nil
}

// Name implements plugin.StreamingProcessor.
func (k *Keep) Name() string { return "keep" }

// Start stores the accumulator.
func (k *Keep) Start(acc plugin.Accumulator) error { k.acc = acc; return nil }

// Add forwards only when a pattern matches.
func (k *Keep) Add(m plugin.Metric, _ plugin.Accumulator) error {
	for _, re := range k.res {
		if re.MatchString(m.Name) {
			if k.acc != nil {
				k.acc.Add(m)
			}
			return nil
		}
	}
	return nil
}

// Stop is a no-op.
func (k *Keep) Stop() error { return nil }
