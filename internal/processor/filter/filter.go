// Package filter implements a StreamingProcessor that keeps or drops metrics
// based on name regex, tag presence/values, and field values.
package filter

import (
	"regexp"
	"strings"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("filter", func() plugin.StreamingProcessor { return New(DefaultConfig()) })
}

// Action is the outcome when a rule matches.
type Action string

const (
	ActionDrop Action = "drop"
	ActionKeep Action = "keep"
)

// Rule defines a single filter predicate. All non-zero fields in a rule must
// match (AND within a rule). Across rules, semantics are OR (any match fires
// the action).
type Rule struct {
	Action     Action    `yaml:"action" json:"action"`
	MetricName string    `yaml:"metric_name,omitempty" json:"metric_name,omitempty"` // regex; empty = any
	Tag        *TagMatch `yaml:"tag,omitempty" json:"tag,omitempty"`                 // tag key+value regex
}

// TagMatch matches a tag key with a value regex. ValueMatch empty = presence.
type TagMatch struct {
	Key        string `yaml:"key" json:"key"`
	ValueMatch string `yaml:"value,omitempty" json:"value,omitempty"` // regex; empty = presence
}

// Config controls the filter processor.
type Config struct {
	// Rules are evaluated in order; the first match wins. If no rule matches,
	// the metric is kept by default. Set DefaultAction=Drop to invert.
	Rules []Rule `yaml:"rules" json:"rules"`

	// DefaultAction is taken when no rule matches. Default: keep.
	DefaultAction Action `yaml:"default_action" json:"default_action"`
}

// DefaultConfig returns a Config that keeps every metric.
func DefaultConfig() Config { return Config{DefaultAction: ActionKeep} }

// compiledRule is a Rule with its regexes pre-compiled.
type compiledRule struct {
	action     Action
	nameRe     *regexp.Regexp
	tagKey     string
	tagValueRe *regexp.Regexp
}

// Filter is a StreamingProcessor.
type Filter struct {
	cfg   Config
	rules []compiledRule
	acc   plugin.Accumulator
}

// New compiles the config and returns the processor.
func New(cfg Config) *Filter {
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = ActionKeep
	}
	f := &Filter{cfg: cfg}
	for _, r := range cfg.Rules {
		cr := compiledRule{action: r.Action}
		if r.MetricName != "" {
			cr.nameRe = regexp.MustCompile(r.MetricName)
		}
		if r.Tag != nil {
			cr.tagKey = r.Tag.Key
			if r.Tag.ValueMatch != "" {
				cr.tagValueRe = regexp.MustCompile(r.Tag.ValueMatch)
			}
		}
		f.rules = append(f.rules, cr)
	}
	return f
}

// Name implements plugin.StreamingProcessor.
func (f *Filter) Name() string { return "filter" }

// Start stores the downstream accumulator.
func (f *Filter) Start(acc plugin.Accumulator) error { f.acc = acc; return nil }

// Add evaluates rules and forwards/keeps/drops accordingly.
func (f *Filter) Add(m plugin.Metric, _ plugin.Accumulator) error {
	if f.matchesKeep(m) {
		if f.acc != nil {
			f.acc.Add(m)
		}
	}
	return nil
}

// Stop is a no-op.
func (f *Filter) Stop() error { return nil }

// matchesKeep returns true if the metric should be forwarded downstream.
func (f *Filter) matchesKeep(m plugin.Metric) bool {
	for _, r := range f.rules {
		if !r.matchMetric(m) {
			continue
		}
		// First matching rule wins.
		return r.action == ActionKeep
	}
	return f.cfg.DefaultAction == ActionKeep
}

func (r compiledRule) matchMetric(m plugin.Metric) bool {
	if r.nameRe != nil && !r.nameRe.MatchString(m.Name) {
		return false
	}
	if r.tagKey != "" {
		v, ok := m.Labels[r.tagKey]
		if !ok {
			return false
		}
		if r.tagValueRe != nil && !r.tagValueRe.MatchString(v) {
			return false
		}
	}
	return true
}

// String returns a debug representation.
func (f *Filter) String() string {
	var b strings.Builder
	b.WriteString("filter{rules=[")
	for i, r := range f.cfg.Rules {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(string(r.Action))
		if r.MetricName != "" {
			b.WriteString("(name=")
			b.WriteString(r.MetricName)
			b.WriteString(")")
		}
		if r.Tag != nil {
			b.WriteString("(tag=")
			b.WriteString(r.Tag.Key)
			b.WriteString(")")
		}
	}
	b.WriteString("]}")
	return b.String()
}
