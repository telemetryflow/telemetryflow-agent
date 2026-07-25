// Package starlark implements a StreamingProcessor that runs an embedded
// Starlark script for every metric. Equivalent to Telegraf's starlark
// processor — a Turing-complete escape hatch so users can implement custom
// logic without a Go release cycle.
//
// The script must define an `apply(metric)` function. The function receives
// a dict-shaped view of the metric and must return one of:
//   - The (modified) metric dict to forward downstream.
//   - None to drop the metric.
//   - A list of metric dicts to fan out into multiple metrics.
//
// Available metric dict keys: name, description, type, value, timestamp
// (unix nanos int), unit, labels (dict[str, str]).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
package starlark

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.starlark.net/starlark"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func init() {
	plugin.MustAddProcessor("starlark", func() plugin.StreamingProcessor { return New(DefaultConfig()) })
}

// Config controls the starlark processor.
type Config struct {
	// Script is the Starlark source code. Must define `apply(metric)`.
	Script string `yaml:"script" json:"script"`

	// Source is an alternative path to load the script from disk. Mutually
	// exclusive with Script. (Wired in a future iteration.)
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
}

// DefaultConfig has an empty script (forwards metrics unchanged).
func DefaultConfig() Config { return Config{} }

// Starlark is a StreamingProcessor.
type Starlark struct {
	cfg         Config
	acc         plugin.Accumulator
	thread      *starlark.Thread
	predeclared starlark.StringDict
	applyFn     *starlark.Function
	mu          sync.Mutex
	compiled    bool
}

// New returns the processor. The script is compiled lazily on Start so that
// constructor failures don't crash the registry.
func New(cfg Config) *Starlark { return &Starlark{cfg: cfg} }

// Name implements plugin.StreamingProcessor.
func (s *Starlark) Name() string { return "starlark" }

// Start compiles the script (if any) and resolves the `apply` function.
func (s *Starlark) Start(acc plugin.Accumulator) error {
	s.acc = acc
	if s.cfg.Script == "" {
		// No-op passthrough when no script configured.
		return nil
	}
	s.thread = &starlark.Thread{Name: "tfo-starlark"}
	globals, err := starlark.ExecFile(s.thread, "tfo_starlark.py", s.cfg.Script, predeclared())
	if err != nil {
		return fmt.Errorf("starlark compile: %w", err)
	}
	fn, ok := globals["apply"]
	if !ok {
		return errors.New("starlark script must define `apply(metric)`")
	}
	applyFn, ok := fn.(*starlark.Function)
	if !ok {
		return errors.New("`apply` must be a function")
	}
	s.applyFn = applyFn
	s.compiled = true
	return nil
}

// Add runs the script's apply function for every metric.
func (s *Starlark) Stop() error { return nil }

// Add invokes the apply function and forwards the result.
func (s *Starlark) Add(m plugin.Metric, _ plugin.Accumulator) error {
	// Fast path: no script → passthrough.
	if !s.compiled {
		if s.acc != nil {
			s.acc.Add(m)
		}
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	arg := metricToStarlark(m)
	v, err := starlark.Call(s.thread, s.applyFn, starlark.Tuple{arg}, nil)
	if err != nil {
		// Don't drop the metric on script error — forward unchanged and
		// surface the error via the accumulator.
		if s.acc != nil {
			s.acc.AddError(fmt.Errorf("starlark apply: %w", err))
			s.acc.Add(m)
		}
		return nil
	}

	switch rv := v.(type) {
	case *starlark.Dict:
		out, err := starlarkToMetric(rv)
		if err != nil {
			s.acc.AddError(err)
			return nil
		}
		if s.acc != nil {
			s.acc.Add(out)
		}
	case starlark.NoneType:
		// Drop the metric.
	case *starlark.List:
		for i := 0; i < rv.Len(); i++ {
			item, ok := rv.Index(i).(*starlark.Dict)
			if !ok {
				s.acc.AddError(fmt.Errorf("starlark list must contain dicts, got %T", rv.Index(i)))
				continue
			}
			out, err := starlarkToMetric(item)
			if err != nil {
				s.acc.AddError(err)
				continue
			}
			if s.acc != nil {
				s.acc.Add(out)
			}
		}
	default:
		s.acc.AddError(fmt.Errorf("starlark apply must return dict, None, or list; got %T", v))
	}
	return nil
}

// predeclared returns the symbols available to every script (besides the
// Starlark builtins). Currently empty — extend with helper modules
// (time, regex, json) in future iterations.
func predeclared() starlark.StringDict { return starlark.StringDict{} }

// metricToStarlark converts a plugin.Metric into a *starlark.Dict.
func metricToStarlark(m plugin.Metric) *starlark.Dict {
	d := starlark.NewDict(6)
	_ = d.SetKey(starlark.String("name"), starlark.String(m.Name))
	_ = d.SetKey(starlark.String("description"), starlark.String(m.Description))
	_ = d.SetKey(starlark.String("type"), starlark.String(string(m.Type)))
	_ = d.SetKey(starlark.String("value"), starlark.Float(m.Value))
	_ = d.SetKey(starlark.String("timestamp"), starlark.MakeInt64(m.Timestamp.UnixNano()))
	_ = d.SetKey(starlark.String("unit"), starlark.String(m.Unit))

	labels := starlark.NewDict(len(m.Labels))
	for k, v := range m.Labels {
		_ = labels.SetKey(starlark.String(k), starlark.String(v))
	}
	_ = d.SetKey(starlark.String("labels"), labels)
	return d
}

// starlarkToMetric converts a *starlark.Dict back into a plugin.Metric.
func starlarkToMetric(d *starlark.Dict) (plugin.Metric, error) {
	var m plugin.Metric
	for _, item := range d.Items() {
		k, v := item[0], item[1]
		key, _ := starlark.AsString(k.(starlark.String))
		switch string(key) {
		case "name":
			s, _ := starlark.AsString(v)
			m.Name = string(s)
		case "description":
			s, _ := starlark.AsString(v)
			m.Description = string(s)
		case "type":
			s, _ := starlark.AsString(v)
			m.Type = plugin.MetricType(string(s))
		case "value":
			if f, ok := v.(starlark.Float); ok {
				m.Value = float64(f)
			} else if iv, ok := v.(starlark.Int); ok {
				n, _ := iv.Int64()
				m.Value = float64(n)
			}
		case "timestamp":
			if iv, ok := v.(starlark.Int); ok {
				ns, _ := iv.Int64()
				m.Timestamp = time.Unix(0, ns)
			}
		case "unit":
			s, _ := starlark.AsString(v)
			m.Unit = string(s)
		case "labels":
			if ld, ok := v.(*starlark.Dict); ok {
				m.Labels = make(map[string]string, ld.Len())
				for _, item := range ld.Items() {
					kk, _ := starlark.AsString(item[0].(starlark.String))
					vv, _ := starlark.AsString(item[1].(starlark.String))
					m.Labels[string(kk)] = string(vv)
				}
			}
		}
	}
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	return m, nil
}
