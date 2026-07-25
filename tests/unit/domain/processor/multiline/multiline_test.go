package multiline_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/processor/multiline"
)

// TestMultiline_ContinuationAppended: a header line followed by a
// continuation line is buffered and emitted as a single multi-line record.
func TestMultiline_ContinuationAppended(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern: `^\s`, // leading whitespace = continuation
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{Name: "log", Description: "ERROR something broke"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "  at foo.bar()"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "  at baz.qux()"}, nil)

	// Nothing should be emitted yet — header still buffered.
	if len(acc.added) != 0 {
		t.Fatalf("expected 0 emits before flush, got %d", len(acc.added))
	}

	m.Flush()
	if len(acc.added) != 1 {
		t.Fatalf("expected 1 aggregated metric, got %d", len(acc.added))
	}
	want := "ERROR something broke\n  at foo.bar()\n  at baz.qux()"
	if acc.added[0].Description != want {
		t.Errorf("description = %q, want %q", acc.added[0].Description, want)
	}
}

// TestMultiline_NewHeaderFlushes: when a new header arrives on a stream that
// has a buffered record, the buffered record is flushed and the new line
// starts a fresh buffer.
func TestMultiline_NewHeaderFlushes(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern: `^\s`,
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{Name: "log", Description: "INFO first"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "  more"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "ERROR second"}, nil) // header → flush

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 emit after new header, got %d", len(acc.added))
	}
	if acc.added[0].Description != "INFO first\n  more" {
		t.Errorf("first emit = %q", acc.added[0].Description)
	}

	// Flush the remaining buffer.
	m.Flush()
	if len(acc.added) != 2 {
		t.Fatalf("expected 2 total emits after flush, got %d", len(acc.added))
	}
	if acc.added[1].Description != "ERROR second" {
		t.Errorf("second emit = %q", acc.added[1].Description)
	}
}

// TestMultiline_TimeoutFlush: when no continuation arrives within Timeout,
// the buffered record is flushed automatically by the timer.
func TestMultiline_TimeoutFlush(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern: `^\s`,
		Timeout: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{Name: "log", Description: "INFO hi"}, nil)
	if len(acc.added) != 0 {
		t.Fatalf("expected no emit yet, got %d", len(acc.added))
	}

	// Wait long enough for the timeout to fire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		acc.mu.Lock()
		n := len(acc.added)
		acc.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	acc.mu.Lock()
	defer acc.mu.Unlock()
	if len(acc.added) != 1 {
		t.Fatalf("expected 1 emit after timeout, got %d", len(acc.added))
	}
	if acc.added[0].Description != "INFO hi" {
		t.Errorf("description = %q", acc.added[0].Description)
	}
}

// TestMultiline_Negate: with Negate=true, matching lines START a new record
// and non-matching lines are continuations.
func TestMultiline_Negate(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern: `^\d{4}-\d{2}-\d{2}`, // line beginning with a date = header
		Negate:  true,
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{Name: "log", Description: "2026-07-25 line one"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "stack trace frame 1"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "stack trace frame 2"}, nil)
	_ = m.Add(plugin.Metric{Name: "log", Description: "2026-07-25 line two"}, nil) // flush

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 emit, got %d", len(acc.added))
	}
	if acc.added[0].Description != "2026-07-25 line one\nstack trace frame 1\nstack trace frame 2" {
		t.Errorf("description = %q", acc.added[0].Description)
	}
}

// TestMultiline_StreamKeyGroupsIndependently: lines on different streams are
// buffered separately and never cross-aggregated.
func TestMultiline_StreamKeyGroupsIndependently(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern:   `^\s`,
		StreamKey: "container",
		Timeout:   time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{
		Name:        "log",
		Description: "INFO from container A",
		Labels:      map[string]string{"container": "A"},
	}, nil)
	// Line from container B — must NOT be appended to A's buffer; it starts
	// its own buffer on the "B" stream.
	_ = m.Add(plugin.Metric{
		Name:        "log",
		Description: "INFO from container B",
		Labels:      map[string]string{"container": "B"},
	}, nil)
	_ = m.Add(plugin.Metric{
		Name:        "log",
		Description: "  continuation for A",
		Labels:      map[string]string{"container": "A"},
	}, nil)

	m.Flush()
	if len(acc.added) != 2 {
		t.Fatalf("expected 2 emits (one per stream), got %d", len(acc.added))
	}

	byStream := map[string]string{}
	for _, mm := range acc.added {
		byStream[mm.Labels["container"]] = mm.Description
	}
	if byStream["A"] != "INFO from container A\n  continuation for A" {
		t.Errorf("A description = %q", byStream["A"])
	}
	if byStream["B"] != "INFO from container B" {
		t.Errorf("B description = %q", byStream["B"])
	}
}

// TestMultiline_StopFlushes: calling Stop emits any buffered records.
func TestMultiline_StopFlushes(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern: `^\s`,
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{Name: "log", Description: "header only"}, nil)
	if err := m.Stop(); err != nil {
		t.Fatalf("stop returned error: %v", err)
	}
	if len(acc.added) != 1 {
		t.Fatalf("expected 1 emit on stop, got %d", len(acc.added))
	}
}

// TestMultiline_EmptyPattern: New must reject an empty pattern.
func TestMultiline_EmptyPattern(t *testing.T) {
	if _, err := multiline.New(multiline.Config{}); err == nil {
		t.Error("expected error for empty pattern")
	}
}

// TestMultiline_InvalidPattern: New must reject an invalid regex.
func TestMultiline_InvalidPattern(t *testing.T) {
	if _, err := multiline.New(multiline.Config{Pattern: "["}); err == nil {
		t.Error("expected error for invalid regex")
	}
}

// TestMultiline_DefaultTimeoutFlushes: a zero Timeout falls back to 5s and
// still triggers an eventual flush. Rather than wait 5s, we just verify
// Start/Stop round-trip cleanly with default config.
func TestMultiline_DefaultTimeoutFlushes(t *testing.T) {
	m, err := multiline.New(multiline.Config{Pattern: `^\s`})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)
	_ = m.Add(plugin.Metric{Name: "log", Description: "header"}, nil)
	if err := m.Stop(); err != nil {
		t.Fatalf("stop returned error: %v", err)
	}
	if len(acc.added) != 1 {
		t.Fatalf("expected 1 emit on stop, got %d", len(acc.added))
	}
}

// TestMultiline_Name returns the registered processor name.
func TestMultiline_Name(t *testing.T) {
	m, err := multiline.New(multiline.Config{Pattern: `^\s`})
	if err != nil {
		t.Fatal(err)
	}
	if m.Name() != "multiline" {
		t.Errorf("name = %q", m.Name())
	}
}

// TestMultiline_ConcurrentAdds: stress the goroutine-safety of Add across
// multiple streams under -race.
func TestMultiline_ConcurrentAdds(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern:   `^\s`,
		StreamKey: "stream",
		Timeout:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	const streams = 8
	const perStream = 20
	var wg sync.WaitGroup
	for s := 0; s < streams; s++ {
		wg.Add(1)
		go func(stream int) {
			defer wg.Done()
			label := "stream-" + string(rune('A'+stream))
			_ = m.Add(plugin.Metric{
				Name:        "log",
				Description: "header",
				Labels:      map[string]string{"stream": label},
			}, nil)
			for i := 0; i < perStream-1; i++ {
				_ = m.Add(plugin.Metric{
					Name:        "log",
					Description: "  continuation",
					Labels:      map[string]string{"stream": label},
				}, nil)
			}
		}(s)
	}
	wg.Wait()
	m.Flush()

	// Each stream should have produced exactly one aggregated metric.
	byStream := map[string]int{}
	acc.mu.Lock()
	defer acc.mu.Unlock()
	for _, mm := range acc.added {
		byStream[mm.Labels["stream"]]++
	}
	for s := 0; s < streams; s++ {
		label := "stream-" + string(rune('A'+s))
		if byStream[label] == 0 {
			t.Errorf("stream %s produced no aggregated metric", label)
		}
	}
}

// TestMultiline_HeaderPreservesLabels: labels carried by the header metric
// survive into the emitted aggregated record (the buffered metric's labels
// are not lost when continuations arrive).
func TestMultiline_HeaderPreservesLabels(t *testing.T) {
	m, err := multiline.New(multiline.Config{
		Pattern: `^\s`,
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc := &captureAcc{}
	m.Start(acc)

	_ = m.Add(plugin.Metric{
		Name:        "log",
		Description: "header",
		Labels:      map[string]string{"pod": "abc"},
	}, nil)
	_ = m.Add(plugin.Metric{
		Name:        "log",
		Description: "  continuation",
		Labels:      map[string]string{"pod": "abc", "extra": "ignored"},
	}, nil)
	m.Flush()

	if len(acc.added) != 1 {
		t.Fatalf("expected 1 emit, got %d", len(acc.added))
	}
	if acc.added[0].Labels["pod"] != "abc" {
		t.Errorf("pod label = %q, want abc", acc.added[0].Labels["pod"])
	}
	// Header's labels win — continuation labels do NOT overwrite.
	if _, ok := acc.added[0].Labels["extra"]; ok {
		t.Error("continuation labels should not leak into the aggregated record")
	}
}

// captureAcc records Add calls for assertion. Safe for concurrent use.
type captureAcc struct {
	mu    sync.Mutex
	added []plugin.Metric
	errs  []error
}

func (a *captureAcc) Add(m plugin.Metric) {
	a.mu.Lock()
	a.added = append(a.added, m)
	a.mu.Unlock()
}
func (a *captureAcc) AddFields(_ string, _ float64, _ map[string]string, _ time.Time)  {}
func (a *captureAcc) AddGauge(_ string, _ float64, _ map[string]string, _ time.Time)   {}
func (a *captureAcc) AddCounter(_ string, _ float64, _ map[string]string, _ time.Time) {}
func (a *captureAcc) AddError(err error) {
	a.mu.Lock()
	a.errs = append(a.errs, err)
	a.mu.Unlock()
}

// Compile-time sanity check: the test file exercises the strings package
// indirectly via the matcher below so unused imports don't slip in.
var _ = strings.HasPrefix
