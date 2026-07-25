// Tests for the selfstat package.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package selfstat

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// resetRegistry is a test helper that restores a clean registry state.
// After Reset the agent-level package variables still reference orphan stats,
// so tests that exercise the agent globals should not rely on AllMetrics
// reflecting them post-reset.
func resetRegistry(t *testing.T) {
	t.Helper()
	Reset()
}

func TestRegisterStat_CounterSemantics(t *testing.T) {
	resetRegistry(t)
	cases := []struct {
		name      string
		ops       func(s Stat)
		wantGet   int64
		wantReset bool
	}{
		{
			name:    "incr accumulates",
			ops:     func(s Stat) { s.Incr(1); s.Incr(2); s.Incr(3) },
			wantGet: 6,
		},
		{
			name:    "set replaces",
			ops:     func(s Stat) { s.Incr(10); s.Set(42); s.Incr(1) },
			wantGet: 43,
		},
		{
			name:    "incr negative subtracts",
			ops:     func(s Stat) { s.Set(10); s.Incr(-4) },
			wantGet: 6,
		},
		{
			name:    "zero on fresh stat",
			ops:     func(s Stat) {},
			wantGet: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetRegistry(t)
			s := RegisterStat("test.counter", map[string]string{"case": tc.name})
			tc.ops(s)
			if got := s.Get(); got != tc.wantGet {
				t.Fatalf("Get = %d, want %d", got, tc.wantGet)
			}
		})
	}
}

func TestRegisterStat_DedupesByIdentity(t *testing.T) {
	resetRegistry(t)
	s1 := RegisterStat("dup", map[string]string{"k": "v"})
	s2 := RegisterStat("dup", map[string]string{"k": "v"})
	if s1 != s2 {
		t.Fatalf("expected identical handle for same (name, labels)")
	}
	s1.Incr(7)
	if got := s2.Get(); got != 7 {
		t.Fatalf("expected shared state, got %d", got)
	}
}

func TestRegisterStat_DistinguishesByLabels(t *testing.T) {
	resetRegistry(t)
	a := RegisterStat("n", map[string]string{"x": "1"})
	b := RegisterStat("n", map[string]string{"x": "2"})
	if a == b {
		t.Fatalf("expected distinct handles for distinct labels")
	}
	a.Incr(3)
	if got := b.Get(); got != 0 {
		t.Fatalf("expected independent state, got %d", got)
	}
}

func TestRegisterStat_NameAndLabels(t *testing.T) {
	resetRegistry(t)
	in := map[string]string{"a": "1", "b": "2"}
	s := RegisterStat("named", in)
	if s.Name() != "named" {
		t.Fatalf("Name = %q, want %q", s.Name(), "named")
	}
	got := s.Labels()
	if len(got) != 2 || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("Labels = %v, want %v", got, in)
	}
	// Mutating the returned map must not affect the stat.
	got["a"] = "mut"
	if s.Labels()["a"] != "1" {
		t.Fatalf("Labels() returned shared map reference")
	}
	// Mutating the input map must not affect the stat either.
	in["a"] = "external"
	if s.Labels()["a"] != "1" {
		t.Fatalf("stat captured input map by reference")
	}
}

func TestGet_Lookup(t *testing.T) {
	resetRegistry(t)
	if _, ok := Get("missing", nil); ok {
		t.Fatalf("expected miss for unregistered stat")
	}
	RegisterStat("present", map[string]string{"k": "v"})
	if _, ok := Get("present", map[string]string{"k": "v"}); !ok {
		t.Fatalf("expected hit for registered stat")
	}
	if _, ok := Get("present", map[string]string{"k": "other"}); ok {
		t.Fatalf("expected miss for mismatched labels")
	}
}

func TestRegisterTimingStat_AveragesSamples(t *testing.T) {
	resetRegistry(t)
	tt := RegisterTimingStat("timing", nil)
	tt.Add(10 * time.Nanosecond)
	tt.Add(20 * time.Nanosecond)
	tt.Add(30 * time.Nanosecond)
	got := tt.Get()
	if want := int64(20); got != want {
		t.Fatalf("Get = %d, want %d", got, want)
	}
}

func TestRegisterTimingStat_ClearsAfterRead(t *testing.T) {
	resetRegistry(t)
	tt := RegisterTimingStat("timing.clear", nil)
	tt.Add(100 * time.Nanosecond)
	if got := tt.Get(); got != 100 {
		t.Fatalf("first Get = %d, want 100", got)
	}
	if got := tt.Get(); got != 0 {
		t.Fatalf("second Get = %d, want 0 (cleared)", got)
	}
	tt.Add(50 * time.Nanosecond)
	tt.Add(150 * time.Nanosecond)
	if got := tt.Get(); got != 100 {
		t.Fatalf("third Get = %d, want 100", got)
	}
}

func TestRegisterTimingStat_NameAndLabels(t *testing.T) {
	resetRegistry(t)
	in := map[string]string{"phase": "write"}
	tt := RegisterTimingStat("timing.named", in)
	if tt.Name() != "timing.named" {
		t.Fatalf("Name = %q", tt.Name())
	}
	if got := tt.Labels(); got["phase"] != "write" || len(got) != 1 {
		t.Fatalf("Labels = %v", got)
	}
}

func TestAllMetrics_NamesAndCounterType(t *testing.T) {
	resetRegistry(t)
	RegisterStat("alpha", map[string]string{"x": "1"})
	RegisterStat("alpha", map[string]string{"x": "2"})
	RegisterTimingStat("beta.timing", nil)

	metrics := AllMetrics()
	if len(metrics) != 3 {
		t.Fatalf("len(metrics) = %d, want 3", len(metrics))
	}

	seen := make(map[string]int, len(metrics))
	for _, m := range metrics {
		if m.Type != plugin.MetricTypeCounter {
			t.Errorf("metric %q: Type = %q, want %q", m.Name, m.Type, plugin.MetricTypeCounter)
		}
		if m.Timestamp.IsZero() {
			t.Errorf("metric %q: Timestamp not set", m.Name)
		}
		if m.Labels == nil {
			t.Errorf("metric %q: Labels is nil", m.Name)
		}
		seen[m.Name]++
	}
	if seen["alpha"] != 2 {
		t.Errorf("alpha occurrences = %d, want 2", seen["alpha"])
	}
	if seen["beta.timing"] != 1 {
		t.Errorf("beta.timing occurrences = %d, want 1", seen["beta.timing"])
	}
}

func TestAllMetrics_TimingReadsAreDestructive(t *testing.T) {
	resetRegistry(t)
	tt := RegisterTimingStat("destructive", nil)
	tt.Add(1 * time.Microsecond)
	metrics := AllMetrics()
	var found float64
	for _, m := range metrics {
		if m.Name == "destructive" {
			found = m.Value
		}
	}
	if found == 0 {
		t.Fatalf("expected non-zero timing value in AllMetrics output")
	}
	// Second snapshot: timing should have been cleared.
	for _, m := range AllMetrics() {
		if m.Name == "destructive" && m.Value != 0 {
			t.Fatalf("timing stat was not cleared after AllMetrics")
		}
	}
}

func TestForCollector_NonNilAndCorrectLabels(t *testing.T) {
	resetRegistry(t)
	cs := ForCollector("cpu")
	if cs == nil {
		t.Fatalf("ForCollector returned nil")
	}
	checks := []struct {
		name string
		s    Stat
	}{
		{"MetricsGathered", cs.MetricsGathered},
		{"GatherErrors", cs.GatherErrors},
		{"GatherTimeouts", cs.GatherTimeouts},
		{"StartupErrors", cs.StartupErrors},
		{"State", cs.State},
	}
	for _, c := range checks {
		if c.s == nil {
			t.Errorf("%s is nil", c.name)
			continue
		}
		if got := c.s.Labels()["collector"]; got != "cpu" {
			t.Errorf("%s collector label = %q, want %q", c.name, got, "cpu")
		}
	}
	if cs.GatherTimeNS == nil {
		t.Fatalf("GatherTimeNS is nil")
	}
	if got := cs.GatherTimeNS.Labels()["collector"]; got != "cpu" {
		t.Errorf("GatherTimeNS collector label = %q, want %q", got, "cpu")
	}

	// State should be settable as a gauge.
	cs.State.Set(CollectorStateRunning)
	if got := cs.State.Get(); got != CollectorStateRunning {
		t.Errorf("State.Get = %d, want %d", got, CollectorStateRunning)
	}
}

func TestForCollector_StableIdentity(t *testing.T) {
	resetRegistry(t)
	a := ForCollector("disk")
	b := ForCollector("disk")
	if a.MetricsGathered != b.MetricsGathered {
		t.Fatalf("expected same handle across ForCollector calls")
	}
	c := ForCollector("net")
	if a.MetricsGathered == c.MetricsGathered {
		t.Fatalf("expected distinct handles for distinct collectors")
	}
}

func TestForExporter_NonNilAndCorrectLabels(t *testing.T) {
	resetRegistry(t)
	es := ForExporter("otlp")
	if es == nil {
		t.Fatalf("ForExporter returned nil")
	}
	checks := []struct {
		name string
		s    Stat
	}{
		{"MetricsWritten", es.MetricsWritten},
		{"MetricsRejected", es.MetricsRejected},
		{"MetricsDropped", es.MetricsDropped},
		{"BufferedMetrics", es.BufferedMetrics},
		{"BufferSize", es.BufferSize},
		{"BufferLimit", es.BufferLimit},
		{"WriteErrors", es.WriteErrors},
		{"MetricsFiltered", es.MetricsFiltered},
	}
	for _, c := range checks {
		if c.s == nil {
			t.Errorf("%s is nil", c.name)
			continue
		}
		if got := c.s.Labels()["exporter"]; got != "otlp" {
			t.Errorf("%s exporter label = %q, want %q", c.name, got, "otlp")
		}
	}
	if es.WriteTimeNS == nil {
		t.Fatalf("WriteTimeNS is nil")
	}
}

func TestForExporter_StableIdentity(t *testing.T) {
	resetRegistry(t)
	a := ForExporter("prom")
	b := ForExporter("prom")
	if a.MetricsWritten != b.MetricsWritten {
		t.Fatalf("expected same handle across ForExporter calls")
	}
}

func TestReset_ClearsState(t *testing.T) {
	resetRegistry(t)
	s := RegisterStat("ephemeral", nil)
	s.Incr(5)
	if got := len(AllMetrics()); got != 1 {
		t.Fatalf("pre-reset AllMetrics len = %d, want 1", got)
	}
	Reset()
	if got := len(AllMetrics()); got != 0 {
		t.Fatalf("post-reset AllMetrics len = %d, want 0", got)
	}
	if _, ok := Get("ephemeral", nil); ok {
		t.Fatalf("Get returned true after Reset")
	}
}

func TestConcurrency_ParallelIncrMatchesSum(t *testing.T) {
	resetRegistry(t)
	s := RegisterStat("concurrent", map[string]string{"case": "parallel"})
	const goroutines = 100
	const perGoroutine = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				s.Incr(1)
			}
		}()
	}
	wg.Wait()
	want := int64(goroutines * perGoroutine)
	if got := s.Get(); got != want {
		t.Fatalf("Get = %d, want %d", got, want)
	}
}

func TestConcurrency_ParallelRegisterAndIncr(t *testing.T) {
	resetRegistry(t)
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var success int64
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			labels := map[string]string{"phase": fmt.Sprintf("g-%d", i%4)}
			s := RegisterStat("shared.register", labels)
			s.Incr(1)
			atomic.AddInt64(&success, 1)
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt64(&success); got != goroutines {
		t.Fatalf("success = %d, want %d", got, goroutines)
	}
}

// Property: AllMetrics output value equals current Get() for any counter.
func TestProperty_AllMetricsMatchesGet(t *testing.T) {
	resetRegistry(t)
	s := RegisterStat("prop", map[string]string{"k": "v"})
	s.Set(12345)
	for _, m := range AllMetrics() {
		if m.Name == "prop" && m.Labels["k"] == "v" {
			if m.Value != 12345 {
				t.Fatalf("AllMetrics Value = %v, want 12345", m.Value)
			}
			return
		}
	}
	t.Fatalf("prop stat missing from AllMetrics")
}

func TestAgentGlobals_RegisteredOnInit(t *testing.T) {
	// These are populated by init(); they may already have been touched by
	// earlier tests' Reset(), but the package variables must remain
	// non-nil regardless of registry state.
	for name, s := range map[string]Stat{
		"AgentMetricsWritten":  AgentMetricsWritten,
		"AgentMetricsRejected": AgentMetricsRejected,
		"AgentMetricsDropped":  AgentMetricsDropped,
		"AgentMetricsGathered": AgentMetricsGathered,
		"AgentGatherErrors":    AgentGatherErrors,
		"AgentGatherTimeouts":  AgentGatherTimeouts,
		"AgentWriteErrors":     AgentWriteErrors,
		"AgentBufferSize":      AgentBufferSize,
		"AgentBufferLimit":     AgentBufferLimit,
		"AgentVersionInfo":     AgentVersionInfo,
	} {
		if s == nil {
			t.Errorf("%s is nil after init()", name)
		}
	}
	if got := AgentVersionInfo.Get(); got != 1 {
		t.Errorf("AgentVersionInfo.Get = %d, want 1 (info gauge)", got)
	}
	if l := AgentVersionInfo.Labels(); l["version"] == "" {
		t.Errorf("AgentVersionInfo missing version label")
	}
}
