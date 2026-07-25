// Package selfstat implements internal agent self-observability counters and
// timings, mirroring Telegraf's selfstat package. Subsystems register named
// stats (optionally labelled) and mutate them as the agent runs; an internal
// collector periodically snapshots them into the normal metric pipeline via
// AllMetrics.
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// Stat is a single integer-valued internal counter or gauge. Implementations
// are safe for concurrent use.
type Stat interface {
	// Set replaces the current value. Used for gauge-style stats.
	Set(v int64)
	// Incr adds delta to the current value. Used for counter-style stats.
	Incr(delta int64)
	// Get returns the current value.
	Get() int64
	// Name returns the metric name this stat is registered under.
	Name() string
	// Labels returns a defensive copy of the stat's label set.
	Labels() map[string]string
}

// TimingStat accumulates duration samples and returns their running average
// (in nanoseconds) on Get, clearing the accumulator. Implementations are safe
// for concurrent use.
type TimingStat interface {
	// Add records a single duration sample.
	Add(d time.Duration)
	// Get returns the average sample in nanoseconds since the previous Get
	// (or since registration if never read), then clears the accumulator.
	// Returns 0 when no samples have been recorded since the last Get.
	Get() int64
	// Name returns the metric name this stat is registered under.
	Name() string
	// Labels returns a defensive copy of the stat's label set.
	Labels() map[string]string
}

// intStat is the default Stat implementation: an atomic int64 with an
// immutable name and label set.
type intStat struct {
	name   string
	labels map[string]string
	value  atomic.Int64
}

// Set replaces the current value atomically.
func (s *intStat) Set(v int64) { s.value.Store(v) }

// Incr adds delta to the current value atomically.
func (s *intStat) Incr(delta int64) { s.value.Add(delta) }

// Get returns the current value atomically.
func (s *intStat) Get() int64 { return s.value.Load() }

// Name returns the metric name.
func (s *intStat) Name() string { return s.name }

// Labels returns a defensive copy of the label set.
func (s *intStat) Labels() map[string]string { return copyLabels(s.labels) }

// timingStatImpl is the default TimingStat implementation: a mutex-guarded
// running sum and sample count.
type timingStatImpl struct {
	name   string
	labels map[string]string
	mu     sync.Mutex
	sum    int64 // accumulated nanoseconds
	count  int64 // number of samples since last Get
}

// Add records a single duration sample.
func (t *timingStatImpl) Add(d time.Duration) {
	ns := int64(d)
	t.mu.Lock()
	t.sum += ns
	t.count++
	t.mu.Unlock()
}

// Get returns the average sample in nanoseconds since the previous Get and
// clears the accumulator. Returns 0 when no samples have been recorded.
func (t *timingStatImpl) Get() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count == 0 {
		return 0
	}
	avg := t.sum / t.count
	t.sum = 0
	t.count = 0
	return avg
}

// Name returns the metric name.
func (t *timingStatImpl) Name() string { return t.name }

// Labels returns a defensive copy of the label set.
func (t *timingStatImpl) Labels() map[string]string { return copyLabels(t.labels) }

// registry holds all stats and timings keyed by a deterministic
// (name + sorted labels) identifier. Each unique (name, labels) pair is
// represented exactly once so callers can re-acquire the same handle from
// multiple call sites.
type registry struct {
	mu      sync.RWMutex
	stats   map[string]Stat
	timings map[string]TimingStat
}

var reg = &registry{
	stats:   make(map[string]Stat),
	timings: make(map[string]TimingStat),
}

// labelsKey builds a stable string identifier for a (name, labels) pair by
// sorting labels alphabetically. The same input always yields the same key.
func labelsKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(name)
	for _, k := range keys {
		sb.WriteByte('|')
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(labels[k])
	}
	return sb.String()
}

// copyLabels returns a shallow copy of the input map; safe to call on nil.
func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// RegisterStat creates (or returns an existing) counter-style Stat for the
// given name and label set. Re-registration with identical arguments returns
// the same Stat instance, allowing independent subsystems to share a counter.
func RegisterStat(name string, labels map[string]string) Stat {
	key := labelsKey(name, labels)
	reg.mu.RLock()
	if s, ok := reg.stats[key]; ok {
		reg.mu.RUnlock()
		return s
	}
	reg.mu.RUnlock()

	reg.mu.Lock()
	defer reg.mu.Unlock()
	if s, ok := reg.stats[key]; ok {
		return s
	}
	s := &intStat{
		name:   name,
		labels: copyLabels(labels),
	}
	reg.stats[key] = s
	return s
}

// RegisterTimingStat creates (or returns an existing) TimingStat for the
// given name and label set. Re-registration with identical arguments returns
// the same instance.
func RegisterTimingStat(name string, labels map[string]string) TimingStat {
	key := labelsKey(name, labels)
	reg.mu.RLock()
	if t, ok := reg.timings[key]; ok {
		reg.mu.RUnlock()
		return t
	}
	reg.mu.RUnlock()

	reg.mu.Lock()
	defer reg.mu.Unlock()
	if t, ok := reg.timings[key]; ok {
		return t
	}
	t := &timingStatImpl{
		name:   name,
		labels: copyLabels(labels),
	}
	reg.timings[key] = t
	return t
}

// Get looks up a previously registered Stat by name and labels. The bool
// return is false when no such stat exists.
func Get(name string, labels map[string]string) (Stat, bool) {
	key := labelsKey(name, labels)
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	s, ok := reg.stats[key]
	return s, ok
}

// AllMetrics returns a snapshot of every registered Stat and TimingStat as a
// slice of plugin.Metric. Stats are emitted as counter metrics with the
// current timestamp. TimingStats are read destructively: their running
// average (in nanoseconds) is returned and their accumulator is cleared, so
// each collector tick reports only the samples observed since the previous
// tick.
//
// The returned metrics are safe to mutate; label maps are fresh copies.
func AllMetrics() []plugin.Metric {
	reg.mu.RLock()
	stats := make([]Stat, 0, len(reg.stats))
	for _, s := range reg.stats {
		stats = append(stats, s)
	}
	timings := make([]TimingStat, 0, len(reg.timings))
	for _, t := range reg.timings {
		timings = append(timings, t)
	}
	reg.mu.RUnlock()

	now := time.Now()
	out := make([]plugin.Metric, 0, len(stats)+len(timings))
	for _, s := range stats {
		out = append(out, plugin.Metric{
			Name:      s.Name(),
			Type:      plugin.MetricTypeCounter,
			Value:     float64(s.Get()),
			Timestamp: now,
			Labels:    s.Labels(),
		})
	}
	for _, t := range timings {
		out = append(out, plugin.Metric{
			Name:      t.Name(),
			Type:      plugin.MetricTypeCounter,
			Value:     float64(t.Get()),
			Timestamp: now,
			Labels:    t.Labels(),
		})
	}
	return out
}

// Reset clears every registered Stat and TimingStat. Intended for test
// isolation only; callers in production code should not invoke it.
func Reset() {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.stats = make(map[string]Stat)
	reg.timings = make(map[string]TimingStat)
}
