// Package collector defines the Collector interface and shared metric types
// used by every data-collection subsystem in the TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
package collector

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type Backoff struct {
	mu         sync.Mutex
	initial    time.Duration
	max        time.Duration
	multiplier float64
	attempt    int
	jitter     float64
	rng        *rand.Rand
}

func NewBackoff(initial, max time.Duration, multiplier float64) *Backoff {
	return &Backoff{
		initial:    initial,
		max:        max,
		multiplier: multiplier,
		jitter:     0.1,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	d := float64(b.initial) * math.Pow(b.multiplier, float64(b.attempt))
	if d > float64(b.max) {
		d = float64(b.max)
	}

	jitterRange := d * b.jitter
	d += b.rng.Float64()*jitterRange - jitterRange/2
	if d < float64(b.initial) {
		d = float64(b.initial)
	}

	b.attempt++
	return time.Duration(d)
}

func (b *Backoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempt = 0
}

func (b *Backoff) Attempt() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempt
}
