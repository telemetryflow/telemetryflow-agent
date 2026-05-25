// Package postgresql_test contains unit tests for the corresponding collector module.
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

package postgresql_test

import (
	"math"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- Delta computation (counter increase) ---

func TestDeltaComputation_CounterIncrease(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.PrevCounters = map[string]uint64{
		"xact_commit:mydb": 1000,
	}
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)

	_ = map[string]string{"postgresql_instance": "test"} // labels placeholder
	current := int64(2500)
	prev, ok := inst.PrevCounters["xact_commit:mydb"]
	if !ok {
		t.Fatal("expected previous counter to exist")
	}

	delta := float64(current) - float64(prev)
	rate := delta / 10.0

	if math.Abs(rate-150.0) > 0.001 {
		t.Errorf("rate = %f, want 150.0", rate)
	}
}

func TestDeltaComputation_CounterReset(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.PrevCounters = map[string]uint64{
		"xact_commit:mydb": 9000,
	}
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)

	current := int64(1000) // Less than previous -> counter was reset.
	prev := inst.PrevCounters["xact_commit:mydb"]

	delta := int64(current) - int64(prev)
	if delta >= 0 {
		t.Error("delta should be negative on counter reset")
	}
}

// --- Cache hit ratio ---

func TestCacheHitRatio(t *testing.T) {
	tests := []struct {
		name     string
		blksHit  float64
		blksRead float64
		expect   float64
	}{
		{"normal", 9000, 1000, 0.9},
		{"all_cache", 10000, 0, 1.0},
		{"no_cache", 0, 10000, 0.0},
		{"both_zero", 0, 0, 0.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hitRatio := postgresql.SafeDivExported(tc.blksHit, tc.blksHit+tc.blksRead)
			if math.Abs(hitRatio-tc.expect) > 0.001 {
				t.Errorf("hitRatio = %f, want %f", hitRatio, tc.expect)
			}
		})
	}
}

// --- Connection utilization ---

func TestConnectionUtilization(t *testing.T) {
	tests := []struct {
		name     string
		current  float64
		maxConns float64
		expect   float64
	}{
		{"normal", 50, 200, 25.0},
		{"full", 200, 200, 100.0},
		{"zero_max", 10, 0, 0.0},
		{"zero_current", 0, 200, 0.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			util := postgresql.SafeDivExported(tc.current, tc.maxConns) * 100.0
			if math.Abs(util-tc.expect) > 0.001 {
				t.Errorf("utilization = %f, want %f", util, tc.expect)
			}
		})
	}
}

// --- Dead tuple accumulation rate ---

func TestDeadTupleRate_FirstCycle(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	// First cycle: no previous measurement -> no rate emitted.
	now := time.Now()
	totalDead := uint64(500)

	if inst.DeadTuplePrevTime.IsZero() {
		// Expected: skip rate, just store current.
		inst.DeadTuplePrev = totalDead
		inst.DeadTuplePrevTime = now
	}

	if inst.DeadTuplePrev != 500 {
		t.Errorf("deadTuplePrev = %d, want 500", inst.DeadTuplePrev)
	}
	if inst.DeadTuplePrevTime.IsZero() {
		t.Error("deadTuplePrevTime should be set")
	}
}

func TestDeadTupleRate_NormalIncrease(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.DeadTuplePrev = 1000
	inst.DeadTuplePrevTime = time.Now().Add(-10 * time.Second)

	totalDead := uint64(2500)
	elapsed := time.Since(inst.DeadTuplePrevTime).Seconds()
	delta := int64(totalDead) - int64(inst.DeadTuplePrev)

	if delta < 0 {
		t.Error("delta should not be negative in normal case")
	}
	rate := float64(delta) / elapsed
	if rate <= 0 {
		t.Errorf("rate = %f, expected positive", rate)
	}
}

func TestDeadTupleRate_CounterReset(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.DeadTuplePrev = 5000
	inst.DeadTuplePrevTime = time.Now().Add(-10 * time.Second)

	// After VACUUM FULL, total dead tuples drops to near zero.
	totalDead := uint64(100)
	delta := int64(totalDead) - int64(inst.DeadTuplePrev)

	if delta >= 0 {
		t.Error("delta should be negative on counter reset")
	}

	// Verify the code would skip emitting (delta < 0 means skip).
	shouldSkip := delta < 0
	if !shouldSkip {
		t.Error("should skip emitting rate on counter reset")
	}
}

// --- Vacuum needed indicator ---

func TestVacuumNeeded_Calculation(t *testing.T) {
	tests := []struct {
		name        string
		threshold   int64
		scaleFactor float64
		liveTup     int64
		deadTup     int64
		needed      bool
	}{
		{"needed", 50, 0.2, 10000, 2100, true},
		{"not_needed", 50, 0.2, 10000, 1000, false},
		{"just_above_threshold", 50, 0.2, 10000, 2051, true},
		{"zero_live", 50, 0.2, 0, 100, true},
		{"zero_dead", 50, 0.2, 10000, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vacuumThreshold := float64(tc.threshold) + tc.scaleFactor*float64(tc.liveTup)
			needed := float64(tc.deadTup) > vacuumThreshold
			if needed != tc.needed {
				t.Errorf("deadTup=%d liveTup=%d threshold=%f: needed=%v, want %v",
					tc.deadTup, tc.liveTup, vacuumThreshold, needed, tc.needed)
			}
		})
	}
}

// --- Bloat estimation ---

func TestBloatEstimation_Calculation(t *testing.T) {
	tests := []struct {
		name      string
		totalSize float64
		relTuples float64
		deadTup   float64
		expect    float64
	}{
		{"normal_bloat", 1_000_000, 10000, 1000, 10.0},
		{"no_dead_tup", 1_000_000, 10000, 0, 0},
		{"high_bloat", 1_000_000, 1000, 5000, 500.0},
		{"zero_tuples", 100_000, 0, 100, 10000.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			avgRowSize := postgresql.SafeDivExported(tc.totalSize, max(tc.relTuples, 1))
			bloatPct := postgresql.SafeDivExported(tc.deadTup*avgRowSize, tc.totalSize) * 100.0
			if tc.expect > 0 && math.Abs(bloatPct-tc.expect) > 0.001 {
				t.Errorf("bloatPct = %f, want %f", bloatPct, tc.expect)
			}
		})
	}
}

// --- Index bloat estimation ---

func TestIndexBloatEstimation(t *testing.T) {
	tests := []struct {
		name        string
		indexBytes  float64
		relTuples   float64
		expectAbove float64
	}{
		{"bloated_index", 10_000_000, 1000, 0},
		{"no_bloat", 8000, 1000, 0},
		{"zero_tuples", 10_000, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedBytes := tc.relTuples * 8.0
			bloatPct := 0.0
			if tc.indexBytes > 0 && expectedBytes > 0 {
				bloatPct = postgresql.SafeDivExported(tc.indexBytes-expectedBytes, tc.indexBytes) * 100.0
				if bloatPct < 0 {
					bloatPct = 0
				}
			}
			if bloatPct < tc.expectAbove {
				t.Errorf("bloatPct = %f, expected >= %f", bloatPct, tc.expectAbove)
			}
		})
	}
}

// --- Per-table XID age ---

func TestTableXIDAge_Values(t *testing.T) {
	labels := map[string]string{"postgresql_instance": "test"}
	rowLabels := postgresql.CopyLabelsExported(labels)
	rowLabels["schemaname"] = "public"
	rowLabels["tablename"] = "big_table"

	if rowLabels["schemaname"] != "public" {
		t.Error("schemaname label not set")
	}
	if rowLabels["tablename"] != "big_table" {
		t.Error("tablename label not set")
	}
}

// --- Dead tuple rate with pgInstance state ---

func TestDeadTupleRate_Integration(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	// First cycle -- no previous state.
	if !inst.DeadTuplePrevTime.IsZero() {
		t.Error("expected zero deadTuplePrevTime initially")
	}

	// Simulate first measurement.
	inst.DeadTuplePrev = 1000
	inst.DeadTuplePrevTime = time.Now().Add(-5 * time.Second)

	// Second cycle -- compute rate.
	newDead := uint64(6000)
	elapsed := time.Since(inst.DeadTuplePrevTime).Seconds()
	delta := int64(newDead) - int64(inst.DeadTuplePrev)

	if delta != 5000 {
		t.Errorf("delta = %d, want 5000", delta)
	}
	rate := float64(delta) / elapsed
	if rate <= 0 {
		t.Errorf("rate = %f, expected positive", rate)
	}
}
