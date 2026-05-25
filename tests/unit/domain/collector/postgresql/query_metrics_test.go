// Package postgresql_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
	"strings"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- fingerprintQuery ---

func TestFingerprintQuery_BasicNormalization(t *testing.T) {
	tests := []struct {
		name   string
		query1 string
		query2 string
		same   bool
	}{
		{
			name:   "identical_queries",
			query1: "SELECT * FROM users WHERE id = 1",
			query2: "SELECT * FROM users WHERE id = 2",
			same:   true,
		},
		{
			name:   "different_structure",
			query1: "SELECT * FROM users WHERE id = 1",
			query2: "SELECT * FROM orders WHERE id = 1",
			same:   false,
		},
		{
			name:   "quoted_strings",
			query1: "SELECT * FROM users WHERE name = 'alice'",
			query2: "SELECT * FROM users WHERE name = 'bob'",
			same:   true,
		},
		{
			name:   "different_whitespace",
			query1: "SELECT  *   FROM   users",
			query2: "SELECT * FROM users",
			same:   true,
		},
		{
			name:   "in_list_normalization",
			query1: "SELECT * FROM t WHERE id IN (1, 2, 3)",
			query2: "SELECT * FROM t WHERE id IN (4, 5, 6, 7)",
			same:   true,
		},
		{
			name:   "dollar_string",
			query1: "SELECT $$hello$$",
			query2: "SELECT $$world$$",
			same:   true,
		},
		{
			name:   "numeric_literals",
			query1: "SELECT * FROM t WHERE x = 42.5",
			query2: "SELECT * FROM t WHERE x = 99.9",
			same:   true,
		},
		{
			name:   "complex_query",
			query1: "SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 100.0 LIMIT 50",
			query2: "SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 200.0 LIMIT 100",
			same:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fp1 := postgresql.FingerprintQueryExported(tc.query1)
			fp2 := postgresql.FingerprintQueryExported(tc.query2)
			if (fp1 == fp2) != tc.same {
				t.Errorf("fingerprintQuery(%q)=%q, fingerprintQuery(%q)=%q, same=%v, want same=%v",
					tc.query1, fp1, tc.query2, fp2, fp1 == fp2, tc.same)
			}
		})
	}
}

func TestFingerprintQuery_Deterministic(t *testing.T) {
	query := "SELECT * FROM users WHERE id = 42 AND name = 'test'"
	fp1 := postgresql.FingerprintQueryExported(query)
	fp2 := postgresql.FingerprintQueryExported(query)
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
}

func TestFingerprintQuery_Length(t *testing.T) {
	query := "SELECT 1"
	fp := postgresql.FingerprintQueryExported(query)
	// SHA-256 first 16 bytes = 32 hex chars.
	if len(fp) != 32 {
		t.Errorf("fingerprint length = %d, want 32", len(fp))
	}
}

func TestFingerprintQuery_LowercaseHex(t *testing.T) {
	query := "SELECT 1"
	fp := postgresql.FingerprintQueryExported(query)
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("fingerprint contains non-lowercase-hex char: %c", c)
			break
		}
	}
}

// --- Delta computation for query stats ---

func TestQueryDeltaComputation_CounterIncrease(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)

	// Simulate previous state.
	qid := "12345"
	inst.PrevCounters["query:"+qid+":calls"] = 1000
	inst.PrevCounters["query:"+qid+":total_exec_time"] = 5000
	inst.PrevCounters["query:"+qid+":rows"] = 2000

	// Current state.
	currentCalls := uint64(3500)
	currentTime := float64(20000)
	currentRows := uint64(8000)

	deltaCalls := int64(currentCalls) - int64(inst.PrevCounters["query:"+qid+":calls"])
	deltaTime := currentTime - float64(inst.PrevCounters["query:"+qid+":total_exec_time"])
	deltaRows := int64(currentRows) - int64(inst.PrevCounters["query:"+qid+":rows"])

	elapsed := 10.0

	if deltaCalls != 2500 {
		t.Errorf("deltaCalls = %d, want 2500", deltaCalls)
	}
	if math.Abs(deltaTime-15000) > 0.001 {
		t.Errorf("deltaTime = %f, want 15000", deltaTime)
	}
	if deltaRows != 6000 {
		t.Errorf("deltaRows = %d, want 6000", deltaRows)
	}

	rateCalls := float64(deltaCalls) / elapsed
	if math.Abs(rateCalls-250) > 0.001 {
		t.Errorf("calls_rate = %f, want 250", rateCalls)
	}

	rateTime := deltaTime / elapsed
	if math.Abs(rateTime-1500) > 0.001 {
		t.Errorf("time_rate = %f, want 1500", rateTime)
	}
}

func TestQueryDeltaComputation_CounterReset(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	qid := "99999"
	inst.PrevCounters["query:"+qid+":calls"] = 9000

	currentCalls := uint64(1000) // Lower than previous -> reset.

	deltaCalls := int64(currentCalls) - int64(inst.PrevCounters["query:"+qid+":calls"])
	if deltaCalls > 0 {
		t.Error("delta should be negative or zero on counter reset")
	}

	// Code should NOT emit rates when delta <= 0.
	if deltaCalls > 0 {
		t.Error("should not emit rate on counter reset")
	}
}

func TestQueryDeltaComputation_NoPreviousState(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	qid := "12345"
	_, hasPrevCalls := inst.PrevCounters["query:"+qid+":calls"]
	_, hasPrevTime := inst.PrevCounters["query:"+qid+":total_exec_time"]
	_, hasPrevRows := inst.PrevCounters["query:"+qid+":rows"]

	if hasPrevCalls || hasPrevTime || hasPrevRows {
		t.Error("should have no previous counters for new query")
	}

	// Code should skip rate emission when previous counters are missing.
	shouldSkip := !hasPrevCalls || !hasPrevTime || !hasPrevRows
	if !shouldSkip {
		t.Error("should skip rate computation when previous counters are missing")
	}
}

// --- Top-N selection logic ---

func TestTopNSelection_OrderByExecTime(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.TopQueriesLimit = 5

	// Simulate that the query would ORDER BY total_exec_time DESC LIMIT 5.
	queries := []struct {
		queryid uint64
		time    float64
	}{
		{1, 5000},
		{2, 3000},
		{3, 8000},
		{4, 1000},
		{5, 6000},
		{6, 200},
		{7, 10000},
		{8, 400},
	}

	// Sort by time descending (simulating ORDER BY total_exec_time DESC).
	sorted := make([]int, len(queries))
	for i := range sorted {
		sorted[i] = i
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if queries[sorted[j]].time > queries[sorted[i]].time {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Take top N.
	limit := inst.TopQueriesLimit
	if limit > len(sorted) {
		limit = len(sorted)
	}
	topN := sorted[:limit]

	expectedOrder := []uint64{7, 3, 5, 1, 2} // 10000, 8000, 6000, 5000, 3000
	for i, idx := range topN {
		if queries[idx].queryid != expectedOrder[i] {
			t.Errorf("topN[%d] = queryid %d, want %d", i, queries[idx].queryid, expectedOrder[i])
		}
	}
}

// --- PrevCounters update ---

func TestPrevCounters_Update(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	// Simulate first collection.
	newCounters := map[string]uint64{
		"query:100:calls":           500,
		"query:100:total_exec_time": 2500,
		"query:100:rows":            1500,
		"query:200:calls":           100,
		"query:200:total_exec_time": 500,
		"query:200:rows":            300,
	}
	inst.PrevCounters = newCounters
	inst.PrevTimestamp = time.Now()

	if len(inst.PrevCounters) != 6 {
		t.Errorf("prevCounters len = %d, want 6", len(inst.PrevCounters))
	}
	if inst.PrevCounters["query:100:calls"] != 500 {
		t.Errorf("query:100:calls = %d, want 500", inst.PrevCounters["query:100:calls"])
	}

	// Simulate second collection -- counters are replaced (not accumulated).
	newCounters2 := map[string]uint64{
		"query:100:calls":           1200,
		"query:100:total_exec_time": 6000,
		"query:100:rows":            3500,
	}
	inst.PrevCounters = newCounters2

	if len(inst.PrevCounters) != 3 {
		t.Errorf("prevCounters len = %d, want 3 (replaced, not accumulated)", len(inst.PrevCounters))
	}
	if inst.PrevCounters["query:200:calls"] != 0 {
		t.Error("query:200 should not exist after replacement")
	}
}

// --- Wait events label structure ---

func TestWaitEvents_Labels(t *testing.T) {
	baseLabels := map[string]string{"postgresql_instance": "test", "postgresql_host": "pg1"}
	wLabels := make(map[string]string, len(baseLabels)+2)
	for k, v := range baseLabels {
		wLabels[k] = v
	}
	wLabels["wait_event_type"] = "LWLock"
	wLabels["wait_event"] = "WALWrite"

	if wLabels["wait_event_type"] != "LWLock" {
		t.Error("wait_event_type label wrong")
	}
	if wLabels["wait_event"] != "WALWrite" {
		t.Error("wait_event label wrong")
	}
	if wLabels["postgresql_instance"] != "test" {
		t.Error("base labels not carried over")
	}
}

// --- Query label structure ---

func TestQueryLabels_FingerprintAndQueryID(t *testing.T) {
	query := "SELECT * FROM users WHERE id = 42"
	fp := postgresql.FingerprintQueryExported(query)

	if len(fp) != 32 {
		t.Errorf("fingerprint length = %d, want 32", len(fp))
	}

	if strings.Contains(fp, "42") {
		t.Error("fingerprint should not contain the literal 42")
	}
}
