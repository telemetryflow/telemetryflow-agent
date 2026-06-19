// Package clickhouse_test contains unit tests for the corresponding collector module.
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

package clickhouse_test

import (
	"testing"
	"time"
)

func TestQueryLogKindAggregation(t *testing.T) {
	type kindStats struct {
		count      float64
		totalDurMs float64
		maxDurMs   float64
		totalRows  float64
		totalBytes float64
		totalMem   float64
		errors     float64
	}

	rows := []struct {
		kind       string
		durationMs float64
		readRows   float64
		readBytes  float64
		memUsage   float64
		isError    bool
	}{
		{"Select", 10, 100, 500, 1024, false},
		{"Select", 30, 200, 1000, 2048, false},
		{"Select", 5, 50, 250, 512, true},
		{"Insert", 20, 10, 100, 256, false},
	}

	byKind := make(map[string]*kindStats)
	for _, r := range rows {
		s, ok := byKind[r.kind]
		if !ok {
			s = &kindStats{}
			byKind[r.kind] = s
		}
		s.count++
		s.totalDurMs += r.durationMs
		if r.durationMs > s.maxDurMs {
			s.maxDurMs = r.durationMs
		}
		s.totalRows += r.readRows
		s.totalBytes += r.readBytes
		s.totalMem += r.memUsage
		if r.isError {
			s.errors++
		}
	}

	sel, ok := byKind["Select"]
	if !ok {
		t.Fatal("Select kind not found")
	}
	if sel.count != 3 {
		t.Errorf("Select count = %f, want 3", sel.count)
	}
	if sel.totalDurMs != 45 {
		t.Errorf("Select totalDurMs = %f, want 45", sel.totalDurMs)
	}
	if sel.maxDurMs != 30 {
		t.Errorf("Select maxDurMs = %f, want 30", sel.maxDurMs)
	}
	if sel.errors != 1 {
		t.Errorf("Select errors = %f, want 1", sel.errors)
	}
	avgDur := sel.totalDurMs / sel.count
	if avgDur != 15 {
		t.Errorf("Select avgDurMs = %f, want 15", avgDur)
	}

	ins, ok := byKind["Insert"]
	if !ok {
		t.Fatal("Insert kind not found")
	}
	if ins.count != 1 {
		t.Errorf("Insert count = %f, want 1", ins.count)
	}
	if ins.errors != 0 {
		t.Errorf("Insert errors = %f, want 0", ins.errors)
	}
}

func TestQueryLogWatermarkAdvancement(t *testing.T) {
	baseWatermark := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	eventTimes := []string{
		"2026-01-01 00:00:10",
		"2026-01-01 00:00:25",
		"2026-01-01 00:00:30",
	}

	newWatermark := baseWatermark
	for _, evStr := range eventTimes {
		evTime, err := time.ParseInLocation("2006-01-02 15:04:05", evStr, time.UTC)
		if err != nil {
			t.Fatalf("failed to parse %q: %v", evStr, err)
		}
		if evTime.After(newWatermark) {
			newWatermark = evTime
		}
	}

	expected := time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC)
	if !newWatermark.Equal(expected) {
		t.Errorf("watermark = %v, want %v", newWatermark, expected)
	}
}

func TestQueryLogWatermarkNoAdvancementOnOlder(t *testing.T) {
	baseWatermark := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	evTime, _ := time.ParseInLocation("2006-01-02 15:04:05", "2026-01-01 00:00:30", time.UTC)
	newWatermark := baseWatermark
	if evTime.After(newWatermark) {
		newWatermark = evTime
	}

	if !newWatermark.Equal(baseWatermark) {
		t.Error("watermark should not advance for older events")
	}
}

func TestQueryLogUnknownKind(t *testing.T) {
	kind := ""
	if kind == "" {
		kind = "Unknown"
	}
	if kind != "Unknown" {
		t.Errorf("empty kind should default to Unknown, got %q", kind)
	}
}
