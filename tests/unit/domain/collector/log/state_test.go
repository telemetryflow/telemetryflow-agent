// Package log_test — unit tests for the LogCollector persisted-state surface
// (GetState/SetState) and the CollectorState value type. These are pure,
// in-memory operations: no files, journald, or goroutines are involved, so the
// persister round-trip is exercised deterministically.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package log_test

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/log"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func newCollector() *log.LogCollector {
	return log.NewLogCollector(config.LogCollectorConfig{}, "agent-1", zap.NewNop())
}

func TestNewCollectorState_Empty(t *testing.T) {
	s := log.NewCollectorState()
	if s == nil || s.Tailers == nil {
		t.Fatal("NewCollectorState must return a non-nil state with an initialised map")
	}
	if len(s.Tailers) != 0 {
		t.Errorf("expected empty tailers, got %d", len(s.Tailers))
	}
}

func TestGetState_NoTailers(t *testing.T) {
	c := newCollector()
	st := c.GetState()
	cs, ok := st.(*log.CollectorState)
	if !ok {
		t.Fatalf("GetState must return *CollectorState, got %T", st)
	}
	if cs.Tailers == nil {
		t.Error("Tailers map must be non-nil even with no tailers")
	}
}

func TestSetState_Nil_NoOp(t *testing.T) {
	c := newCollector()
	c.SetState(nil) // must not panic; nothing restored
}

func TestSetState_TypedPointer(t *testing.T) {
	c := newCollector()
	in := &log.CollectorState{Tailers: map[string]log.TailerState{
		"/var/log/app.log": {Path: "/var/log/app.log", Inode: 42, Offset: 1024, Fingerprint: "abc"},
	}}
	c.SetState(in) // must not panic; stored as restoredState
}

func TestSetState_TypedValue(t *testing.T) {
	c := newCollector()
	in := log.CollectorState{Tailers: map[string]log.TailerState{
		"/var/log/x.log": {Path: "/var/log/x.log", Offset: 7},
	}}
	c.SetState(in) // value (non-pointer) variant branch
}

func TestSetState_UnknownShape_Ignored(t *testing.T) {
	c := newCollector()
	c.SetState(12345)          // default branch — silently ignored
	c.SetState("not a state")  // default branch
	c.SetState([]int{1, 2, 3}) // default branch
}

// TestSetState_JSONMapRoundTrip drives the map[string]interface{} branch that
// the persister produces from on-disk JSON, exercising collectorStateFromMap,
// toInt64 and toUint64.
func TestSetState_JSONMapRoundTrip(t *testing.T) {
	c := newCollector()
	raw := `{"tailers":{"/var/log/a.log":{"path":"/var/log/a.log","inode":99,"offset":2048,"fingerprint":"deadbeef"}}}`
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c.SetState(m) // map branch → collectorStateFromMap → toInt64/toUint64 (float64 path)
}

// TestSetState_NumericTypeBranches feeds collectorStateFromMap entries whose
// inode/offset values use every numeric Go type toInt64/toUint64 switch on
// (float64, int, int64, uint64, json.Number), plus a non-numeric that both
// coercers reject (entry kept with zero inode/offset).
func TestSetState_NumericTypeBranches(t *testing.T) {
	c := newCollector()
	c.SetState(map[string]interface{}{
		"tailers": map[string]interface{}{
			"/f64.log":  map[string]interface{}{"inode": float64(1), "offset": float64(2)},
			"/int.log":  map[string]interface{}{"inode": int(3), "offset": int(4)},
			"/i64.log":  map[string]interface{}{"inode": int64(5), "offset": int64(6)},
			"/u64.log":  map[string]interface{}{"inode": uint64(7), "offset": uint64(8)},
			"/jnum.log": map[string]interface{}{"inode": json.Number("9"), "offset": json.Number("10")},
			"/bad.log":  map[string]interface{}{"inode": "x", "offset": true},
		},
	})
}

func TestSetState_MalformedMaps(t *testing.T) {
	c := newCollector()

	// 'tailers' present but not an object → collectorStateFromMap returns error
	// → SetState logs + ignores (must not panic).
	c.SetState(map[string]interface{}{"tailers": "oops"})

	// No 'tailers' key → collectorStateFromMap returns empty state, no error.
	c.SetState(map[string]interface{}{"other": 1})

	// 'tailers' object with a non-object entry (skipped) and a well-formed one.
	c.SetState(map[string]interface{}{
		"tailers": map[string]interface{}{
			"/skip.log": "not-an-object",
			"/ok.log": map[string]interface{}{
				"inode":       float64(5),
				"offset":      float64(10),
				"fingerprint": "fp",
			},
		},
	})
}
