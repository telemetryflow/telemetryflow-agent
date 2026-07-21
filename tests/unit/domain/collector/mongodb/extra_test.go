// Package mongodb_test contains unit tests for the corresponding collector module.
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
package mongodb_test

import (
	"reflect"
	"testing"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestComputeRates(t *testing.T) {
	prev := map[string]float64{
		"db.mongodb.asserts.regular":  10,
		"db.mongodb.network.bytes_in": 100,
	}
	metrics := mongodb.ComputeRatesExported(prev, 5.0, map[string]string{"db.instance": "x"})
	// Current implementation emits no metrics but iterates over counters.
	if metrics != nil {
		t.Errorf("expected nil metrics, got %d", len(metrics))
	}
}

func TestNormalizeQuery_NestedAndArray(t *testing.T) {
	in := map[string]interface{}{
		"filter": map[string]interface{}{"age": map[string]interface{}{"$gt": 30}},
		"tags":   []interface{}{"a", "b", "c"},
		"flag":   true,
		"empty":  nil,
	}
	got := mongodb.NormalizeQuery(in)

	nested, ok := got["filter"].(map[string]interface{})
	if !ok {
		t.Fatalf("filter not normalized to map: %v", got["filter"])
	}
	inner, ok := nested["age"].(map[string]interface{})
	if !ok || inner["$gt"] != "?" {
		t.Errorf("nested normalize failed: %v", nested)
	}

	arr, ok := got["tags"].([]interface{})
	if !ok || !reflect.DeepEqual(arr, []interface{}{"?", "?", "?"}) {
		t.Errorf("array normalize failed: %v", got["tags"])
	}
	if got["flag"] != "?" || got["empty"] != "?" {
		t.Errorf("scalar/nil normalize failed: %v", got)
	}
}

func TestFingerprintQuery_ArrayAndNestedCanonical(t *testing.T) {
	q := map[string]interface{}{
		"in":     []interface{}{1, 2, 3},
		"nested": map[string]interface{}{"x": "y"},
	}
	fp1 := mongodb.FingerprintQuery(q)
	fp2 := mongodb.FingerprintQuery(map[string]interface{}{
		"nested": map[string]interface{}{"x": "z"},
		"in":     []interface{}{9, 8, 7},
	})
	// Same shape (values normalized) -> same fingerprint.
	if fp1 != fp2 {
		t.Errorf("expected same fingerprint for same shape, got %q vs %q", fp1, fp2)
	}
	if fp1 == "" {
		t.Error("empty fingerprint")
	}
}

func TestAdvanceBackoff(t *testing.T) {
	seq := mongodb.AdvanceBackoffExported(9)
	if seq[0] != 1 {
		t.Errorf("first backoff = %v, want 1s", seq[0])
	}
	if seq[1] != 2 || seq[2] != 4 {
		t.Errorf("exponential backoff wrong: %v", seq)
	}
	// Capped at 60s.
	if seq[len(seq)-1] != 60 {
		t.Errorf("backoff not capped at 60s: %v", seq[len(seq)-1])
	}
}

func TestCloseConnectionNil(t *testing.T) {
	mongodb.CloseConnectionNilExported() // must not panic
	mongodb.DetectTopologyNilExported()  // must not panic
}

func TestQANInstanceLabels(t *testing.T) {
	labels := mongodb.QANInstanceLabelsExported("inst-9", map[string]string{"team": "obs"})
	if labels["mongodb_instance"] != "inst-9" {
		t.Errorf("mongodb_instance = %q", labels["mongodb_instance"])
	}
	if labels["db_system"] != "mongodb" {
		t.Errorf("db_system = %q", labels["db_system"])
	}
	if labels["team"] != "obs" {
		t.Errorf("team label = %q", labels["team"])
	}
}

func TestNewQANMongoDBCollector_NilLogger(t *testing.T) {
	// nil logger should trigger the internal fallback logger path.
	c := mongodb.NewQANMongoDBCollector(mongodb.QANMongoDBConfig{}, nil)
	if c == nil {
		t.Fatal("expected non-nil collector")
	}
	if c.Name() != "qan-mongodb-profiler" {
		t.Errorf("Name() = %q", c.Name())
	}
}
