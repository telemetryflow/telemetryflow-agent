// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestNormalizeQuery(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		want  map[string]interface{}
	}{
		{
			name:  "simple literals",
			input: map[string]interface{}{"name": "John", "age": int32(30)},
			want:  map[string]interface{}{"name": "?", "age": "?"},
		},
		{
			name:  "nested document",
			input: map[string]interface{}{"name": "John", "age": map[string]interface{}{"$gt": int64(30)}},
			want:  map[string]interface{}{"name": "?", "age": map[string]interface{}{"$gt": "?"}},
		},
		{
			name:  "array values",
			input: map[string]interface{}{"tags": []interface{}{"a", "b"}},
			want:  map[string]interface{}{"tags": []interface{}{"?", "?"}},
		},
		{
			name:  "nil value",
			input: map[string]interface{}{"field": nil},
			want:  map[string]interface{}{"field": "?"},
		},
		{
			name:  "boolean value",
			input: map[string]interface{}{"active": true},
			want:  map[string]interface{}{"active": "?"},
		},
		{
			name:  "empty document",
			input: map[string]interface{}{},
			want:  map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mongodb.NormalizeQuery(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("NormalizeQuery() got %d keys, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				gotVal, ok := got[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				if v == "?" {
					if gotVal != "?" {
						t.Errorf("key %q: got %v, want ?", k, gotVal)
					}
				}
			}
		})
	}
}

func TestFingerprintQueryDeterminism(t *testing.T) {
	q1 := map[string]interface{}{"name": "Alice", "age": int32(25)}
	q2 := map[string]interface{}{"status": "active", "score": int32(90)}

	fp1a := mongodb.FingerprintQuery(q1)
	fp1b := mongodb.FingerprintQuery(q1)
	fp2 := mongodb.FingerprintQuery(q2)

	if fp1a != fp1b {
		t.Errorf("same query shape produced different fingerprints: %s vs %s", fp1a, fp1b)
	}
	if fp1a == fp2 {
		t.Error("different query shapes should produce different fingerprints, but got same")
	}
}

func TestFingerprintQueryKeyOrderIndependent(t *testing.T) {
	q1 := map[string]interface{}{"a": int32(1), "b": int32(2)}
	q2 := map[string]interface{}{"b": int32(99), "a": int32(42)}

	fp1 := mongodb.FingerprintQuery(q1)
	fp2 := mongodb.FingerprintQuery(q2)

	if fp1 != fp2 {
		t.Errorf("key order should not affect fingerprint: %s vs %s", fp1, fp2)
	}
}
