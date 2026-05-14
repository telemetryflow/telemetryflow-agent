// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestAsInt(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  int32
	}{
		{"int32", int32(42), 42},
		{"int64", int64(100), 100},
		{"float64", float64(3.14), 3},
		{"nil", nil, 0},
		{"string", "hello", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mongodb.AsIntExported(tt.input); got != tt.want {
				t.Errorf("asInt(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestAsInt64(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  int64
	}{
		{"int32", int32(42), 42},
		{"int64", int64(100), 100},
		{"float64", float64(3.14), 3},
		{"nil", nil, 0},
		{"string", "hello", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mongodb.AsInt64Exported(tt.input); got != tt.want {
				t.Errorf("asInt64(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestAsFloat(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  float64
	}{
		{"int32", int32(42), 42.0},
		{"int64", int64(100), 100.0},
		{"float64", float64(3.14), 3.14},
		{"nil", nil, 0.0},
		{"string", "hello", 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mongodb.AsFloatExported(tt.input); got != tt.want {
				t.Errorf("asFloat(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAsString(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{"string", "hello", "hello"},
		{"int", int32(42), ""},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mongodb.AsStringExported(tt.input); got != tt.want {
				t.Errorf("asString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		num, denom, want float64
	}{
		{10, 5, 2.0},
		{3, 0, 0},
		{0, 5, 0},
		{7, 10, 0.7},
	}
	for _, tt := range tests {
		got := mongodb.SafeDivExported(tt.num, tt.denom)
		if got != tt.want {
			t.Errorf("safeDiv(%v, %v) = %v, want %v", tt.num, tt.denom, got, tt.want)
		}
	}
}
