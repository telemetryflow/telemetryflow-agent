// Table-driven unit tests for the IF-MIB counter-wrap and utilization math.
// These MUST pass without a live SNMP device.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package ifmib_test

import (
	"math"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/snmp/ifmib"
)

func TestCounterDelta(t *testing.T) {
	tests := []struct {
		name    string
		prev    uint64
		cur     uint64
		is64bit bool
		want    uint64
	}{
		{"32bit no wrap", 100, 500, false, 400},
		{"32bit zero delta", 42, 42, false, 0},
		{"32bit exact wrap", math.MaxUint32, 0, false, 1},
		{"32bit wrap with remainder", math.MaxUint32 - 10, 20, false, 31},
		{"32bit near-full to small", 4_000_000_000, 100, false, (uint64(1) << 32) - 4_000_000_000 + 100},
		{"64bit no wrap", 1_000_000_000_000, 1_000_000_050_000, true, 50_000},
		{"64bit zero delta", 9_999, 9_999, true, 0},
		{"64bit exact wrap", math.MaxUint64, 0, true, 1},
		{"64bit wrap with remainder", math.MaxUint64 - 5, 4, true, 10},
		{"64bit large value no wrap", 18_000_000_000_000_000_000, 18_000_000_000_000_001_000, true, 1_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ifmib.CounterDelta(tt.prev, tt.cur, tt.is64bit)
			if got != tt.want {
				t.Fatalf("CounterDelta(%d, %d, %v) = %d, want %d", tt.prev, tt.cur, tt.is64bit, got, tt.want)
			}
		})
	}
}

func TestUtilization(t *testing.T) {
	const gigabit = uint64(1_000_000_000) // 1 Gbps in bps

	tests := []struct {
		name        string
		prev, cur   uint64
		is64bit     bool
		hasPrevious bool
		interval    float64 // seconds
		speedBps    uint64
		want        float64
	}{
		{
			// 62.5 MB over 60s on a 1 Gbps link:
			// (62_500_000 * 8) / (60 * 1e9) * 100 = 500_000_000 / 60_000_000_000 * 100 = 0.8333%
			name: "typical low utilization", prev: 0, cur: 62_500_000, is64bit: true,
			hasPrevious: true, interval: 60, speedBps: gigabit, want: 0.8333333333,
		},
		{
			// 7.5 GB over 60s on 1 Gbps: exactly 100% saturation.
			// deltaBits = 7_500_000_000 * 8 = 60e9; capacity = 60 * 1e9 = 60e9 -> 100%
			name: "full saturation", prev: 0, cur: 7_500_000_000, is64bit: true,
			hasPrevious: true, interval: 60, speedBps: gigabit, want: 100,
		},
		{
			// delta exceeds link capacity -> clamped to 100 (e.g. speed misreport)
			name: "over capacity clamps to 100", prev: 0, cur: 20_000_000_000, is64bit: true,
			hasPrevious: true, interval: 60, speedBps: gigabit, want: 100,
		},
		{
			name: "first sample has no previous", prev: 0, cur: 1_000_000_000, is64bit: true,
			hasPrevious: false, interval: 60, speedBps: gigabit, want: 0,
		},
		{
			name: "zero speed guards divide by zero", prev: 0, cur: 1_000_000, is64bit: true,
			hasPrevious: true, interval: 60, speedBps: 0, want: 0,
		},
		{
			name: "non-positive interval returns zero", prev: 0, cur: 1_000_000, is64bit: true,
			hasPrevious: true, interval: 0, speedBps: gigabit, want: 0,
		},
		{
			// 32-bit wrap: prev near max, cur small. delta = 2^32 - prev + cur bytes.
			// prev=4_294_967_196 (2^32-100), cur=900 -> delta=1000 bytes over 1s on 1Gbps.
			// (1000*8)/(1*1e9)*100 = 0.0008%
			name: "32bit wrap yields small positive util", prev: math.MaxUint32 - 99, cur: 900, is64bit: false,
			hasPrevious: true, interval: 1, speedBps: gigabit, want: 0.0008,
		},
		{
			// half utilization: 6.25 MB/s * 8 = 50 Mbps on 100 Mbps link = 50%
			name: "half utilization 100Mbps link", prev: 1_000_000, cur: 1_000_000 + 6_250_000, is64bit: true,
			hasPrevious: true, interval: 1, speedBps: 100_000_000, want: 50,
		},
	}

	const eps = 1e-6
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ifmib.Utilization(tt.prev, tt.cur, tt.is64bit, tt.hasPrevious, tt.interval, tt.speedBps)
			if math.Abs(got-tt.want) > eps {
				t.Fatalf("Utilization() = %.10f, want %.10f (diff %.10g)", got, tt.want, math.Abs(got-tt.want))
			}
			if got < 0 || got > 100 {
				t.Fatalf("Utilization() = %.6f out of clamp range [0,100]", got)
			}
		})
	}
}
