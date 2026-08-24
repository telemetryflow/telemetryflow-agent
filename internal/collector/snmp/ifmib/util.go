// Package ifmib implements a TelemetryFlow Agent collector that polls IF-MIB
// interface counters (RFC 2863) from SNMP-managed network devices, computes
// per-interface bandwidth utilization from consecutive counter deltas, and
// pushes the resulting samples to the TFO Platform network-map ingestion
// endpoint.
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
package ifmib

const (
	// maxUint32 is the wrap modulus for 32-bit IF-MIB counters
	// (ifInOctets / ifOutOctets, Counter32).
	maxUint32 = uint64(1) << 32
)

// CounterDelta returns the number of units that a monotonically-increasing SNMP
// counter advanced between two consecutive polls, correctly accounting for
// counter wrap-around.
//
//   - 64-bit counters (ifHCInOctets / ifHCOutOctets, Counter64): unsigned
//     subtraction in Go is already modulo 2^64, so cur-prev yields the correct
//     delta even when the raw value wrapped past 2^64 (cur < prev).
//   - 32-bit counters (ifInOctets / ifOutOctets, Counter32): the raw value is
//     held in the low 32 bits of a uint64, so a wrap is corrected by masking the
//     modular difference back down to 32 bits.
//
// A counter reset (e.g. device reboot / ifCounterDiscontinuity) is
// indistinguishable from a wrap at this layer and is treated as a wrap, which
// is the conventional behaviour for interface-utilization math. Callers that
// need reset detection should compare ifCounterDiscontinuityTime separately.
func CounterDelta(prev, cur uint64, is64bit bool) uint64 {
	delta := cur - prev // modulo 2^64
	if !is64bit {
		delta &= maxUint32 - 1 // mask to low 32 bits -> modulo 2^32
	}
	return delta
}

// Utilization computes interface bandwidth utilization as a percentage of link
// speed over a polling interval, from a pair of consecutive octet counters.
//
//	util = (deltaOctets * 8) / (intervalSeconds * ifSpeedBps) * 100
//
// It handles both 32-bit and 64-bit counter wrap via CounterDelta and clamps
// the result to the inclusive range [0, 100]. It returns 0 (rather than a
// spurious spike or a divide-by-zero) whenever the sample is not meaningful:
//   - hasPrevious is false (the first poll for this interface has no delta), or
//   - intervalSeconds <= 0, or
//   - ifSpeedBps == 0 (unknown / administratively-unset link speed).
func Utilization(prev, cur uint64, is64bit, hasPrevious bool, intervalSeconds float64, ifSpeedBps uint64) float64 {
	if !hasPrevious || intervalSeconds <= 0 || ifSpeedBps == 0 {
		return 0
	}
	delta := CounterDelta(prev, cur, is64bit)
	bitsPerSecondCapacity := intervalSeconds * float64(ifSpeedBps)
	util := (float64(delta) * 8.0) / bitsPerSecondCapacity * 100.0
	return clamp(util, 0, 100)
}

// clamp constrains v to the inclusive range [lo, hi].
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
