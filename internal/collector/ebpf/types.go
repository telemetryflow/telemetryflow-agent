//go:build linux

// Package ebpf implements a kernel-level metrics collector using eBPF programs
// attached to tracepoints and kprobes. It captures syscall counts, TCP/UDP
// connections, file I/O, scheduler events, memory page faults, and — optionally
// — Cilium Hubble network-flow data. On non-Linux platforms the collector is a
// no-op stub.
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
package ebpf

// Go equivalents of BPF map key/value structs from bpf/headers/common.h.
// These must match the C struct layout exactly (field sizes, alignment).
//
// When bpf2go is available (Phase 3, Linux CI), these are auto-generated.
// For cross-platform compilation, we define them manually here.

const taskCommLen = 16

// syscallKey is the key for per-process + syscall aggregation.
type syscallKey struct {
	PID       uint32
	SyscallNr uint32
}

// syscallVal is the value for syscall statistics.
type syscallVal struct {
	Count   uint64
	TotalNs uint64
	Errors  uint64
	Comm    [taskCommLen]byte
}

// netKey is the key for per-process network aggregation.
type netKey struct {
	PID uint32
}

// tcpVal is the value for TCP connection statistics.
type tcpVal struct {
	Connections uint64
	BytesSent   uint64
	BytesRecv   uint64
	RttNs       uint64
	Retransmits uint64
	Comm        [taskCommLen]byte
}

// udpVal is the value for UDP packet statistics.
type udpVal struct {
	PacketsSent uint64
	PacketsRecv uint64
	Comm        [taskCommLen]byte
}

// fileioKey is the key for file I/O aggregation (pid + operation).
type fileioKey struct {
	PID       uint32
	Operation uint32 // 0=read, 1=write, 2=open
}

// fileioVal is the value for file I/O statistics.
type fileioVal struct {
	Count   uint64
	Bytes   uint64
	TotalNs uint64
	Comm    [taskCommLen]byte
}

// schedKey is the key for scheduler aggregation.
type schedKey struct {
	PID uint32
}

// schedVal is the value for scheduler statistics.
type schedVal struct {
	ContextSwitches uint64
	RunqLatencyNs   uint64
	OncpuNs         uint64
	Migrations      uint64
	Comm            [taskCommLen]byte
}

// memKey is the key for memory aggregation.
type memKey struct {
	PID uint32
}

// memVal is the value for memory statistics.
type memVal struct {
	PageFaults  uint64
	MajorFaults uint64
	MinorFaults uint64
	Comm        [taskCommLen]byte
}

// tcpstateKey is the key for TCP state transitions.
type tcpstateKey struct {
	PID      uint32
	OldState uint32
	NewState uint32
}

// tcpstateVal is the value for TCP state transition counts.
type tcpstateVal struct {
	Count uint64
}

// commToString converts a fixed-size comm byte array to a Go string.
func commToString(comm [taskCommLen]byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm[:])
}

// fileioOperationName returns the human-readable name for a file I/O operation.
func fileioOperationName(op uint32) string {
	switch op {
	case 0:
		return "read"
	case 1:
		return "write"
	case 2:
		return "open"
	default:
		return "unknown"
	}
}
