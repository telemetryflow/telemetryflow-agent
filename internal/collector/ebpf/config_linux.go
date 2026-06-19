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

// shouldIncludeProcess returns true if a process name should be traced.
func (cc *collectorConfig) shouldIncludeProcess(comm string) bool {
	for _, re := range cc.excludeProcessRe {
		if re.MatchString(comm) {
			return false
		}
	}
	if len(cc.processFilterRe) == 0 {
		return true
	}
	for _, re := range cc.processFilterRe {
		if re.MatchString(comm) {
			return true
		}
	}
	return false
}
