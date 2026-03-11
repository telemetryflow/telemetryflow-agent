//go:build !linux

// Package ebpf implements a kernel-level metrics collector using eBPF programs
// attached to tracepoints and kprobes. It captures syscall counts, TCP/UDP
// connections, file I/O, scheduler events, memory page faults, and — optionally
// — Cilium Hubble network-flow data. On non-Linux platforms the collector is a
// no-op stub.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
package ebpf

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// loadPrograms is a no-op on non-Linux platforms.
func (c *EBPFCollector) loadPrograms() error {
	return nil
}

// closePrograms is a no-op on non-Linux platforms.
func (c *EBPFCollector) closePrograms() {}

// collectAll returns nil on non-Linux platforms.
func (c *EBPFCollector) collectAll(_ context.Context) []collector.Metric {
	return nil
}
