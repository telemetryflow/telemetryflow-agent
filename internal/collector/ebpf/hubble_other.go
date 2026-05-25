//go:build !linux

// Package ebpf implements a kernel-level metrics collector using eBPF programs
// attached to tracepoints and kprobes. It captures syscall counts, TCP/UDP
// connections, file I/O, scheduler events, memory page faults, and — optionally
// — Cilium Hubble network-flow data. On non-Linux platforms the collector is a
// no-op stub.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// hubbleClient is a stub on non-Linux platforms.
// Hubble/Cilium integration requires Linux kernel eBPF support.
type hubbleClient struct {
	cfg    config.CiliumCollectorConfig
	logger *zap.Logger
}

func newHubbleClient(cfg config.CiliumCollectorConfig, logger *zap.Logger) *hubbleClient {
	return &hubbleClient{cfg: cfg, logger: logger}
}

func (h *hubbleClient) connect(_ context.Context) error { return nil }
func (h *hubbleClient) close()                          {}
