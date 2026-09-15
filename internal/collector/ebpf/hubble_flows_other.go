//go:build !linux

// Package ebpf — Hubble network-flow subscriber (non-Linux stub).
//
// Cilium Hubble integration requires Linux. On other platforms the subscriber
// is a no-op so the agent still compiles and the feature flag simply has no
// effect.
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

import (
	"context"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// NetworkFlowCallback receives batches of mapped network-flow records.
type NetworkFlowCallback func([]exporter.NetworkFlowRecord)

// NetworkFlowSubscriber is a no-op on non-Linux platforms.
type NetworkFlowSubscriber struct {
	logger *zap.Logger
}

// NewNetworkFlowSubscriber returns a no-op subscriber on non-Linux platforms.
func NewNetworkFlowSubscriber(_ config.CiliumCollectorConfig, _ NetworkFlowCallback, logger *zap.Logger) *NetworkFlowSubscriber {
	return &NetworkFlowSubscriber{logger: logger.With(zap.String("component", "hubble-flows"))}
}

// Run is a no-op that returns as soon as the context is cancelled.
func (s *NetworkFlowSubscriber) Run(ctx context.Context) {
	s.logger.Debug("Hubble flow subscription is unsupported on this platform (Linux only)")
	<-ctx.Done()
}
