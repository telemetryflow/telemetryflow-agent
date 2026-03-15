// Package log implements file-based and journald log collection for TFO-Agent.
//
// journald_stub provides a no-op JournaldCollector for non-Linux platforms
// where systemd journal is not available.
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

//go:build !linux

package log

import (
	"context"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// JournaldCollector is a no-op stub on non-Linux platforms.
type JournaldCollector struct{}

// LogEntry is a structured log line (stub definition for non-Linux).
type LogEntry struct {
	Unit     string
	Priority string
	Message  string
}

// NewJournaldCollector returns a no-op collector on non-Linux.
func NewJournaldCollector(_ config.JournaldConfig, _ *zap.Logger) *JournaldCollector {
	return &JournaldCollector{}
}

// Lines returns a nil channel (never emits).
func (j *JournaldCollector) Lines() <-chan LogEntry { return nil }

// Start is a no-op on non-Linux.
func (j *JournaldCollector) Start(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// Stop is a no-op on non-Linux.
func (j *JournaldCollector) Stop() {}
