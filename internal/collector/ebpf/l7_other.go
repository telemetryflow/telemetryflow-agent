//go:build !linux

// TelemetryFlow Agent - eBPF L7 RED collector (non-Linux stub)
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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

// collectL7 returns empty metrics on non-Linux platforms.
func (c *EBPFCollector) collectL7(_ context.Context) ([]collector.Metric, error) {
	return nil, nil
}
