// Package nginx exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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
//
// This file contains forwarding-only wrappers. It introduces no runtime
// behavior changes; it merely re-exports unexported symbols so that the
// external nginx_test package can exercise them.

package nginx

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// CollectInstanceExported forwards to the internal collectInstance method.
func (c *NginxCollector) CollectInstanceExported(ctx context.Context, inst config.NginxInstance) []collector.Metric {
	return c.collectInstance(ctx, inst)
}

// InstanceLabelsExported forwards to the package-level instanceLabels helper.
func InstanceLabelsExported(inst config.NginxInstance) map[string]string {
	return instanceLabels(inst)
}

// ParseStubStatusExported forwards to the package-level parseStubStatus helper.
func ParseStubStatusExported(body string) (StubStatsExported, bool) {
	s, ok := parseStubStatus(body)
	return StubStatsExported{
		Active:   s.active,
		Accepts:  s.accepts,
		Handled:  s.handled,
		Requests: s.requests,
		Reading:  s.reading,
		Writing:  s.writing,
		Waiting:  s.waiting,
	}, ok
}

// StubStatsExported is the exported mirror of the unexported stubStats struct.
type StubStatsExported struct {
	Active   int64
	Accepts  int64
	Handled  int64
	Requests int64
	Reading  int64
	Writing  int64
	Waiting  int64
}

// SplitHostPortExported forwards to the package-level splitHostPort helper.
func SplitHostPortExported(rawURL string) (host, port string) {
	return splitHostPort(rawURL)
}
