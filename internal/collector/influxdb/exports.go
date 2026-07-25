// Package influxdb exposes unexported symbols for external test packages.
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
// external influxdb_test package can exercise them.

package influxdb

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ClientExported is a test-visible handle to the internal httpClient.
type ClientExported struct {
	inner *httpClient
}

// NewClientExported constructs an httpClient for an instance.
func NewClientExported(inst config.InfluxDBInstance) *ClientExported {
	return &ClientExported{inner: newClient(inst)}
}

// PingVersion forwards to the internal pingVersion method.
func (c *ClientExported) PingVersion(ctx context.Context) string {
	return c.inner.pingVersion(ctx)
}

// GetDebugVars forwards to the internal getDebugVars method.
func (c *ClientExported) GetDebugVars(ctx context.Context) ([]byte, int, error) {
	return c.inner.getDebugVars(ctx)
}

// CollectInstanceExported forwards to the internal collectInstance method.
func (c *InfluxDBCollector) CollectInstanceExported(ctx context.Context, inst config.InfluxDBInstance) []collector.Metric {
	return c.collectInstance(ctx, inst)
}
