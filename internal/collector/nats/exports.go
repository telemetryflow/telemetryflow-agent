// Package nats exposes unexported symbols for external test packages.
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
//
// This file contains forwarding-only wrappers. It introduces no runtime
// behavior changes; it merely re-exports unexported symbols so that the
// external nats_test package can exercise them.

package nats

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// MonitorClientExported is a test-visible handle to the internal monitorClient.
type MonitorClientExported struct {
	inner *monitorClient
}

// NewMonitorClientExported constructs a monitorClient for an instance.
func NewMonitorClientExported(inst config.NATSInstanceConfig) *MonitorClientExported {
	return &MonitorClientExported{inner: newMonitorClient(inst)}
}

// BaseURL returns the configured base URL of the underlying client.
func (m *MonitorClientExported) BaseURL() string { return m.inner.baseURL }

// GetJSON forwards to the internal getJSON method.
func (m *MonitorClientExported) GetJSON(ctx context.Context, path string, target any) error {
	return m.inner.getJSON(ctx, path, target)
}

// CollectInstanceExported forwards to the internal collectInstance method.
func (c *NATSCollector) CollectInstanceExported(ctx context.Context, inst config.NATSInstanceConfig) ([]collector.Metric, error) {
	return c.collectInstance(ctx, inst)
}

// InstanceLabelsExported forwards to the internal instanceLabels method.
func (c *NATSCollector) InstanceLabelsExported(inst config.NATSInstanceConfig) map[string]string {
	return c.instanceLabels(inst)
}
