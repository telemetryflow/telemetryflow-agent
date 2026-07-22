// Package rabbitmq exposes unexported symbols for external test packages.
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
// This file is a forwarding-only shim. It adds no runtime behavior; it merely
// re-exports unexported symbols so black-box test packages can reach them.

package rabbitmq

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// PathEscapeExported forwards to the unexported pathEscape helper.
func PathEscapeExported(s string) string { return pathEscape(s) }

// WithLabelExported forwards to the unexported withLabel helper.
func WithLabelExported(base map[string]string, key, val string) map[string]string {
	return withLabel(base, key, val)
}

// InstanceLabelsExported forwards to the unexported (*RabbitMQCollector).instanceLabels.
func (c *RabbitMQCollector) InstanceLabelsExported(inst config.RabbitMQInstanceConfig) map[string]string {
	return c.instanceLabels(inst)
}

// MgmtClientExported is a test-visible handle to the unexported mgmtClient.
type MgmtClientExported struct{ inner *mgmtClient }

// NewMgmtClientExported forwards to the unexported newMgmtClient constructor.
func NewMgmtClientExported(inst config.RabbitMQInstanceConfig) (*MgmtClientExported, error) {
	mc, err := newMgmtClient(inst)
	if err != nil {
		return nil, err
	}
	return &MgmtClientExported{inner: mc}, nil
}

// BaseURL returns the resolved base URL of the underlying client.
func (m *MgmtClientExported) BaseURL() string { return m.inner.baseURL }

// GetJSON forwards to the unexported (*mgmtClient).getJSON.
func (m *MgmtClientExported) GetJSON(ctx context.Context, path string, target any) error {
	return m.inner.getJSON(ctx, path, target)
}
