// Package postgresql implements the PostgreSQL database monitoring collector.
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

package postgresql

import (
	"context"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// OTLPEmitter wraps an OTLPMetricBridge to push PostgreSQL collector metrics
// to the TelemetryFlow platform. It adds db.postgresql.* resource attributes
// so the backend can route and identify the metric source.
type OTLPEmitter struct {
	bridge *exporter.OTLPMetricBridge
	logger *zap.Logger
}

// NewOTLPEmitter creates an OTLP emitter using the provided bridge.
func NewOTLPEmitter(bridge *exporter.OTLPMetricBridge, logger *zap.Logger) *OTLPEmitter {
	return &OTLPEmitter{
		bridge: bridge,
		logger: logger.Named("postgresql.otlp"),
	}
}

// EmitMetrics converts a slice of collector metrics to OTLP and exports them,
// adding per-instance resource attributes extracted from the metric labels.
//
// Resource attributes added per request:
//   - service.name  = "postgresql"
//   - db.system     = "postgresql"
//   - db.instance.id = instance name from labels
//   - net.host.name  = host from labels
//   - net.host.port  = port (from pgInstance config)
func (e *OTLPEmitter) EmitMetrics(ctx context.Context, metrics []collector.Metric) error {
	if len(metrics) == 0 || e.bridge == nil {
		return nil
	}

	// Build resource attributes from the first metric's labels. All metrics
	// in a batch from a single instance share the same labels.
	resourceAttrs := resourceAttrsFromMetric(metrics[0])

	if err := e.bridge.Export(ctx, metrics, resourceAttrs); err != nil {
		return fmt.Errorf("postgresql otlp emit: %w", err)
	}

	e.logger.Debug("Emitted metrics via OTLP",
		zap.Int("count", len(metrics)),
	)
	return nil
}

// EmitMetricsForInstance is like EmitMetrics but uses the instance config to
// build resource attributes, avoiding reliance on label presence.
func (e *OTLPEmitter) EmitMetricsForInstance(ctx context.Context, metrics []collector.Metric, inst *pgInstance) error {
	if len(metrics) == 0 || e.bridge == nil {
		return nil
	}

	resourceAttrs := resourceAttrsFromInstance(inst)

	if err := e.bridge.Export(ctx, metrics, resourceAttrs); err != nil {
		return fmt.Errorf("postgresql otlp emit %s: %w", inst.config.Name, err)
	}

	e.logger.Debug("Emitted metrics via OTLP",
		zap.String("instance", inst.config.Name),
		zap.Int("count", len(metrics)),
	)
	return nil
}

// Shutdown closes the underlying OTLP bridge.
func (e *OTLPEmitter) Shutdown(ctx context.Context) error {
	if e.bridge != nil {
		return e.bridge.Shutdown(ctx)
	}
	return nil
}

// resourceAttrsFromMetric extracts OTLP resource attributes from metric labels.
func resourceAttrsFromMetric(m collector.Metric) map[string]string {
	attrs := map[string]string{
		"service.name":   "postgresql",
		"db.system":      "postgresql",
		"db.instance.id": m.Labels["postgresql_instance"],
		"net.host.name":  m.Labels["postgresql_host"],
	}
	if v, ok := m.Labels["postgresql_version"]; ok {
		attrs["db.postgresql.version"] = v
	}
	return attrs
}

// resourceAttrsFromInstance builds OTLP resource attributes from pgInstance config.
func resourceAttrsFromInstance(inst *pgInstance) map[string]string {
	attrs := map[string]string{
		"service.name":   "postgresql",
		"db.system":      "postgresql",
		"db.instance.id": inst.config.Name,
		"net.host.name":  inst.config.Host,
		"net.host.port":  strconv.Itoa(inst.config.Port),
	}
	if inst.versionStr != "" {
		attrs["db.postgresql.version"] = inst.versionStr
	}
	if inst.config.DBName != "" {
		attrs["db.name"] = inst.config.DBName
	}
	return attrs
}
