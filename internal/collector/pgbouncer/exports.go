// Package pgbouncer exposes unexported symbols for external test packages.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package pgbouncer

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// SetConnectorFactoryExported overrides the package-level ConnectorFactory used
// by Collect(). Tests inject a fake factory that returns canned rows or a
// connection error without touching the network. Call with nil to restore the
// default pgx-backed factory.
func SetConnectorFactoryExported(fn ConnectorFactory) {
	if fn == nil {
		connectorFactory = pgxConnector
		return
	}
	connectorFactory = fn
}

// CollectStatsExported drives collectStats against the supplied querier so the
// SHOW STATS row-scan path can be exercised from external tests.
func CollectStatsExported(ctx context.Context, q Querier, labels map[string]string) ([]collector.Metric, error) {
	return collectStats(ctx, q, labels)
}

// CollectPoolsExported drives collectPools against the supplied querier so the
// SHOW POOLS row-scan path can be exercised from external tests.
func CollectPoolsExported(ctx context.Context, q Querier, labels map[string]string) ([]collector.Metric, error) {
	return collectPools(ctx, q, labels)
}

// InstanceLabelsExported exposes instanceLabels for tests.
func InstanceLabelsExported(cfg config.PgBouncerCollectorConfig, inst config.PgBouncerInstance) map[string]string {
	return instanceLabels(cfg, inst)
}

// WithRowLabelsExported exposes withRowLabels for tests.
func WithRowLabelsExported(base map[string]string, database, user string) map[string]string {
	return withRowLabels(base, database, user)
}

// ApplyInstanceDefaultsExported exposes applyInstanceDefaults for tests.
func ApplyInstanceDefaultsExported(inst *config.PgBouncerInstance) { applyInstanceDefaults(inst) }
