// Package config contains the InternalStatsCollectorConfig type declared
// separately from the main config.go so it can be merged centrally.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// InternalStatsCollectorConfig configures the selfstat emitter collector.
// When Enabled, the agent periodically snapshots internal selfstat counters
// (plugin metrics, agent metrics, collector metrics, exporter metrics) into
// the normal metric pipeline under the `internal` collector name.
type InternalStatsCollectorConfig struct {
	// Enabled gates the collector. Defaults to false (off).
	Enabled bool `mapstructure:"enabled"`

	// Interval is the collection cadence. Defaults to 30s when zero.
	Interval time.Duration `mapstructure:"interval"`
}
