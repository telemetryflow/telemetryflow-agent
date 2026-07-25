// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// SQLGenericCollectorConfig configures the generic SQL collector (M4), which
// runs user-defined SQL queries against any database/sql driver and emits one
// metric per result row.
type SQLGenericCollectorConfig struct {
	Enabled   bool                 `mapstructure:"enabled"`
	Interval  time.Duration        `mapstructure:"interval"`
	Instances []SQLGenericInstance `mapstructure:"instances"`
}

// SQLGenericInstance configures a single database connection and the set of
// queries to run against it.
type SQLGenericInstance struct {
	Name    string        `mapstructure:"name"`
	Driver  string        `mapstructure:"driver"` // postgres, mysql, sqlite3, sqlserver, etc.
	DSN     string        `mapstructure:"dsn"`
	Timeout time.Duration `mapstructure:"timeout"`
	Queries []SQLQuery    `mapstructure:"queries"`
}

// SQLQuery defines a single metric-producing SQL query. Each row in the result
// set becomes one metric whose value comes from ValueColumn and whose labels
// come from LabelColumns.
type SQLQuery struct {
	Metric       string   `mapstructure:"metric"`        // e.g. "billing.active_subscriptions"
	Type         string   `mapstructure:"type"`          // gauge (default) | counter
	SQL          string   `mapstructure:"sql"`           // returns one row per emitted metric
	ValueColumn  string   `mapstructure:"value_column"`  // column holding the numeric value
	LabelColumns []string `mapstructure:"label_columns"` // columns to use as labels
	Unit         string   `mapstructure:"unit,omitempty"`
}
