// Package config defines the PgBouncer connection-pooler collector configuration.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// PgBouncerCollectorConfig configures the PgBouncer collector.
type PgBouncerCollectorConfig struct {
	Enabled   bool                `mapstructure:"enabled"`
	Interval  time.Duration       `mapstructure:"interval"`
	Instances []PgBouncerInstance `mapstructure:"instances"`
	Tags      map[string]string   `mapstructure:"tags"`
}

// PgBouncerInstance is a single PgBouncer admin endpoint to monitor.
type PgBouncerInstance struct {
	Name     string            `mapstructure:"name"`
	Host     string            `mapstructure:"host"`
	Port     int               `mapstructure:"port"`     // default 6432
	Database string            `mapstructure:"database"` // usually "pgbouncer"
	User     string            `mapstructure:"user"`
	Password string            `mapstructure:"password"`
	SSLMode  string            `mapstructure:"ssl_mode"` // disable, require, verify-ca, verify-full
	Timeout  time.Duration     `mapstructure:"timeout"`
	Tags     map[string]string `mapstructure:"tags"`
}
