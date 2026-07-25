// Package config defines the SyslogListenerConfig type declared separately
// from the main config.go so it can be merged centrally by the integrator.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// SyslogListenerConfig configures the syslog receiver collector.
type SyslogListenerConfig struct {
	Enabled       bool             `mapstructure:"enabled"`
	Listeners     []SyslogListener `mapstructure:"listeners"`
	DefaultFormat string           `mapstructure:"default_format"` // "rfc3164" (default) | "rfc5424" | "cisco"
	Timezone      string           `mapstructure:"timezone"`       // default "UTC"
	FlushInterval time.Duration    `mapstructure:"flush_interval"` // default 30s
}

// SyslogListener is a single bind address for the syslog receiver.
type SyslogListener struct {
	Protocol string `mapstructure:"protocol"` // "udp" (default), "tcp", "unix"
	Address  string `mapstructure:"address"`  // default "0.0.0.0"
	Port     int    `mapstructure:"port"`     // required (514 for UDP, 601 for TCP per RFC 3195)
	Format   string `mapstructure:"format"`   // override DefaultFormat for this listener
}
