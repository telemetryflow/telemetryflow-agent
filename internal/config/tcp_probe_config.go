// Package config defines TelemetryFlow Agent configuration types.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// TCPProbeCollectorConfig configures the TCP/UDP port probe collector.
type TCPProbeCollectorConfig struct {
	Enabled  bool             `mapstructure:"enabled"`
	Interval time.Duration    `mapstructure:"interval"`
	Targets  []TCPProbeTarget `mapstructure:"targets"`
}

// TCPProbeTarget is a single probe target.
type TCPProbeTarget struct {
	Host     string        `mapstructure:"host"`
	Port     int           `mapstructure:"port"`
	Name     string        `mapstructure:"name"`
	Protocol string        `mapstructure:"protocol"` // "tcp" (default) or "udp"
	Timeout  time.Duration `mapstructure:"timeout"`  // default 5s
	Send     string        `mapstructure:"send"`     // optional bytes to send after connect (for banner grab)
	Expect   string        `mapstructure:"expect"`   // optional substring to find in response
}
