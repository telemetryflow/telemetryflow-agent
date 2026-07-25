// Package config contains the PingCollectorConfig type declared separately
// from the main config.go so it can be merged centrally by the integrator.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// PingCollectorConfig configures the ICMP ping probe collector.
type PingCollectorConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
	Targets  []PingTarget  `mapstructure:"targets"`
	// Count is the number of echo requests per probe cycle (default 5).
	Count int `mapstructure:"count"`
	// Timeout is the per-target probe timeout (default 5s).
	Timeout time.Duration `mapstructure:"timeout"`
	// IntervalBetween is the wait between successive packets (default 1s).
	IntervalBetween time.Duration `mapstructure:"interval_between"`
	// Privileged selects raw-socket mode (true, requires root/CAP_NET_RAW)
	// vs. unprivileged UDP-mode ICMP (false, requires
	// `net.ipv4.ping_group_range` on Linux). Defaults to false.
	Privileged bool `mapstructure:"privileged"`
}

// PingTarget is a single ping target.
type PingTarget struct {
	// Host is the target IP address or hostname.
	Host string `mapstructure:"host"`
	// Name is an optional human-friendly label emitted as the `target` label.
	// When empty, Host is used.
	Name string `mapstructure:"name"`
}
