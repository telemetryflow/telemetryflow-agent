// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// HTTPProbeCollectorConfig configures the HTTP synthetic check collector.
type HTTPProbeCollectorConfig struct {
	Enabled  bool              `mapstructure:"enabled"`
	Interval time.Duration     `mapstructure:"interval"`
	Targets  []HTTPProbeTarget `mapstructure:"targets"`
}

// HTTPProbeTarget is a single HTTP probe target.
type HTTPProbeTarget struct {
	URL               string            `mapstructure:"url"`
	Name              string            `mapstructure:"name"`
	Method            string            `mapstructure:"method"` // default GET
	Headers           map[string]string `mapstructure:"headers"`
	Body              string            `mapstructure:"body"`
	ExpectedStatus    []int             `mapstructure:"expected_status"` // default [200, 201, 204, 301, 302]
	ExpectedBodyRegex string            `mapstructure:"expected_body_regex"`
	FollowRedirects   bool              `mapstructure:"follow_redirects"` // default true (via YAML/Viper)
	Timeout           time.Duration     `mapstructure:"timeout"`          // default 10s
	TLSSkipVerify     bool              `mapstructure:"tls_skip_verify"`
	Username          string            `mapstructure:"username"` // basic auth
	Password          string            `mapstructure:"password"`
}
