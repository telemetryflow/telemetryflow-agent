// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// HAProxyCollectorConfig configures the HAProxy stats CSV scraper collector.
type HAProxyCollectorConfig struct {
	Enabled   bool              `mapstructure:"enabled"`
	Interval  time.Duration     `mapstructure:"interval"`
	Instances []HAProxyInstance `mapstructure:"instances"`
}

// HAProxyInstance is a single HAProxy stats endpoint to monitor.
type HAProxyInstance struct {
	Name          string        `mapstructure:"name"`
	URL           string        `mapstructure:"url"` // e.g. http://haproxy/stats;csv
	Username      string        `mapstructure:"username"`
	Password      string        `mapstructure:"password"`
	Timeout       time.Duration `mapstructure:"timeout"`
	TLSEnabled    bool          `mapstructure:"tls_enabled"`
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify"`
}
