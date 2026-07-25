// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// ApacheCollectorConfig configures the Apache HTTPD server-status collector.
type ApacheCollectorConfig struct {
	Enabled   bool             `mapstructure:"enabled"`
	Interval  time.Duration    `mapstructure:"interval"`
	Instances []ApacheInstance `mapstructure:"instances"`
}

// ApacheInstance is a single Apache server-status endpoint to scrape.
type ApacheInstance struct {
	Name          string        `mapstructure:"name"`
	URL           string        `mapstructure:"url"` // e.g. http://apache/server-status?auto
	Timeout       time.Duration `mapstructure:"timeout"`
	TLSEnabled    bool          `mapstructure:"tls_enabled"`
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify"`
	Username      string        `mapstructure:"username"`
	Password      string        `mapstructure:"password"`
}
