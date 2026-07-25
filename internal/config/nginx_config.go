// Package config defines the NginxCollectorConfig type declared separately
// from the main config.go so it can be merged centrally by the integrator.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// NginxCollectorConfig configures the Nginx OSS stub_status collector.
type NginxCollectorConfig struct {
	Enabled   bool            `mapstructure:"enabled"`
	Interval  time.Duration   `mapstructure:"interval"`
	Instances []NginxInstance `mapstructure:"instances"`
}

// NginxInstance is a single Nginx stub_status endpoint to scrape.
type NginxInstance struct {
	Name          string            `mapstructure:"name"`
	URL           string            `mapstructure:"url"`     // full URL to stub_status, e.g. http://nginx:8080/stub_status
	Timeout       time.Duration     `mapstructure:"timeout"` // default 5s
	TLSEnabled    bool              `mapstructure:"tls_enabled"`
	TLSSkipVerify bool              `mapstructure:"tls_skip_verify"`
	Username      string            `mapstructure:"username"` // basic auth
	Password      string            `mapstructure:"password"`
	Headers       map[string]string `mapstructure:"headers"`
}
