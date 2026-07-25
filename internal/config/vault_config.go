// Package config defines the VaultCollectorConfig type declared
// separately from the main config.go so it can be merged centrally.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// VaultCollectorConfig configures the HashiCorp Vault metrics collector (M4).
// One collector instance fans out to one or more Vault instances, scraping the
// /v1/sys/metrics endpoint in Prometheus text exposition format by default.
type VaultCollectorConfig struct {
	Enabled   bool            `mapstructure:"enabled"`
	Interval  time.Duration   `mapstructure:"interval"`
	Instances []VaultInstance `mapstructure:"instances"`
}

// VaultInstance is a single Vault endpoint to scrape.
type VaultInstance struct {
	Name          string        `mapstructure:"name"`
	URL           string        `mapstructure:"url"`       // e.g. http://vault:8200
	Token         string        `mapstructure:"token"`     // X-Vault-Token header
	Namespace     string        `mapstructure:"namespace"` // X-Vault-Namespace (Enterprise)
	Timeout       time.Duration `mapstructure:"timeout"`
	TLSEnabled    bool          `mapstructure:"tls_enabled"`
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify"`
	MetricsPath   string        `mapstructure:"metrics_path"` // default /v1/sys/metrics
	Format        string        `mapstructure:"format"`       // "prometheus" (default); future: "json"
}
