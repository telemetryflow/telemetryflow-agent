// Package config defines the InfluxDB collector configuration.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package config

import "time"

// InfluxDBCollectorConfig contains settings for monitoring InfluxDB v1/v2
// instances via the /debug/vars runtime endpoint.
type InfluxDBCollectorConfig struct {
	// Enabled enables the InfluxDB monitoring collector
	Enabled bool `mapstructure:"enabled"`

	// Interval is how often to scrape /debug/vars (default: 15s)
	Interval time.Duration `mapstructure:"interval"`

	// Instances is the list of InfluxDB instances to monitor
	Instances []InfluxDBInstance `mapstructure:"instances"`
}

// InfluxDBInstance contains connection settings for a single InfluxDB instance.
type InfluxDBInstance struct {
	// Name is a human-readable identifier for this instance
	Name string `mapstructure:"name"`

	// URL is the base InfluxDB URL (e.g., http://influxdb:8086)
	URL string `mapstructure:"url"`

	// Username is the basic-auth username (v1)
	Username string `mapstructure:"username"`

	// Password is the basic-auth password (v1)
	Password string `mapstructure:"password"`

	// Token is the v2 API token (Authorization: Token <token>)
	Token string `mapstructure:"token"`

	// Timeout is the HTTP client timeout (default: 10s)
	Timeout time.Duration `mapstructure:"timeout"`

	// TLSEnabled enables HTTPS
	TLSEnabled bool `mapstructure:"tls_enabled"`

	// TLSSkipVerify disables TLS certificate verification
	TLSSkipVerify bool `mapstructure:"tls_skip_verify"`
}
