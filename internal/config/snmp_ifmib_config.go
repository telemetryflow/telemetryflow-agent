// Package config: SNMPInterfaceCollectorConfig configures the IF-MIB interface
// metrics collector, which polls RFC 2863 interface counters and pushes
// per-interface utilization samples to the TFO Platform network-map endpoint.
// Declared separately from config.go so it can be merged centrally.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// SNMPInterfaceCollectorConfig configures the IF-MIB interface-metrics collector.
type SNMPInterfaceCollectorConfig struct {
	Enabled  bool                  `mapstructure:"enabled"`
	Interval time.Duration         `mapstructure:"interval"` // poll interval, default 60s
	Devices  []SNMPInterfaceDevice `mapstructure:"devices"`

	// BackendEndpoint is the TFO Platform base URL (e.g. https://api.telemetryflow.id).
	// The collector POSTs to {BackendEndpoint}/api/v2/monitoring/network-map/snmp/interface-metrics.
	BackendEndpoint string `mapstructure:"backend_endpoint"`

	// Authentication with the platform. Prefer the agent's API-key headers;
	// a BearerToken (JWT) is used instead when set.
	APIKeyID     string `mapstructure:"api_key_id"`
	APIKeySecret string `mapstructure:"-" yaml:"api_key_secret"`
	BearerToken  string `mapstructure:"-" yaml:"bearer_token"`

	// BatchSize caps the number of samples per HTTP POST (default 500).
	BatchSize int `mapstructure:"batch_size"`

	// Timeout for each HTTP push request (default 30s).
	Timeout time.Duration `mapstructure:"timeout"`

	// MaxRetryAttempts for push requests (default 3).
	MaxRetryAttempts int `mapstructure:"max_retry_attempts"`
}

// SNMPInterfaceDevice is a single SNMP-managed network device to poll for
// IF-MIB interface counters. DeviceID MUST match the platform's device UUID so
// samples correlate to the right node in the network map.
type SNMPInterfaceDevice struct {
	DeviceID   string `mapstructure:"device_id"`   // platform device UUID
	DeviceName string `mapstructure:"device_name"` // human-readable name (e.g. "core-sw")

	Host      string        `mapstructure:"host"`
	Community string        `mapstructure:"community"` // v1/v2c community string
	Version   string        `mapstructure:"version"`   // "1", "2c" (default), or "3"
	Port      int           `mapstructure:"port"`      // default 161
	Timeout   time.Duration `mapstructure:"timeout"`   // default 10s
	Retries   int           `mapstructure:"retries"`   // default 3

	// Auth holds SNMPv3 credentials (only used when Version == "3").
	Auth SNMPv3Auth `mapstructure:"auth"`
}

// ToSNMPAgent projects an SNMPInterfaceDevice onto the shared SNMPAgent type so
// the IF-MIB collector can reuse the existing gosnmp connection wiring
// (v1/v2c/v3) without duplicating it.
func (d SNMPInterfaceDevice) ToSNMPAgent() SNMPAgent {
	return SNMPAgent{
		Host:      d.Host,
		Name:      d.DeviceName,
		Community: d.Community,
		Version:   d.Version,
		Port:      d.Port,
		Timeout:   d.Timeout,
		Retries:   d.Retries,
		Auth:      d.Auth,
	}
}
