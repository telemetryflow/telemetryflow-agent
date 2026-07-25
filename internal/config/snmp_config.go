// Package config contains the SNMPCollectorConfig type declared separately
// from the main config.go so it can be merged centrally by the integrator.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// SNMPCollectorConfig configures the SNMP polling collector.
type SNMPCollectorConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"` // default 60s
	Agents   []SNMPAgent   `mapstructure:"agents"`
	Fields   []SNMPField   `mapstructure:"fields"`
	Tables   []SNMPTable   `mapstructure:"tables"`
}

// SNMPAgent is a single SNMP-managed device.
type SNMPAgent struct {
	Host      string        `mapstructure:"host"`
	Name      string        `mapstructure:"name"`
	Community string        `mapstructure:"community"` // v1/v2c community string
	Version   string        `mapstructure:"version"`   // "1", "2c" (default), or "3"
	Port      int           `mapstructure:"port"`      // default 161
	Timeout   time.Duration `mapstructure:"timeout"`   // default 10s
	Retries   int           `mapstructure:"retries"`   // default 3

	// Auth holds SNMPv3 credentials (only used when Version == "3").
	Auth SNMPv3Auth `mapstructure:"auth"`
}

// SNMPv3Auth holds SNMPv3 credentials.
type SNMPv3Auth struct {
	Username      string `mapstructure:"username"`
	AuthProtocol  string `mapstructure:"auth_protocol"` // MD5, SHA, SHA256, SHA512
	AuthPassword  string `mapstructure:"auth_password"`
	PrivProtocol  string `mapstructure:"priv_protocol"` // DES, AES, AES256, AES192C, AES256C
	PrivPassword  string `mapstructure:"priv_password"`
	SecurityLevel string `mapstructure:"security_level"` // noAuthNoPriv, authNoPriv, authPriv (default)
}

// SNMPField is a single scalar OID to poll.
type SNMPField struct {
	Name string `mapstructure:"name"`
	OID  string `mapstructure:"oid"`
	Unit string `mapstructure:"unit,omitempty"` // optional unit hint
}

// SNMPTable is a repeating OID whose values form a table.
type SNMPTable struct {
	Name       string `mapstructure:"name"`
	OID        string `mapstructure:"oid"`
	IndexAsTag bool   `mapstructure:"index_as_tag"` // use the OID index as a tag value
}
