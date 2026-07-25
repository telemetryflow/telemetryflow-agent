// Package config defines the DNS query probe collector configuration.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// DNSCollectorConfig configures the DNS query probe collector.
type DNSCollectorConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
	Servers  []DNSServer   `mapstructure:"servers"`
	Queries  []DNSQuery    `mapstructure:"queries"`
	Port     int           `mapstructure:"port"`    // default 53
	Timeout  time.Duration `mapstructure:"timeout"` // per query (default 5s)
}

// DNSServer is a single DNS server target.
type DNSServer struct {
	Address string `mapstructure:"address"` // IP address
	Name    string `mapstructure:"name"`    // human-friendly label
}

// DNSQuery is a single query to issue against every server.
type DNSQuery struct {
	Domain     string `mapstructure:"domain"`
	RecordType string `mapstructure:"record_type"` // A, AAAA, TXT, MX, NS, CNAME, PTR (default A)
}
