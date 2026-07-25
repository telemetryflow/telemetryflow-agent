// Package config defines the sFlow v5 listener collector configuration.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// SflowCollectorConfig configures the sFlow v5 listener.
type SflowCollectorConfig struct {
	Enabled bool `mapstructure:"enabled"`

	// Address is the bind address. Default "0.0.0.0".
	Address string `mapstructure:"address"`

	// Port is the UDP port to listen on. Default 6343 (IANA sFlow).
	Port int `mapstructure:"port"`

	// Protocol is the transport. Default "udp".
	Protocol string `mapstructure:"protocol"`

	// Workers is the number of background parser goroutines. Default 4.
	Workers int `mapstructure:"workers"`

	// BufSize is the UDP socket read-buffer size in bytes. Default 65535.
	BufSize int `mapstructure:"buffer_size"`

	// FlushInterval is how often buffered sample counters are emitted via
	// Collect(). Default 30s.
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Tags are collector-level tags applied to all sflow metrics.
	Tags map[string]string `mapstructure:"tags"`
}
