// Package config defines the NetFlow v5/v9/IPFIX listener collector configuration.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// NetflowCollectorConfig configures the NetFlow v5/v9/IPFIX listener.
type NetflowCollectorConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Address  string `mapstructure:"address"`     // default "0.0.0.0"
	Port     int    `mapstructure:"port"`        // default 2055
	Protocol string `mapstructure:"protocol"`    // "udp" (default); future: "tcp", "sctp"
	Workers  int    `mapstructure:"workers"`     // background parser goroutines (default 4)
	BufSize  int    `mapstructure:"buffer_size"` // UDP socket buffer bytes (default 65535)

	// Protocols lists the NetFlow versions to accept. Default ["5","9","ipfix"].
	// Unknown versions increment a parse-error counter and are dropped.
	Protocols []string `mapstructure:"protocols"`

	// FlushInterval is how often buffered flow counters are emitted as
	// metrics via Collect(). Default 30s.
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Tags are collector-level tags applied to all netflow metrics.
	Tags map[string]string `mapstructure:"tags"`
}
