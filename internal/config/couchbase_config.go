// Package config defines the CouchbaseCollectorConfig type declared separately
// from the main config.go so it can be merged centrally.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// CouchbaseCollectorConfig configures the Couchbase cluster collector (M4).
// One collector instance fans out to one or more Couchbase endpoints.
type CouchbaseCollectorConfig struct {
	Enabled   bool                `mapstructure:"enabled"`
	Interval  time.Duration       `mapstructure:"interval"`
	Instances []CouchbaseInstance `mapstructure:"instances"`
}

// CouchbaseInstance is a single Couchbase endpoint to scrape.
type CouchbaseInstance struct {
	Name          string        `mapstructure:"name"`
	URL           string        `mapstructure:"url"` // e.g. http://couchbase:8091
	Username      string        `mapstructure:"username"`
	Password      string        `mapstructure:"password"`
	Timeout       time.Duration `mapstructure:"timeout"`
	TLSEnabled    bool          `mapstructure:"tls_enabled"`
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify"`
	Buckets       []string      `mapstructure:"buckets"` // empty = no bucket collection
}
