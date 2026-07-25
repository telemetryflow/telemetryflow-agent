// Package config defines the ElasticsearchCollectorConfig type declared
// separately from the main config.go so it can be merged centrally.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// ElasticsearchCollectorConfig configures the Elasticsearch cluster collector
// (M4). One collector instance fans out to one or more Elasticsearch endpoints.
type ElasticsearchCollectorConfig struct {
	Enabled   bool                    `mapstructure:"enabled"`
	Interval  time.Duration           `mapstructure:"interval"`
	Instances []ElasticsearchInstance `mapstructure:"instances"`
}

// ElasticsearchInstance is a single Elasticsearch endpoint to scrape.
type ElasticsearchInstance struct {
	Name              string        `mapstructure:"name"`
	URL               string        `mapstructure:"url"` // e.g. http://elasticsearch:9200
	Username          string        `mapstructure:"username"`
	Password          string        `mapstructure:"password"`
	Timeout           time.Duration `mapstructure:"timeout"`
	TLSEnabled        bool          `mapstructure:"tls_enabled"`
	TLSSkipVerify     bool          `mapstructure:"tls_skip_verify"`
	ClusterHealthOnly bool          `mapstructure:"cluster_health_only"` // skip per-node stats (less load)
}
