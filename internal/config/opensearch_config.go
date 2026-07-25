// Package config defines the OpenSearchCollectorConfig type declared
// separately from the main config.go so it can be merged centrally.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package config

import "time"

// OpenSearchCollectorConfig configures the OpenSearch cluster collector
// (M4). One collector instance fans out to one or more OpenSearch endpoints.
// OpenSearch is the AWS-backed fork of Elasticsearch and exposes the same
// REST API, so the configuration mirrors ElasticsearchCollectorConfig.
type OpenSearchCollectorConfig struct {
	Enabled   bool                 `mapstructure:"enabled"`
	Interval  time.Duration        `mapstructure:"interval"`
	Instances []OpenSearchInstance `mapstructure:"instances"`
}

// OpenSearchInstance is a single OpenSearch endpoint to scrape.
type OpenSearchInstance struct {
	Name              string        `mapstructure:"name"`
	URL               string        `mapstructure:"url"` // e.g. http://opensearch:9200
	Username          string        `mapstructure:"username"`
	Password          string        `mapstructure:"password"`
	Timeout           time.Duration `mapstructure:"timeout"`
	TLSEnabled        bool          `mapstructure:"tls_enabled"`
	TLSSkipVerify     bool          `mapstructure:"tls_skip_verify"`
	ClusterHealthOnly bool          `mapstructure:"cluster_health_only"` // skip per-node stats (less load)
}
