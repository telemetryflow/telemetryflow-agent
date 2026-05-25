// Package scraper implements a Prometheus pull-based scraper that periodically
// fetches metrics from configured HTTP targets, parses Prometheus text-format
// exposition, and applies relabeling rules before forwarding to exporters.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
package scraper

import "time"

// ScraperConfig maps to config.PrometheusScraperConfig (new config section).
type ScraperConfig struct {
	Enabled bool
	Jobs    []ScrapeJobConfig
}

// ScrapeJobConfig maps to one entry in scrape_jobs[].
type ScrapeJobConfig struct {
	JobName         string
	Enabled         bool
	Targets         []string // host:port
	ScrapeInterval  time.Duration
	ScrapePath      string // default: /metrics
	ScrapeTimeout   time.Duration
	HonorLabels     bool
	BasicAuth       *BasicAuthConfig
	BearerToken     string
	BearerTokenFile string
	TLSConfig       TLSConfig
	RelabelConfigs  []RelabelConfig
}

// RelabelConfig defines a single metric relabeling rule.
type RelabelConfig struct {
	SourceLabels []string
	Regex        string
	TargetLabel  string
	Replacement  string
	Action       string // keep, drop, replace
}

// BasicAuthConfig holds HTTP basic authentication credentials.
type BasicAuthConfig struct {
	Username string
	Password string
}

// TLSConfig holds TLS configuration for scrape connections.
type TLSConfig struct {
	InsecureSkipVerify bool
	CAFile             string
	CertFile           string
	KeyFile            string
}
