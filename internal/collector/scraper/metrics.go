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

import "github.com/prometheus/client_golang/prometheus"

// Self-observability metric name constants.
const (
	MetricScrapeDuration = "tfo_scraper_scrape_duration_seconds"
	MetricScrapeErrors   = "tfo_scraper_scrape_errors_total"
	MetricParseErrors    = "tfo_scraper_parse_errors_total"
	MetricMetricsScraped = "tfo_scraper_metrics_scraped_total"
	MetricTargetsActive  = "tfo_scraper_targets_active"
)

var (
	// ScrapeDuration tracks how long each scrape takes, labelled by job and instance.
	ScrapeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    MetricScrapeDuration,
			Help:    "Duration of Prometheus scrape requests in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"job", "instance"},
	)

	// ScrapeErrors counts scrape-level errors (HTTP failures, timeouts), labelled by job and instance.
	ScrapeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricScrapeErrors,
			Help: "Total number of scrape errors by job and instance.",
		},
		[]string{"job", "instance"},
	)

	// ParseErrors counts metric parse errors after a successful scrape, labelled by job and instance.
	ParseErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricParseErrors,
			Help: "Total number of Prometheus text parse errors by job and instance.",
		},
		[]string{"job", "instance"},
	)

	// MetricsScraped counts the total number of metrics collected per scrape, labelled by job and instance.
	MetricsScraped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricMetricsScraped,
			Help: "Total number of metrics scraped by job and instance.",
		},
		[]string{"job", "instance"},
	)

	// TargetsActive tracks the number of active targets per job.
	TargetsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: MetricTargetsActive,
			Help: "Number of active scrape targets per job.",
		},
		[]string{"job"},
	)
)

func init() {
	prometheus.MustRegister(
		ScrapeDuration,
		ScrapeErrors,
		ParseErrors,
		MetricsScraped,
		TargetsActive,
	)
}
