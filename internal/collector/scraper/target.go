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

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// scrapeTarget performs a single HTTP GET scrape of the given target, parses the
// Prometheus text response, attaches job/instance labels, applies relabeling rules,
// updates self-observability counters, and returns the resulting metrics.
//
// URL construction:
//   - If target has no scheme, "http://" is prepended.
//   - cfg.ScrapePath is appended (defaults to "/metrics" if empty).
func scrapeTarget(ctx context.Context, client *http.Client, target string, cfg ScrapeJobConfig) ([]collector.Metric, error) {
	// Build the scrape URL.
	url := buildScrapeURL(target, cfg.ScrapePath)

	start := time.Now()

	// Perform the HTTP GET.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		ScrapeErrors.WithLabelValues(cfg.JobName, target).Inc()
		return nil, fmt.Errorf("scraper: build request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		ScrapeErrors.WithLabelValues(cfg.JobName, target).Inc()
		return nil, fmt.Errorf("scraper: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		ScrapeErrors.WithLabelValues(cfg.JobName, target).Inc()
		return nil, fmt.Errorf("scraper: GET %s returned HTTP %d", url, resp.StatusCode)
	}

	// Parse the Prometheus text body.
	metrics, err := parsePrometheusText(resp.Body)
	if err != nil {
		ParseErrors.WithLabelValues(cfg.JobName, target).Inc()
		return nil, fmt.Errorf("scraper: parse %s: %w", url, err)
	}

	// Attach job and instance labels, respecting honor_labels.
	for i := range metrics {
		if metrics[i].Labels == nil {
			metrics[i].Labels = make(map[string]string)
		}
		if !cfg.HonorLabels || metrics[i].Labels["job"] == "" {
			metrics[i].Labels["job"] = cfg.JobName
		}
		if !cfg.HonorLabels || metrics[i].Labels["instance"] == "" {
			metrics[i].Labels["instance"] = target
		}
	}

	// Apply relabeling rules.
	metrics = applyRelabelRules(metrics, cfg.RelabelConfigs)

	// Update self-observability counters.
	MetricsScraped.WithLabelValues(cfg.JobName, target).Add(float64(len(metrics)))
	ScrapeDuration.WithLabelValues(cfg.JobName, target).Observe(time.Since(start).Seconds())

	return metrics, nil
}

// buildScrapeURL constructs the full scrape URL from a target and path.
func buildScrapeURL(target, scrapePath string) string {
	if scrapePath == "" {
		scrapePath = "/metrics"
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	return strings.TrimRight(target, "/") + scrapePath
}
