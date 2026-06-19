// Package scraper_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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

package scraper_test

import (
	"testing"

	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

func TestBuildScrapeURL(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		scrapePath string
		expect     string
	}{
		{"no_scheme_default_path", "localhost:9090", "", "http://localhost:9090/metrics"},
		{"no_scheme_custom_path", "localhost:9090", "/api/v1/metrics", "http://localhost:9090/api/v1/metrics"},
		{"with_scheme", "https://prom.example.com", "/metrics", "https://prom.example.com/metrics"},
		{"trailing_slash", "http://localhost:9090/", "/metrics", "http://localhost:9090/metrics"},
		{"empty_path_defaults", "10.0.0.1:9100", "", "http://10.0.0.1:9100/metrics"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scraper.BuildScrapeURLExported(tc.target, tc.scrapePath)
			if got != tc.expect {
				t.Errorf("BuildScrapeURLExported(%q, %q) = %q, want %q", tc.target, tc.scrapePath, got, tc.expect)
			}
		})
	}
}
