// Package scraper_test contains unit tests for scrapeTarget using httptest.
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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

const sampleMetrics = `# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET"} 100
# TYPE up gauge
up 1
`

func TestScrapeTarget_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metrics", r.URL.Path)
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{JobName: "test-job"}
	metrics, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), stripScheme(srv.URL), cfg)
	require.NoError(t, err)
	require.Len(t, metrics, 2)

	// job and instance labels attached (honor_labels=false)
	for _, m := range metrics {
		assert.Equal(t, "test-job", m.Labels["job"])
		assert.Equal(t, stripScheme(srv.URL), m.Labels["instance"])
	}
}

func TestScrapeTarget_CustomPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/custom/metrics", r.URL.Path)
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{JobName: "job", ScrapePath: "/custom/metrics"}
	metrics, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), srv.URL, cfg)
	require.NoError(t, err)
	assert.Len(t, metrics, 2)
}

func TestScrapeTarget_HonorLabels(t *testing.T) {
	body := `# TYPE up gauge
up{job="original",instance="orig-inst"} 1
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{JobName: "test-job", HonorLabels: true}
	metrics, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), srv.URL, cfg)
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	// honor_labels preserves the target-provided values
	assert.Equal(t, "original", metrics[0].Labels["job"])
	assert.Equal(t, "orig-inst", metrics[0].Labels["instance"])
}

func TestScrapeTarget_HonorLabelsFillsMissing(t *testing.T) {
	body := `# TYPE up gauge
up 1
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{JobName: "test-job", HonorLabels: true}
	metrics, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), srv.URL, cfg)
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	// With honor_labels but no incoming values, fills in defaults
	assert.Equal(t, "test-job", metrics[0].Labels["job"])
}

func TestScrapeTarget_WithRelabel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{
		JobName: "job",
		RelabelConfigs: []scraper.RelabelConfig{
			{SourceLabels: []string{"method"}, Regex: "GET", Action: "drop"},
		},
	}
	metrics, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), srv.URL, cfg)
	require.NoError(t, err)
	// The GET counter dropped, only `up` remains
	assert.Len(t, metrics, 1)
	assert.Equal(t, "up", metrics[0].Name)
}

func TestScrapeTarget_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{JobName: "job"}
	_, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), srv.URL, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestScrapeTarget_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close so the connection is refused

	cfg := scraper.ScrapeJobConfig{JobName: "job"}
	_, err := scraper.ScrapeTargetExported(context.Background(), http.DefaultClient, url, cfg)
	require.Error(t, err)
}

func TestScrapeTarget_ParseError(t *testing.T) {
	// A body with a bad type declaration that yields a parse error and no families.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# TYPE metric_a counter\nmetric_a{ 1\n"))
	}))
	defer srv.Close()

	cfg := scraper.ScrapeJobConfig{JobName: "job"}
	_, err := scraper.ScrapeTargetExported(context.Background(), srv.Client(), srv.URL, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestScrapeTarget_BadRequestURL(t *testing.T) {
	// Control character in target makes http.NewRequestWithContext fail.
	cfg := scraper.ScrapeJobConfig{JobName: "job"}
	_, err := scraper.ScrapeTargetExported(context.Background(), http.DefaultClient, "http://exa\x7fmple.com", cfg)
	require.Error(t, err)
}

// stripScheme removes the http:// prefix to exercise the scheme-prepend path.
func stripScheme(u string) string {
	return strings.TrimPrefix(u, "http://")
}
