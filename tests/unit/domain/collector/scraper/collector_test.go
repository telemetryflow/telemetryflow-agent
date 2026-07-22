// Package scraper_test contains unit tests for PrometheusScraperCollector lifecycle.
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

func TestCollector_NameAndInitialState(t *testing.T) {
	c := scraper.NewPrometheusScraperCollector(scraper.ScraperConfig{}, zap.NewNop())
	assert.Equal(t, "prometheus_scraper", c.Name())
	assert.False(t, c.IsRunning())
}

func TestCollector_StartCollectStop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	cfg := scraper.ScraperConfig{
		Enabled: true,
		Jobs: []scraper.ScrapeJobConfig{
			{
				JobName:        "job1",
				Enabled:        true,
				Targets:        []string{stripScheme(srv.URL)},
				ScrapeInterval: 20 * time.Millisecond,
			},
			{
				JobName: "disabled-job",
				Enabled: false,
			},
		},
	}
	c := scraper.NewPrometheusScraperCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, c.Start(ctx))
	assert.True(t, c.IsRunning())

	// Wait for at least one scrape to land in the channel.
	assert.Eventually(t, func() bool {
		got, err := c.Collect(ctx)
		return err == nil && len(got) > 0
	}, 2*time.Second, 20*time.Millisecond)

	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
}

func TestCollector_StartIdempotent(t *testing.T) {
	c := scraper.NewPrometheusScraperCollector(scraper.ScraperConfig{}, zap.NewNop())
	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	// Second Start is a no-op while running.
	require.NoError(t, c.Start(ctx))
	require.NoError(t, c.Stop())
}

func TestCollector_StopWhenNotRunning(t *testing.T) {
	c := scraper.NewPrometheusScraperCollector(scraper.ScraperConfig{}, zap.NewNop())
	// Stop before Start is a no-op.
	require.NoError(t, c.Stop())
}

func TestCollector_CollectEmpty(t *testing.T) {
	c := scraper.NewPrometheusScraperCollector(scraper.ScraperConfig{}, zap.NewNop())
	require.NoError(t, c.Start(context.Background()))
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
	require.NoError(t, c.Stop())
}

func TestCollector_StartJobError(t *testing.T) {
	// A job with an unreadable bearer token file makes newScrapeJob fail,
	// which propagates out of Start.
	cfg := scraper.ScraperConfig{
		Enabled: true,
		Jobs: []scraper.ScrapeJobConfig{
			{JobName: "bad", Enabled: true, BearerTokenFile: "/nonexistent/token"},
		},
	}
	c := scraper.NewPrometheusScraperCollector(cfg, zap.NewNop())
	err := c.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create job")
}
