// Package scraper implements a Prometheus pull-based scraper that periodically
// fetches metrics from configured HTTP targets, parses Prometheus text-format
// exposition, and applies relabeling rules before forwarding to exporters.
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
package scraper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"go.uber.org/zap"
)

// bearerRoundTripper injects an Authorization: Bearer header on every request.
type bearerRoundTripper struct {
	token string
	next  http.RoundTripper
}

func (b *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the original.
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

// basicAuthRoundTripper injects HTTP basic auth on every request.
type basicAuthRoundTripper struct {
	username string
	password string
	next     http.RoundTripper
}

func (b *basicAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.SetBasicAuth(b.username, b.password)
	return b.next.RoundTrip(r)
}

// ScrapeJob manages the periodic scrape loop for one named job.
type ScrapeJob struct {
	cfg    ScrapeJobConfig
	client *http.Client // pre-configured with auth + TLS
	ticker *time.Ticker
	out    chan<- []collector.Metric
	logger *zap.Logger
}

// newScrapeJob constructs a ScrapeJob with a fully configured HTTP client.
func newScrapeJob(cfg ScrapeJobConfig, out chan<- []collector.Metric, logger *zap.Logger) (*ScrapeJob, error) {
	tlsCfg, err := buildTLSConfig(cfg.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("scraper: job %q: build TLS config: %w", cfg.JobName, err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	timeout := cfg.ScrapeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	var rt http.RoundTripper = transport

	// Resolve bearer token (file takes precedence over inline value).
	bearerToken := cfg.BearerToken
	if cfg.BearerTokenFile != "" {
		data, err := os.ReadFile(cfg.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("scraper: job %q: read bearer token file: %w", cfg.JobName, err)
		}
		bearerToken = string(data)
	}

	if bearerToken != "" {
		rt = &bearerRoundTripper{token: bearerToken, next: rt}
	} else if cfg.BasicAuth != nil {
		rt = &basicAuthRoundTripper{
			username: cfg.BasicAuth.Username,
			password: cfg.BasicAuth.Password,
			next:     rt,
		}
	}

	client := &http.Client{
		Transport: rt,
		Timeout:   timeout,
	}

	return &ScrapeJob{
		cfg:    cfg,
		client: client,
		out:    out,
		logger: logger,
	}, nil
}

// buildTLSConfig constructs a *tls.Config from the scraper TLSConfig.
func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // user-controlled opt-in
	}

	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates found in CA file %q", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key (%q, %q): %w", cfg.CertFile, cfg.KeyFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// Start launches the scrape goroutine. It returns immediately; the goroutine
// runs until ctx is cancelled.
func (j *ScrapeJob) Start(ctx context.Context) {
	interval := j.cfg.ScrapeInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}

	j.ticker = time.NewTicker(interval)

	TargetsActive.WithLabelValues(j.cfg.JobName).Set(float64(len(j.cfg.Targets)))

	go func() {
		defer j.ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-j.ticker.C:
				j.runScrape(ctx)
			}
		}
	}()
}

// Stop stops the ticker, halting future scrapes. Any in-flight scrape
// continues until it completes or its context is cancelled.
func (j *ScrapeJob) Stop() {
	if j.ticker != nil {
		j.ticker.Stop()
	}
}

// runScrape iterates all targets, scrapes each one, and forwards results.
func (j *ScrapeJob) runScrape(ctx context.Context) {
	for _, target := range j.cfg.Targets {
		metrics, err := scrapeTarget(ctx, j.client, target, j.cfg)
		if err != nil {
			j.logger.Warn("scrape target failed",
				zap.String("job", j.cfg.JobName),
				zap.String("target", target),
				zap.Error(err),
			)
			continue
		}

		if len(metrics) == 0 {
			continue
		}

		// Non-blocking send: drop if the channel is full.
		select {
		case j.out <- metrics:
		default:
			j.logger.Warn("scraper metrics channel full, dropping batch",
				zap.String("job", j.cfg.JobName),
				zap.String("target", target),
				zap.Int("dropped", len(metrics)),
			)
		}
	}
}
