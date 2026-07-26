// Package http_probe implements a TelemetryFlow Agent synthetic check collector
// that issues HTTP requests against configured targets and records round-trip
// time, status code, content length, TLS certificate health, redirect count,
// and optional body regex match results. It uses the Go standard library only.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package http_probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "http_probe"

// defaultExpectedStatus is used when a target leaves ExpectedStatus empty.
var defaultExpectedStatus = []int{200, 201, 204, 301, 302}

// HTTPProbeCollector monitors one or more HTTP endpoints via synthetic checks.
type HTTPProbeCollector struct {
	cfg      config.HTTPProbeCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewHTTPProbeCollector constructs a new HTTP probe collector.
func NewHTTPProbeCollector(cfg config.HTTPProbeCollectorConfig, logger *zap.Logger) *HTTPProbeCollector {
	return &HTTPProbeCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *HTTPProbeCollector) Name() string { return collectorName }

func (c *HTTPProbeCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *HTTPProbeCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("http_probe collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("HTTP probe collector starting", zap.Int("targets", len(c.cfg.Targets)))
	return nil
}

func (c *HTTPProbeCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured targets, honoring
// context cancellation between targets.
func (c *HTTPProbeCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Targets) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, target := range c.cfg.Targets {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		all = append(all, c.probeTarget(ctx, target)...)
	}
	return all, nil
}

// probeTarget issues a single HTTP request against the target and returns the
// resulting metrics. Transport-level failures (DNS, connect, timeout) produce a
// state=0 metric set rather than an error.
func (c *HTTPProbeCollector) probeTarget(ctx context.Context, target config.HTTPProbeTarget) []collector.Metric {
	method := target.Method
	if method == "" {
		method = http.MethodGet
	}
	timeout := target.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	expectedStatus := target.ExpectedStatus
	if len(expectedStatus) == 0 {
		expectedStatus = defaultExpectedStatus
	}

	labels := targetLabels(target)
	now := time.Now()
	isHTTPS := false
	if u, err := url.Parse(target.URL); err == nil && u.Scheme == "https" {
		isHTTPS = true
	}
	mk := func(name string, v float64, unit, desc string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        collector.MetricTypeGauge,
			Value:       v,
			Timestamp:   now,
			Unit:        unit,
			Description: desc,
			Labels:      make(map[string]string, len(labels)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		return m
	}

	redirectCount := 0
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: target.TLSSkipVerify,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !target.FollowRedirects {
				return http.ErrUseLastResponse
			}
			redirectCount++
			if redirectCount > 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	var bodyReader io.Reader
	if target.Body != "" {
		bodyReader = bytes.NewReader([]byte(target.Body))
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, target.URL, bodyReader)
	if err != nil {
		c.logger.Warn("HTTP probe request build failed",
			zap.String("target", target.Name), zap.Error(err))
		return failureMetrics(mk, isHTTPS, target.ExpectedBodyRegex)
	}
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}
	if target.Username != "" || target.Password != "" {
		req.SetBasicAuth(target.Username, target.Password)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsedMs := float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		c.logger.Debug("HTTP probe request failed",
			zap.String("target", target.Name), zap.Error(err))
		return failureMetrics(mk, isHTTPS, target.ExpectedBodyRegex, elapsedMs, float64(redirectCount))
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	contentLength := float64(len(body))
	statusCode := resp.StatusCode

	state := 0.0
	for _, s := range expectedStatus {
		if s == statusCode {
			state = 1
			break
		}
	}

	out := []collector.Metric{
		mk("network.http.response_time_ms", elapsedMs, "ms", "HTTP round-trip time in milliseconds"),
		mk("network.http.status_code", float64(statusCode), "", "HTTP response status code (0 on failure)"),
		mk("network.http.content_length", contentLength, "bytes", "Response content length in bytes"),
		mk("network.http.state", state, "", "Probe state: 1=ok, 0=fail"),
		mk("network.http.redirect_count", float64(redirectCount), "", "Number of redirects followed"),
	}
	if isHTTPS {
		days, valid := tlsInfo(resp)
		out = append(out,
			mk("network.http.tls_days_remaining", days, "days", "Days until TLS certificate expiry"),
			mk("network.http.tls_valid", valid, "", "TLS certificate validity: 1=valid, 0=invalid"),
		)
	}
	if target.ExpectedBodyRegex != "" {
		found := 0.0
		if re, rerr := regexp.Compile(target.ExpectedBodyRegex); rerr == nil && re.Match(body) {
			found = 1
		}
		out = append(out, mk("network.http.string_found", found, "", "Body regex match: 1=found, 0=not found"))
	}
	return out
}

// failureMetrics emits the state=0 metric set used when the HTTP request never
// completed successfully. elapsedMs and redirectCount default to 0 when omitted.
func failureMetrics(mk metricBuilder, isHTTPS bool, regex string, extra ...float64) []collector.Metric {
	var (
		elapsedMs     float64
		redirectCount int
	)
	if len(extra) > 0 {
		elapsedMs = extra[0]
	}
	if len(extra) > 1 {
		redirectCount = int(extra[1])
	}
	out := []collector.Metric{
		mk("network.http.response_time_ms", elapsedMs, "ms", "HTTP round-trip time in milliseconds"),
		mk("network.http.status_code", 0, "", "HTTP response status code (0 on failure)"),
		mk("network.http.content_length", 0, "bytes", "Response content length in bytes"),
		mk("network.http.state", 0, "", "Probe state: 1=ok, 0=fail"),
		mk("network.http.redirect_count", float64(redirectCount), "", "Number of redirects followed"),
	}
	if isHTTPS {
		out = append(out,
			mk("network.http.tls_days_remaining", -1, "days", "Days until TLS certificate expiry"),
			mk("network.http.tls_valid", 0, "", "TLS certificate validity: 1=valid, 0=invalid"),
		)
	}
	if regex != "" {
		out = append(out, mk("network.http.string_found", 0, "", "Body regex match: 1=found, 0=not found"))
	}
	return out
}

// metricBuilder is the closure signature used to assemble metrics with shared
// labels and timestamp.
type metricBuilder func(name string, v float64, unit, desc string) collector.Metric

// tlsInfo returns the days remaining until the leaf peer certificate expires
// and a 0/1 validity flag (1 = not expired). Returns -1, 0 when no cert state
// is available.
func tlsInfo(resp *http.Response) (daysRemaining float64, valid float64) {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return -1, 0
	}
	cert := resp.TLS.PeerCertificates[0]
	days := time.Until(cert.NotAfter).Hours() / 24
	if days >= 0 {
		valid = 1
	}
	return days, valid
}

// targetLabels builds the standard label set for a target.
func targetLabels(target config.HTTPProbeTarget) map[string]string {
	name := target.Name
	if name == "" {
		name = target.URL
	}
	host := ""
	if u, err := url.Parse(target.URL); err == nil {
		host = u.Host
	}
	return map[string]string{
		"target": name,
		"url":    target.URL,
		"host":   host,
	}
}
