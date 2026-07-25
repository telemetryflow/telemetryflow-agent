// Package vault implements a TelemetryFlow Agent collector that scrapes the
// HashiCorp Vault /v1/sys/metrics endpoint (Prometheus text exposition format
// by default) and emits metrics under the vault.* namespace. It uses the Go
// standard library only.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "vault"

// defaultTimeout is applied when an instance does not set one.
const defaultTimeout = 10 * time.Second

// defaultMetricsPath is the standard Vault Prometheus metrics endpoint.
const defaultMetricsPath = "/v1/sys/metrics"

// VaultCollector monitors one or more HashiCorp Vault instances via the
// /v1/sys/metrics Prometheus endpoint. It implements collector.Collector.
type VaultCollector struct {
	cfg      config.VaultCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewVaultCollector constructs a new Vault collector.
func NewVaultCollector(cfg config.VaultCollectorConfig, logger *zap.Logger) *VaultCollector {
	return &VaultCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *VaultCollector) Name() string { return collectorName }

func (c *VaultCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *VaultCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("vault collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("Vault collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *VaultCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances,
// honoring context cancellation between instances.
func (c *VaultCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		all = append(all, c.collectInstance(ctx, inst)...)
	}
	return all, nil
}

// metricBuilder is the closure signature used to assemble metrics with shared
// labels and timestamp.
type metricBuilder func(name string, v float64, typ collector.MetricType, unit, desc string, extra map[string]string) collector.Metric

// collectInstance scrapes a single Vault endpoint and returns metrics.
// Scrape failures (transport error, non-200, empty body, unparseable text)
// yield a single state=0 metric.
func (c *VaultCollector) collectInstance(ctx context.Context, inst config.VaultInstance) []collector.Metric {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	baseLabels := instanceLabels(inst)
	now := time.Now()
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string, extra map[string]string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        typ,
			Value:       v,
			Timestamp:   now,
			Unit:        unit,
			Description: desc,
			Labels:      make(map[string]string, len(baseLabels)+len(extra)),
		}
		for k, val := range baseLabels {
			m.Labels[k] = val
		}
		for k, val := range extra {
			m.Labels[k] = val
		}
		return m
	}

	client := newHTTPClient(inst, timeout)
	body, ok := c.fetch(ctx, client, inst)
	if !ok {
		return failureMetrics(mk)
	}
	parsed := parsePrometheusText(string(body))
	if len(parsed) == 0 {
		// Empty or unparseable body — treat as scrape failure.
		return failureMetrics(mk)
	}
	out := make([]collector.Metric, 0, len(parsed)+1)
	out = append(out, mk("vault.state", 1, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail", nil))
	for _, p := range parsed {
		out = append(out, mk(p.name, p.value, p.typ, "", p.help, p.labels))
	}
	return out
}

// failureMetrics is the state=0 metric set emitted when the scrape did not
// produce a usable body.
func failureMetrics(mk metricBuilder) []collector.Metric {
	return []collector.Metric{
		mk("vault.state", 0, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail", nil),
	}
}

// fetch performs an HTTP GET against the Vault metrics endpoint and returns
// the raw body bytes. The boolean is false when the request fails or the
// response status is not 200.
func (c *VaultCollector) fetch(ctx context.Context, client *http.Client, inst config.VaultInstance) ([]byte, bool) {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	path := inst.MetricsPath
	if path == "" {
		path = defaultMetricsPath
	}
	format := inst.Format
	if format == "" {
		format = "prometheus"
	}
	target := strings.TrimRight(inst.URL, "/") + path + "?format=" + format

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		c.logger.Debug("Vault request build failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return nil, false
	}
	if inst.Token != "" {
		req.Header.Set("X-Vault-Token", inst.Token)
	}
	if inst.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", inst.Namespace)
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debug("Vault scrape request failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("Vault scrape non-200",
			zap.String("instance", inst.Name), zap.Int("status", resp.StatusCode))
		return nil, false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug("Vault scrape read failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return nil, false
	}
	return body, true
}

// newHTTPClient builds an *http.Client honoring TLSSkipVerify.
func newHTTPClient(inst config.VaultInstance, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: inst.TLSSkipVerify,
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

// instanceLabels builds the standard label set for an instance. vault_host is
// derived from the URL host when parseable, otherwise it falls back to the
// raw URL string.
func instanceLabels(inst config.VaultInstance) map[string]string {
	name := inst.Name
	if name == "" {
		name = inst.URL
	}
	host := inst.URL
	if u, err := url.Parse(inst.URL); err == nil && u.Host != "" {
		host = u.Host
	}
	return map[string]string{
		"vault_instance": name,
		"vault_host":     host,
		"db_system":      "vault",
	}
}

// =====================================================================
// Minimal Prometheus text exposition parser (stdlib only).
// =====================================================================

// parsedMetric is a single decoded sample line.
type parsedMetric struct {
	name   string
	value  float64
	typ    collector.MetricType
	help   string
	labels map[string]string
}

// parsePrometheusText decodes Prometheus text exposition format into a flat
// list of parsed samples. It is a deliberately small line-by-line parser:
// comments (# HELP / # TYPE) populate lookup tables; sample lines are decoded
// into name, labels, and value. Histogram and summary components (_bucket,
// _sum, _count) inherit their family's declared type.
func parsePrometheusText(text string) []parsedMetric {
	lines := strings.Split(text, "\n")
	typeMap := make(map[string]string)
	helpMap := make(map[string]string)
	var samples []string

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line[0] == '#' {
			body := strings.TrimSpace(line[1:])
			if strings.HasPrefix(body, "HELP ") {
				rest := body[len("HELP "):]
				sp := strings.IndexByte(rest, ' ')
				if sp < 0 {
					continue
				}
				name := strings.TrimSpace(rest[:sp])
				helpMap[name] = strings.TrimSpace(rest[sp+1:])
			} else if strings.HasPrefix(body, "TYPE ") {
				rest := body[len("TYPE "):]
				sp := strings.IndexByte(rest, ' ')
				if sp < 0 {
					continue
				}
				name := strings.TrimSpace(rest[:sp])
				typeMap[name] = strings.ToLower(strings.TrimSpace(rest[sp+1:]))
			}
			continue
		}
		samples = append(samples, line)
	}

	out := make([]parsedMetric, 0, len(samples))
	for _, line := range samples {
		pm, ok := decodeSample(line, typeMap, helpMap)
		if !ok {
			continue
		}
		out = append(out, pm)
	}
	return out
}

// decodeSample parses a single non-comment exposition line.
func decodeSample(line string, typeMap, helpMap map[string]string) (parsedMetric, bool) {
	var name, labelPart, valuePart string

	if i := strings.IndexByte(line, '{'); i >= 0 {
		name = line[:i]
		rest := line[i+1:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			return parsedMetric{}, false
		}
		labelPart = rest[:j]
		valuePart = strings.TrimSpace(rest[j+1:])
	} else {
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			return parsedMetric{}, false
		}
		name = line[:sp]
		valuePart = strings.TrimSpace(line[sp+1:])
	}

	// A sample may carry a trailing timestamp token; keep only the value.
	if sp := strings.IndexByte(valuePart, ' '); sp >= 0 {
		valuePart = valuePart[:sp]
	}

	if !isValidMetricName(name) {
		return parsedMetric{}, false
	}
	val, err := strconv.ParseFloat(valuePart, 64)
	if err != nil {
		return parsedMetric{}, false
	}

	typ, help := lookupType(name, typeMap, helpMap)
	return parsedMetric{
		name:   mapMetricName(name),
		value:  val,
		typ:    typ,
		help:   help,
		labels: parseLabels(labelPart),
	}, true
}

// lookupType resolves the MetricType for a sample. Histogram/summary
// components (_bucket, _sum, _count) inherit the declared type of their base
// family. Samples without a TYPE declaration default to gauge (untyped).
func lookupType(name string, typeMap, helpMap map[string]string) (collector.MetricType, string) {
	if t, ok := typeMap[name]; ok {
		return metricTypeFor(t), helpMap[name]
	}
	for _, suffix := range []string{"_bucket", "_sum", "_count"} {
		if strings.HasSuffix(name, suffix) {
			base := name[:len(name)-len(suffix)]
			if t, ok := typeMap[base]; ok {
				switch t {
				case "histogram", "summary":
					return metricTypeFor(t), helpMap[base]
				}
			}
		}
	}
	return collector.MetricTypeGauge, helpMap[name]
}

// metricTypeFor maps a Prometheus type keyword to a collector.MetricType.
func metricTypeFor(t string) collector.MetricType {
	switch t {
	case "counter":
		return collector.MetricTypeCounter
	case "gauge":
		return collector.MetricTypeGauge
	case "histogram":
		return collector.MetricTypeHistogram
	case "summary":
		return collector.MetricTypeSummary
	default:
		return collector.MetricTypeGauge
	}
}

// mapMetricName rewrites a raw Vault metric name to the vault.* namespace.
// vault_foo_bar -> vault.foo_bar; anything else is namespaced verbatim.
func mapMetricName(name string) string {
	if strings.HasPrefix(name, "vault_") {
		return "vault." + name[len("vault_"):]
	}
	return "vault." + name
}

// isValidMetricName reports whether s is a valid Prometheus metric identifier.
func isValidMetricName(s string) bool {
	if s == "" {
		return false
	}
	if !isNameStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}

func isNameStart(c byte) bool {
	return c == '_' || c == ':' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

// parseLabels decodes the comma-separated key="value" pairs inside a label
// block (the text between { and }). Escapes (\n, \", \\) are honored.
func parseLabels(s string) map[string]string {
	if s == "" {
		return nil
	}
	m := make(map[string]string)
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == ',' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[i : i+eq])
		i += eq + 1
		if i >= len(s) || s[i] != '"' {
			break
		}
		i++ // skip opening quote
		var val strings.Builder
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					val.WriteByte('\n')
				case '"':
					val.WriteByte('"')
				case '\\':
					val.WriteByte('\\')
				default:
					val.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			if c == '"' {
				i++ // skip closing quote
				break
			}
			val.WriteByte(c)
			i++
		}
		if key != "" {
			m[key] = val.String()
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
