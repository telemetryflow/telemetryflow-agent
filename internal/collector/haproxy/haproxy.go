// Package haproxy implements a TelemetryFlow Agent collector that scrapes the
// HAProxy stats CSV export endpoint and emits per-proxy / per-server metrics
// under the proxy.haproxy.* namespace. It uses the Go standard library only.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package haproxy

import (
	"context"
	"crypto/tls"
	"encoding/csv"
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

const collectorName = "haproxy"

// defaultColumns is the standard HAProxy CSV column order, used as a fallback
// when the endpoint suppresses the leading "#" comment line (e.g. ";csv;").
var defaultColumns = []string{
	"pxname", "svname", "qcur", "qmax", "scur", "smax", "slim", "stot",
	"bin", "bout", "dreq", "dresp", "ereq", "econ", "eresp", "wretr",
	"status", "weight", "act", "bck", "chrs", "last", "aget",
	"qtime", "ctime", "rtime", "ttime",
	"hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other",
}

// HAProxyCollector monitors one or more HAProxy stats endpoints via CSV export.
type HAProxyCollector struct {
	cfg      config.HAProxyCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewHAProxyCollector constructs a new HAProxy collector.
func NewHAProxyCollector(cfg config.HAProxyCollectorConfig, logger *zap.Logger) *HAProxyCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	return &HAProxyCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *HAProxyCollector) Name() string { return collectorName }

func (c *HAProxyCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *HAProxyCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("haproxy collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("HAProxy collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *HAProxyCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances.
// Scrape failures (transport errors, non-200 status, malformed CSV) yield a
// single proxy.haproxy.status=0 metric for the instance rather than an error.
func (c *HAProxyCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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

func (c *HAProxyCollector) collectInstance(ctx context.Context, inst config.HAProxyInstance) []collector.Metric {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: inst.TLSSkipVerify,
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, inst.URL, nil)
	if err != nil {
		c.logger.Warn("HAProxy request build failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(inst, time.Now())
	}
	if inst.Username != "" || inst.Password != "" {
		req.SetBasicAuth(inst.Username, inst.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debug("HAProxy scrape failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(inst, time.Now())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("HAProxy scrape non-200",
			zap.String("instance", inst.Name), zap.Int("status", resp.StatusCode))
		return failureMetrics(inst, time.Now())
	}

	rows, columns, err := parseCSV(resp.Body)
	if err != nil {
		c.logger.Warn("HAProxy CSV parse failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(inst, time.Now())
	}

	now := time.Now()
	metrics := BuildHAProxyMetrics(rows, columns, instanceLabels(inst), now)
	if len(metrics) == 0 {
		return failureMetrics(inst, now)
	}
	return metrics
}

// parseCSV reads the HAProxy stats CSV body, returning the data rows and the
// column-name slice. The column names come from the leading "#" comment line;
// when absent (e.g. ";csv;" suppresses it), defaultColumns is used instead.
func parseCSV(r io.Reader) (rows [][]string, columns []string, err error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	all, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("read csv: %w", err)
	}
	if len(all) == 0 {
		return nil, nil, fmt.Errorf("empty csv")
	}
	if strings.HasPrefix(all[0][0], "#") {
		all[0][0] = strings.TrimSpace(strings.TrimPrefix(all[0][0], "#"))
		columns = all[0]
		rows = all[1:]
	} else {
		columns = defaultColumns
		rows = all
	}
	return rows, columns, nil
}

// BuildHAProxyMetrics maps HAProxy CSV rows to collector.Metric under the
// proxy.haproxy.* namespace. Each row is classified as frontend (svname ==
// FRONTEND), backend (svname == BACKEND), or server.
func BuildHAProxyMetrics(rows [][]string, columns []string, baseLabels map[string]string, now time.Time) []collector.Metric {
	idx := make(map[string]int, len(columns))
	for i, c := range columns {
		idx[c] = i
	}
	col := func(name string, row []string) string {
		i, ok := idx[name]
		if !ok || i < 0 || i >= len(row) {
			return ""
		}
		return row[i]
	}
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string, labels map[string]string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        typ,
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

	var out []collector.Metric
	emitGauge := func(row []string, metric, colName, unit, desc string, labels map[string]string) {
		if raw := col(colName, row); raw != "" {
			if v, ok := parseFloat(raw); ok {
				out = append(out, mk("proxy.haproxy."+metric, v, collector.MetricTypeGauge, unit, desc, labels))
			}
		}
	}
	emitCounter := func(row []string, metric, colName, unit, desc string, labels map[string]string) {
		if raw := col(colName, row); raw != "" {
			if v, ok := parseFloat(raw); ok {
				out = append(out, mk("proxy.haproxy."+metric, v, collector.MetricTypeCounter, unit, desc, labels))
			}
		}
	}

	httpClasses := []struct{ colName, code string }{
		{"hrsp_1xx", "1xx"},
		{"hrsp_2xx", "2xx"},
		{"hrsp_3xx", "3xx"},
		{"hrsp_4xx", "4xx"},
		{"hrsp_5xx", "5xx"},
	}

	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		pxname := col("pxname", row)
		svname := col("svname", row)
		if pxname == "" && svname == "" {
			continue
		}
		typ := classifyType(svname)
		labels := map[string]string{
			"haproxy_instance": baseLabels["haproxy_instance"],
			"haproxy_host":     baseLabels["haproxy_host"],
			"pxname":           pxname,
			"svname":           svname,
			"type":             typ,
		}

		emitGauge(row, "sessions_current", "scur", "", "Current sessions", labels)
		emitGauge(row, "sessions_max", "smax", "", "Max sessions", labels)
		emitCounter(row, "sessions_total", "stot", "", "Cumulative sessions", labels)
		emitCounter(row, "bytes_in_total", "bin", "bytes", "Bytes in", labels)
		emitCounter(row, "bytes_out_total", "bout", "bytes", "Bytes out", labels)
		emitCounter(row, "connection_errors_total", "econ", "", "Connection errors", labels)
		emitCounter(row, "response_errors_total", "eresp", "", "Response errors", labels)
		emitGauge(row, "server_weight", "weight", "", "Server weight", labels)

		for _, cls := range httpClasses {
			if raw := col(cls.colName, row); raw != "" {
				if v, ok := parseFloat(raw); ok {
					l := make(map[string]string, len(labels)+1)
					for k, val := range labels {
						l[k] = val
					}
					l["code"] = cls.code
					out = append(out, mk("proxy.haproxy.http_responses_total", v,
						collector.MetricTypeCounter, "", "HTTP responses by code class", l))
				}
			}
		}

		out = append(out, mk("proxy.haproxy.status", statusValue(col("status", row)),
			collector.MetricTypeGauge, "", "HAProxy status: 1=UP, 0=DOWN/MAINT", labels))

		if typ == "backend" {
			emitGauge(row, "active_servers", "act", "", "Active servers", labels)
			emitGauge(row, "backup_servers", "bck", "", "Backup servers", labels)
		}
	}
	return out
}

// classifyType maps an HAProxy svname to a row type label.
func classifyType(svname string) string {
	switch svname {
	case "FRONTEND":
		return "frontend"
	case "BACKEND":
		return "backend"
	default:
		return "server"
	}
}

// statusValue normalizes the HAProxy status field to 1 (UP/OPEN) or 0
// (DOWN/MAINT and anything else).
func statusValue(s string) float64 {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "UP", "OPEN":
		return 1
	default:
		return 0
	}
}

func parseFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// failureMetrics emits a single status=0 metric for an unreachable or
// unparseable HAProxy instance so operators can alert on the scrape failure.
func failureMetrics(inst config.HAProxyInstance, now time.Time) []collector.Metric {
	labels := instanceLabels(inst)
	m := collector.Metric{
		Name:        "proxy.haproxy.status",
		Type:        collector.MetricTypeGauge,
		Value:       0,
		Timestamp:   now,
		Description: "HAProxy status: 1=UP, 0=DOWN/MAINT",
		Labels:      make(map[string]string, len(labels)),
	}
	for k, v := range labels {
		m.Labels[k] = v
	}
	return []collector.Metric{m}
}

// instanceLabels builds the instance-level label set shared by all rows.
func instanceLabels(inst config.HAProxyInstance) map[string]string {
	host := ""
	if u, err := url.Parse(inst.URL); err == nil {
		host = u.Host
	}
	name := inst.Name
	if name == "" {
		name = inst.URL
	}
	return map[string]string{
		"haproxy_instance": name,
		"haproxy_host":     host,
	}
}

// Compile-time guard: HAProxyCollector satisfies collector.Collector.
var _ collector.Collector = (*HAProxyCollector)(nil)
