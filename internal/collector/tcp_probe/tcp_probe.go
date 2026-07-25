// Package tcp_probe implements a TelemetryFlow Agent collector that performs
// lightweight TCP/UDP port probes against configured targets. For each target
// it records connect latency, optional banner-grab response time, and an
// up/down state gauge. Only the Go standard library is required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package tcp_probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "tcp_probe"

// DefaultProbeTimeout is used when a target omits Timeout.
const DefaultProbeTimeout = 5 * time.Second

// TCPProbeCollector probes one or more TCP/UDP endpoints.
type TCPProbeCollector struct {
	cfg      config.TCPProbeCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewTCPProbeCollector constructs a collector with sane defaults applied.
func NewTCPProbeCollector(cfg config.TCPProbeCollectorConfig, logger *zap.Logger) *TCPProbeCollector {
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if t.Protocol == "" {
			t.Protocol = "tcp"
		}
		if t.Timeout <= 0 {
			t.Timeout = DefaultProbeTimeout
		}
	}
	return &TCPProbeCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *TCPProbeCollector) Name() string { return collectorName }

func (c *TCPProbeCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *TCPProbeCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("tcp_probe collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("tcp_probe collector starting", zap.Int("targets", len(c.cfg.Targets)))
	return nil
}

func (c *TCPProbeCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one probe cycle across all configured targets.
func (c *TCPProbeCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Targets) == 0 {
		return nil, nil
	}
	now := time.Now()
	metrics := make([]collector.Metric, 0, len(c.cfg.Targets)*4)
	for _, tgt := range c.cfg.Targets {
		if err := ctx.Err(); err != nil {
			return metrics, err
		}
		r := probeTarget(ctx, tgt)
		metrics = append(metrics, buildMetrics(now, tgt, r)...)
	}
	return metrics, nil
}

// probeResult captures the outcome of probing a single target.
type probeResult struct {
	connectMs   float64
	responseMs  float64
	state       float64 // 1 open, 0 closed
	stringFound float64 // 0/1; meaningful only when Expect != ""
	err         error
}

func probeTarget(ctx context.Context, tgt config.TCPProbeTarget) probeResult {
	protocol := tgt.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	timeout := tgt.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	addr := net.JoinHostPort(tgt.Host, strconv.Itoa(tgt.Port))

	r := probeResult{}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Use a dialer that respects ctx so cancellation propagates to UDP too.
	dialer := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, protocol, addr)
	if err != nil {
		r.err = err
		return r
	}
	defer func() { _ = conn.Close() }()
	r.connectMs = float64(time.Since(start).Milliseconds())
	r.state = 1

	if tgt.Send == "" && tgt.Expect == "" {
		return r
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if tgt.Send != "" {
		if _, err := conn.Write([]byte(tgt.Send)); err != nil {
			r.err = err
			return r
		}
	}
	if tgt.Expect != "" {
		respStart := time.Now()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		r.responseMs = float64(time.Since(respStart).Milliseconds())
		if err != nil {
			r.err = err
			return r
		}
		if strings.Contains(string(buf[:n]), tgt.Expect) {
			r.stringFound = 1
		}
	}
	return r
}

func buildMetrics(now time.Time, tgt config.TCPProbeTarget, r probeResult) []collector.Metric {
	labels := map[string]string{
		"target":   tgt.Name,
		"host":     tgt.Host,
		"port":     strconv.Itoa(tgt.Port),
		"protocol": tgt.Protocol,
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
	out := []collector.Metric{
		mk("network.tcp.connect_time_ms", r.connectMs, "ms", "TCP/UDP connect latency in milliseconds"),
		mk("network.tcp.response_time_ms", r.responseMs, "ms", "Banner-grab response time in milliseconds (0 if no send/expect)"),
		mk("network.tcp.state", r.state, "", "Port state (1=open, 0=closed)"),
		mk("network.tcp.string_found", r.stringFound, "", "Whether expected substring was found in response (0/1)"),
	}
	return out
}
