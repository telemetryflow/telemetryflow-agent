// Package sflow implements a TelemetryFlow Agent network collector that
// receives sFlow v5 datagrams from network devices and emits aggregate
// counters under the network.sflow.* namespace.
//
// Service-style collector: Start() opens a UDP listener and spawns worker
// goroutines that parse incoming datagrams. Collect() snapshots and resets
// the per-window counters and emits them as metrics. Per-sample detailed
// metric emission is intentionally deferred (TODO) to avoid metric-volume
// explosions on high-traffic exporters.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package sflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "sflow"

// Documented defaults applied by NewSflowCollector when the corresponding
// config field is zero.
const (
	defaultAddress       = "0.0.0.0"
	defaultPort          = 6343
	defaultWorkers       = 4
	defaultBufSize       = 65535
	defaultFlushInterval = 30 * time.Second
)

// SflowCollector listens for sFlow v5 datagrams on a UDP socket and emits
// aggregate counters every Collect cycle.
type SflowCollector struct {
	cfg    config.SflowCollectorConfig
	logger *zap.Logger

	mu      sync.RWMutex
	running bool

	// injectedSource, when non-nil, replaces the real UDP socket in Start().
	// Used by tests to feed canned packets.
	injectedSource PacketSourceExported

	// activeSource holds whichever source Start() ends up using (the injected
	// fake or an adapter around a real net.PacketConn). It is closed by Stop.
	activeSource PacketSourceExported

	packets  chan []byte   // reader -> workers
	stopChan chan struct{} // closed by Stop to signal shutdown
	cancel   context.CancelFunc
	wg       sync.WaitGroup // tracks readLoop + workers

	// cnt holds per-window counters mutated by worker goroutines and snap-
	// shotted+reset by Collect(). All fields are atomic.
	cnt counters

	// agentIP holds the last successfully-decoded agent IP string. It is the
	// value used for the agent_ip metric label. sFlow deployments typically
	// have one agent per listener; for mixed-agent listeners this reflects
	// the most recent source.
	agentIP atomic.Value
}

// counters holds aggregate counters since the last Collect() snapshot.
type counters struct {
	packetsReceived atomic.Uint64
	samplesReceived atomic.Uint64
	bytesReceived   atomic.Uint64
	parseErrors     atomic.Uint64

	samplesFlow            atomic.Uint64
	samplesCounter         atomic.Uint64
	samplesExpandedFlow    atomic.Uint64
	samplesExpandedCounter atomic.Uint64
	samplesUnknown         atomic.Uint64
}

// snapshot is the per-window delta returned by snapshotAndReset().
type snapshot struct {
	packets uint64
	samples uint64
	bytes   uint64
	errors  uint64

	samplesFlow            uint64
	samplesCounter         uint64
	samplesExpandedFlow    uint64
	samplesExpandedCounter uint64
	samplesUnknown         uint64
}

// NewSflowCollector constructs an SflowCollector with documented defaults
// applied to every zero-valued config field.
func NewSflowCollector(cfg config.SflowCollectorConfig, logger *zap.Logger) *SflowCollector {
	applyDefaults(&cfg)
	return &SflowCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

// applyDefaults fills zero-valued fields with documented defaults.
func applyDefaults(cfg *config.SflowCollectorConfig) {
	if cfg.Address == "" {
		cfg.Address = defaultAddress
	}
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "udp"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.BufSize <= 0 {
		cfg.BufSize = defaultBufSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
}

func (c *SflowCollector) Name() string { return collectorName }

func (c *SflowCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// listenerAddr returns the configured "address:port" string used as the
// `listener` metric label.
func (c *SflowCollector) listenerAddr() string {
	return net.JoinHostPort(c.cfg.Address, fmt.Sprintf("%d", c.cfg.Port))
}

// Start binds the UDP listener (or installs the injected test source) and
// spawns the reader + worker goroutines.
func (c *SflowCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("sflow collector already running")
	}

	src := c.injectedSource
	if src == nil {
		conn, err := net.ListenPacket(c.cfg.Protocol, c.listenerAddr())
		if err != nil {
			return fmt.Errorf("sflow listen %s: %w", c.listenerAddr(), err)
		}
		if uc, ok := conn.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(c.cfg.BufSize)
		}
		src = &packetSourceAdapter{c: conn}
	}
	c.activeSource = src

	c.packets = make(chan []byte, capFor(c.cfg.Workers))
	c.stopChan = make(chan struct{})
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running = true

	c.wg.Add(1)
	go c.readLoop(runCtx, src)

	workers := c.cfg.Workers
	c.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go c.worker()
	}

	c.logger.Info("sFlow collector listening",
		zap.String("listener", c.listenerAddr()),
		zap.Int("workers", workers),
	)
	return nil
}

// capFor sizes the worker queue as a small multiple of the worker count so a
// short burst of datagrams does not block the reader.
func capFor(workers int) int {
	if workers <= 0 {
		return 16
	}
	cap := workers * 4
	if cap < 16 {
		cap = 16
	}
	return cap
}

// readLoop reads datagrams from the source, copies each into a fresh buffer,
// and dispatches to the worker queue. Returns when the source is closed or
// stopChan fires; closing the packets channel on exit unblocks the workers.
func (c *SflowCollector) readLoop(ctx context.Context, src PacketSourceExported) {
	defer c.wg.Done()
	defer close(c.packets)
	buf := make([]byte, c.cfg.BufSize)
	for {
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			if isClosed(err) || ctx.Err() != nil {
				return
			}
			c.logger.Debug("sFlow read error", zap.Error(err))
			continue
		}
		if n <= 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case c.packets <- pkt:
		case <-c.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// worker drains the packet queue and parses each datagram.
func (c *SflowCollector) worker() {
	defer c.wg.Done()
	for pkt := range c.packets {
		c.processPacket(pkt)
	}
}

// isClosed reports whether err is a socket-closed / context-canceled error.
func isClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// processPacket parses a single datagram and updates the per-window counters.
// Bytes and packets are always counted; parse errors increment parseErrors and
// short-circuit sample counting. On a successful parse every sample is bucketed
// by format and the agent IP is remembered for the agent_ip label.
func (c *SflowCollector) processPacket(pkt []byte) {
	c.cnt.packetsReceived.Add(1)
	c.cnt.bytesReceived.Add(uint64(len(pkt)))

	hdr, samples, err := ParseSflowV5(pkt)
	if err != nil {
		c.cnt.parseErrors.Add(1)
		c.logger.Debug("sflow parse error",
			zap.Error(err),
			zap.Int("bytes", len(pkt)))
		return
	}
	c.cnt.samplesReceived.Add(uint64(len(samples)))
	for _, s := range samples {
		switch sampleFormatName(s.Enterprise, s.FormatType) {
		case "flow":
			c.cnt.samplesFlow.Add(1)
		case "counter":
			c.cnt.samplesCounter.Add(1)
		case "expanded_flow":
			c.cnt.samplesExpandedFlow.Add(1)
		case "expanded_counter":
			c.cnt.samplesExpandedCounter.Add(1)
		default:
			c.cnt.samplesUnknown.Add(1)
		}
	}
	if hdr.AgentIP != "" {
		c.agentIP.Store(hdr.AgentIP)
	}
}

// sampleFormatName maps an sFlow sample's (enterprise, formatType) pair to the
// label used by network.sflow.samples_by_format. Enterprise-specific formats
// (enterprise != 0) or unrecognized standard formats collapse to "unknown".
func sampleFormatName(enterprise, formatType uint32) string {
	if enterprise != 0 {
		return "unknown"
	}
	switch formatType {
	case 1:
		return "flow"
	case 2:
		return "counter"
	case 3:
		return "expanded_flow"
	case 4:
		return "expanded_counter"
	default:
		return "unknown"
	}
}

// Collect snapshots and resets the per-window counters, then emits them as
// counter metrics under network.sflow.*. It is safe to call whether or not the
// collector is running.
func (c *SflowCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	snap := c.snapshotAndReset()
	return buildSflowMetrics(snap, c.listenerAddr(), c.loadAgentIP(), c.cfg.Tags, time.Now()), nil
}

// snapshotAndReset returns the per-window deltas and zeroes every counter.
// Each field is swapped independently, so a packet processed concurrently with
// the snapshot is attributed to exactly one of the two adjacent windows.
func (c *SflowCollector) snapshotAndReset() snapshot {
	return snapshot{
		packets:                c.cnt.packetsReceived.Swap(0),
		samples:                c.cnt.samplesReceived.Swap(0),
		bytes:                  c.cnt.bytesReceived.Swap(0),
		errors:                 c.cnt.parseErrors.Swap(0),
		samplesFlow:            c.cnt.samplesFlow.Swap(0),
		samplesCounter:         c.cnt.samplesCounter.Swap(0),
		samplesExpandedFlow:    c.cnt.samplesExpandedFlow.Swap(0),
		samplesExpandedCounter: c.cnt.samplesExpandedCounter.Swap(0),
		samplesUnknown:         c.cnt.samplesUnknown.Swap(0),
	}
}

// loadAgentIP returns the last-seen agent IP, or "" when no valid datagram has
// been parsed yet.
func (c *SflowCollector) loadAgentIP() string {
	if v := c.agentIP.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Stop closes the source, signals shutdown, and waits for the reader and all
// worker goroutines to exit. Idempotent and safe to call from multiple
// goroutines.
func (c *SflowCollector) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	close(c.stopChan)
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	src := c.activeSource
	c.activeSource = nil
	c.mu.Unlock()

	// Closing the source unblocks readLoop's ReadFrom. The fake sources used
	// in tests implement Close for the same reason.
	if src != nil {
		if closer, ok := src.(sourceCloser); ok {
			_ = closer.Close()
		}
	}
	c.wg.Wait()
	return nil
}

// buildSflowMetrics maps a per-window snapshot to the network.sflow.* metric
// namespace. It always emits the full set (including zero-valued format rows)
// so downstream dashboards have a stable schema. Collector-level tags and the
// decoded agent IP are folded into every metric as labels.
func buildSflowMetrics(s snapshot, listener, agentIP string, tags map[string]string, now time.Time) []collector.Metric {
	base := map[string]string{"listener": listener, "agent_ip": agentIP}
	for k, v := range tags {
		base[k] = v
	}
	mk := func(name string, v float64, desc string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        collector.MetricTypeCounter,
			Value:       v,
			Timestamp:   now,
			Description: desc,
			Labels:      make(map[string]string, len(base)),
		}
		for k, val := range base {
			m.Labels[k] = val
		}
		return m
	}
	mkFmt := func(format string, v float64) collector.Metric {
		m := mk("network.sflow.samples_by_format", v, "sFlow samples received by sample format")
		m.Labels["format"] = format
		return m
	}
	out := make([]collector.Metric, 0, 9)
	out = append(out,
		mk("network.sflow.packets_received_total", float64(s.packets),
			"UDP datagrams received since last collect"),
		mk("network.sflow.samples_received_total", float64(s.samples),
			"sFlow samples parsed since last collect"),
		mk("network.sflow.bytes_received_total", float64(s.bytes),
			"UDP payload bytes received since last collect"),
		mk("network.sflow.parse_errors_total", float64(s.errors),
			"Datagrams that failed to parse since last collect"),
		mkFmt("flow", float64(s.samplesFlow)),
		mkFmt("counter", float64(s.samplesCounter)),
		mkFmt("expanded_flow", float64(s.samplesExpandedFlow)),
		mkFmt("expanded_counter", float64(s.samplesExpandedCounter)),
		mkFmt("unknown", float64(s.samplesUnknown)),
	)
	return out
}

// Compile-time guard: SflowCollector satisfies the collector.Collector
// interface.
var _ collector.Collector = (*SflowCollector)(nil)
