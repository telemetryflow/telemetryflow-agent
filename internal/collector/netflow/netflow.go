// Package netflow implements a TelemetryFlow Agent network collector that
// receives NetFlow v5/v9/IPFIX datagrams from network devices and emits
// aggregate counters under the network.netflow.* namespace.
//
// Service-style collector: Start() opens a UDP listener and spawns worker
// goroutines that parse incoming datagrams. Collect() snapshots and resets
// the per-window counters and emits them as metrics. Per-flow metric
// emission is intentionally deferred to a future version to avoid metric-
// volume explosions on high-traffic exporters.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package netflow

import (
	"context"
	"encoding/binary"
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

const collectorName = "netflow"

// Documented defaults applied by NewNetflowCollector when the corresponding
// config field is zero.
const (
	defaultAddress       = "0.0.0.0"
	defaultPort          = 2055
	defaultWorkers       = 4
	defaultBufSize       = 65535
	defaultFlushInterval = 30 * time.Second
)

// NetflowCollector listens for NetFlow v5/v9/IPFIX datagrams on a UDP socket
// and emits aggregate counters every Collect cycle.
type NetflowCollector struct {
	cfg    config.NetflowCollectorConfig
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
	// shotted+reset by Collect(). All fields are atomic; the brief cross-
	// field skew during a snapshot (a packet counted in packetsReceived but
	// not yet in pktsV5) is negligible at 30s granularity.
	cnt counters
}

// counters holds aggregate counters since the last Collect() snapshot.
type counters struct {
	packetsReceived atomic.Uint64
	flowsReceived   atomic.Uint64
	bytesReceived   atomic.Uint64
	parseErrors     atomic.Uint64

	pktsV5    atomic.Uint64
	pktsV9    atomic.Uint64
	pktsIPFIX atomic.Uint64
	pktsUnk   atomic.Uint64
}

// snapshot is the per-window delta returned by snapshotAndReset().
type snapshot struct {
	packets   uint64
	flows     uint64
	bytes     uint64
	errors    uint64
	pktsV5    uint64
	pktsV9    uint64
	pktsIPFIX uint64
	pktsUnk   uint64
}

// NewNetflowCollector constructs a NetflowCollector with documented defaults
// applied to every zero-valued config field.
func NewNetflowCollector(cfg config.NetflowCollectorConfig, logger *zap.Logger) *NetflowCollector {
	applyDefaults(&cfg)
	return &NetflowCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

// applyDefaults fills zero-valued fields with documented defaults.
func applyDefaults(cfg *config.NetflowCollectorConfig) {
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
	if len(cfg.Protocols) == 0 {
		cfg.Protocols = []string{"5", "9", "ipfix"}
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
}

func (c *NetflowCollector) Name() string { return collectorName }

func (c *NetflowCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// listenerAddr returns the configured "address:port" string used as the
// `listener` metric label.
func (c *NetflowCollector) listenerAddr() string {
	return net.JoinHostPort(c.cfg.Address, fmt.Sprintf("%d", c.cfg.Port))
}

// Start binds the UDP listener (or installs the injected test source) and
// spawns the reader + worker goroutines.
func (c *NetflowCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("netflow collector already running")
	}

	src := c.injectedSource
	if src == nil {
		conn, err := net.ListenPacket(c.cfg.Protocol, c.listenerAddr())
		if err != nil {
			return fmt.Errorf("netflow listen %s: %w", c.listenerAddr(), err)
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

	c.logger.Info("NetFlow collector listening",
		zap.String("listener", c.listenerAddr()),
		zap.Int("workers", workers),
		zap.Strings("protocols", c.cfg.Protocols),
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
func (c *NetflowCollector) readLoop(ctx context.Context, src PacketSourceExported) {
	defer c.wg.Done()
	defer close(c.packets)
	buf := make([]byte, c.cfg.BufSize)
	for {
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			if isClosed(err) || ctx.Err() != nil {
				return
			}
			c.logger.Debug("NetFlow read error", zap.Error(err))
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
func (c *NetflowCollector) worker() {
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
// Version routing:
//   - v5: parse header+records, count flows; on parse failure increment
//     parse_errors but still count the packet under v5.
//   - v9 / IPFIX: header-only inspection today; full template parsing is a
//     TODO. Packets and bytes are still counted.
//   - anything else: count under "unknown" and bump parse_errors.
func (c *NetflowCollector) processPacket(pkt []byte) {
	c.cnt.packetsReceived.Add(1)

	var version uint16
	if len(pkt) >= 2 {
		version = binary.BigEndian.Uint16(pkt[0:2])
	}

	switch version {
	case VersionNetflowV5:
		_, flows, err := ParseNetflowV5(pkt)
		if err != nil {
			c.cnt.parseErrors.Add(1)
			c.logger.Debug("netflow v5 parse error",
				zap.Error(err),
				zap.Int("bytes", len(pkt)))
		} else {
			c.cnt.flowsReceived.Add(uint64(len(flows)))
		}
		c.cnt.bytesReceived.Add(uint64(len(pkt)))
		c.cnt.pktsV5.Add(1)
	case VersionNetflowV9:
		// TODO(netflow): implement NetFlow v9 template-store parsing.
		// Until then count traffic so operators can see exporter activity.
		c.cnt.bytesReceived.Add(uint64(len(pkt)))
		c.cnt.pktsV9.Add(1)
	case VersionNetflowIPFIX:
		// TODO(netflow): implement IPFIX (RFC 7011) template parsing.
		c.cnt.bytesReceived.Add(uint64(len(pkt)))
		c.cnt.pktsIPFIX.Add(1)
	default:
		c.cnt.parseErrors.Add(1)
		c.cnt.pktsUnk.Add(1)
		if len(pkt) >= 2 {
			c.logger.Debug("netflow unknown version", zap.Uint16("version", version))
		}
	}
}

// Collect snapshots and resets the per-window counters, then emits them as
// counter metrics under network.netflow.*. It is safe to call whether or not
// the collector is running.
func (c *NetflowCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	snap := c.snapshotAndReset()
	return buildNetflowMetrics(snap, c.listenerAddr(), time.Now()), nil
}

// snapshotAndReset returns the per-window deltas and zeroes every counter.
// Each field is swapped independently, so a packet processed concurrently
// with the snapshot is attributed to exactly one of the two adjacent windows.
func (c *NetflowCollector) snapshotAndReset() snapshot {
	return snapshot{
		packets:   c.cnt.packetsReceived.Swap(0),
		flows:     c.cnt.flowsReceived.Swap(0),
		bytes:     c.cnt.bytesReceived.Swap(0),
		errors:    c.cnt.parseErrors.Swap(0),
		pktsV5:    c.cnt.pktsV5.Swap(0),
		pktsV9:    c.cnt.pktsV9.Swap(0),
		pktsIPFIX: c.cnt.pktsIPFIX.Swap(0),
		pktsUnk:   c.cnt.pktsUnk.Swap(0),
	}
}

// Stop closes the source, signals shutdown, and waits for the reader and all
// worker goroutines to exit. Idempotent and safe to call from multiple
// goroutines.
func (c *NetflowCollector) Stop() error {
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

// buildNetflowMetrics maps a per-window snapshot to the network.netflow.*
// metric namespace. It always emits the full set (including zero-valued
// version rows) so downstream dashboards have a stable schema.
func buildNetflowMetrics(s snapshot, listener string, now time.Time) []collector.Metric {
	base := map[string]string{"listener": listener}
	// Fold collector-level tags into base at call sites when needed; the
	// listener label is the primary dimension here.
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
	mkVer := func(version string, v float64) collector.Metric {
		m := mk("network.netflow.packets_by_version", v, "Datagrams received by NetFlow version")
		m.Labels["version"] = version
		return m
	}
	out := make([]collector.Metric, 0, 8)
	out = append(out,
		mk("network.netflow.packets_received_total", float64(s.packets),
			"UDP datagrams received since last collect"),
		mk("network.netflow.flows_received_total", float64(s.flows),
			"NetFlow records parsed since last collect"),
		mk("network.netflow.bytes_received_total", float64(s.bytes),
			"UDP payload bytes received since last collect"),
		mk("network.netflow.parse_errors_total", float64(s.errors),
			"Datagrams that failed to parse since last collect"),
		mkVer("5", float64(s.pktsV5)),
		mkVer("9", float64(s.pktsV9)),
		mkVer("ipfix", float64(s.pktsIPFIX)),
		mkVer("unknown", float64(s.pktsUnk)),
	)
	return out
}

// Compile-time guard: NetflowCollector satisfies the collector.Collector
// interface.
var _ collector.Collector = (*NetflowCollector)(nil)
