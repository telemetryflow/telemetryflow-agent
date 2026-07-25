// Package sflow exposes unexported symbols for external test packages so the
// listener loop can be driven from canned packets without binding a real UDP
// socket, and so the metric builder can be exercised directly.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package sflow

import (
	"net"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// PacketSourceExported abstracts the datagram source so tests can inject
// canned packets without touching the network. The signature mirrors
// net.PacketConn.ReadFrom so a real PacketConn (wrapped in
// packetSourceAdapter) satisfies it identically.
type PacketSourceExported interface {
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
}

// packetSourceAdapter adapts a net.PacketConn to PacketSourceExported and also
// exposes Close so Stop() can uniformly shut the source down.
type packetSourceAdapter struct {
	c net.PacketConn
}

func (a *packetSourceAdapter) ReadFrom(b []byte) (int, net.Addr, error) {
	return a.c.ReadFrom(b)
}

func (a *packetSourceAdapter) Close() error { return a.c.Close() }

// sourceCloser is the optional Close contract a PacketSourceExported may
// implement. Both packetSourceAdapter and test fakes implement it.
type sourceCloser interface {
	Close() error
}

// SetPacketSourceExported injects a fake source for tests. When set, Start()
// uses this source instead of opening a UDP socket. Passing nil restores
// production behavior (real net.ListenPacket on the next Start).
func (c *SflowCollector) SetPacketSourceExported(src PacketSourceExported) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.injectedSource = src
}

// CfgAddressExported returns the effective bind address after defaults.
func (c *SflowCollector) CfgAddressExported() string { return c.cfg.Address }

// CfgPortExported returns the effective UDP port after defaults.
func (c *SflowCollector) CfgPortExported() int { return c.cfg.Port }

// CfgProtocolExported returns the transport protocol after defaults.
func (c *SflowCollector) CfgProtocolExported() string { return c.cfg.Protocol }

// CfgWorkersExported returns the worker count after defaults.
func (c *SflowCollector) CfgWorkersExported() int { return c.cfg.Workers }

// CfgBufSizeExported returns the UDP read-buffer size after defaults.
func (c *SflowCollector) CfgBufSizeExported() int { return c.cfg.BufSize }

// CfgFlushIntervalExported returns the flush interval after defaults.
func (c *SflowCollector) CfgFlushIntervalExported() time.Duration { return c.cfg.FlushInterval }

// CounterSnapshotExported mirrors the internal snapshot struct so external
// tests can construct a snapshot by value.
type CounterSnapshotExported struct {
	Packets                uint64
	Samples                uint64
	Bytes                  uint64
	Errors                 uint64
	SamplesFlow            uint64
	SamplesCounter         uint64
	SamplesExpandedFlow    uint64
	SamplesExpandedCounter uint64
	SamplesUnknown         uint64
}

func (s CounterSnapshotExported) internal() snapshot {
	return snapshot{
		packets:                s.Packets,
		samples:                s.Samples,
		bytes:                  s.Bytes,
		errors:                 s.Errors,
		samplesFlow:            s.SamplesFlow,
		samplesCounter:         s.SamplesCounter,
		samplesExpandedFlow:    s.SamplesExpandedFlow,
		samplesExpandedCounter: s.SamplesExpandedCounter,
		samplesUnknown:         s.SamplesUnknown,
	}
}

// BuildSflowMetricsExported wraps buildSflowMetrics so external tests can
// drive the metric schema checks directly without spinning up the collector.
func BuildSflowMetricsExported(s CounterSnapshotExported, listener, agentIP string, tags map[string]string, now time.Time) []collector.Metric {
	return buildSflowMetrics(s.internal(), listener, agentIP, tags, now)
}

// PeekCountersExported returns a copy of the current per-window counters
// WITHOUT resetting them. Tests use it to poll for processing completion so
// they can call Collect() exactly once with deterministic results.
func (c *SflowCollector) PeekCountersExported() CounterSnapshotExported {
	return CounterSnapshotExported{
		Packets:                c.cnt.packetsReceived.Load(),
		Samples:                c.cnt.samplesReceived.Load(),
		Bytes:                  c.cnt.bytesReceived.Load(),
		Errors:                 c.cnt.parseErrors.Load(),
		SamplesFlow:            c.cnt.samplesFlow.Load(),
		SamplesCounter:         c.cnt.samplesCounter.Load(),
		SamplesExpandedFlow:    c.cnt.samplesExpandedFlow.Load(),
		SamplesExpandedCounter: c.cnt.samplesExpandedCounter.Load(),
		SamplesUnknown:         c.cnt.samplesUnknown.Load(),
	}
}
