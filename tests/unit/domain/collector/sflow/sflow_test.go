// Package sflow_test contains external unit tests for the sFlow v5 listener
// collector. Tests inject fakeSource instances so they run deterministically
// in CI without binding a real UDP socket.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package sflow_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/sflow"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// fakeSource is a PacketSourceExported stub used to feed canned datagrams into
// the collector's read loop. ReadFrom polls the queue, returns net.ErrClosed
// once Close is called, and never touches the network.
type fakeSource struct {
	mu     sync.Mutex
	queue  [][]byte
	closed chan struct{}
	once   sync.Once
}

func newFakeSource() *fakeSource {
	return &fakeSource{closed: make(chan struct{})}
}

func (f *fakeSource) push(p []byte) {
	f.mu.Lock()
	f.queue = append(f.queue, p)
	f.mu.Unlock()
}

func (f *fakeSource) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		if len(f.queue) > 0 {
			pkt := f.queue[0]
			f.queue = f.queue[1:]
			f.mu.Unlock()
			n := copy(b, pkt)
			return n, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, nil
		}
		f.mu.Unlock()
		select {
		case <-f.closed:
			return 0, nil, net.ErrClosed
		case <-time.After(time.Millisecond):
		}
	}
}

func (f *fakeSource) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// sflowSampleSpec describes one sample envelope to encode in a test datagram.
type sflowSampleSpec struct {
	formatType uint32 // written verbatim as the 32-bit format word (enterprise 0)
	bodyLen    uint32
}

// makeSflowIPv4 builds an sFlow v5 IPv4 datagram with the given agent IP,
// sequence, uptime, and sample envelopes. Sample bodies are zero bytes of
// bodyLen (they are not decoded by the M2.8 parser).
func makeSflowIPv4(t *testing.T, agentIP net.IP, sequence, uptime uint32, samples ...sflowSampleSpec) []byte {
	t.Helper()
	const hdrLen = 28 // version + ip_version + ipv4 + sub_agent + seq + uptime + num_samples
	bodyBytes := 0
	for _, s := range samples {
		bodyBytes += 8 + int(s.bodyLen)
	}
	buf := make([]byte, hdrLen+bodyBytes)
	putUint32(buf[0:4], 5) // version
	putUint32(buf[4:8], 1) // ip_version = IPv4
	ip4 := agentIP.To4()
	if ip4 == nil {
		t.Fatalf("agentIP not IPv4: %v", agentIP)
	}
	copy(buf[8:12], ip4)                        // agent IP
	putUint32(buf[12:16], 0)                    // sub_agent_id
	putUint32(buf[16:20], sequence)             // sequence_number
	putUint32(buf[20:24], uptime)               // uptime_ms
	putUint32(buf[24:28], uint32(len(samples))) // num_samples
	off := hdrLen
	for _, s := range samples {
		putUint32(buf[off:off+4], s.formatType)
		putUint32(buf[off+4:off+8], s.bodyLen)
		off += 8 + int(s.bodyLen)
	}
	return buf
}

// putUint32 writes v big-endian into b[0:4]. Local alias so the test stays
// focused on layout rather than importing encoding/binary at every call site.
func putUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func findFormatMetric(metrics []collector.Metric, format string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == "network.sflow.samples_by_format" && metrics[i].Labels["format"] == format {
			return &metrics[i]
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Parser tests
// -----------------------------------------------------------------------------

func TestParseSflowV5_IPv4SingleFlowSample(t *testing.T) {
	// One flow sample (format 1) — the kind that would carry raw_packet data.
	pkt := makeSflowIPv4(t,
		net.IPv4(10, 0, 0, 1),
		77, 5000,
		sflowSampleSpec{formatType: 1, bodyLen: 100},
	)
	hdr, samples, err := sflow.ParseSflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseSflowV5: %v", err)
	}
	if hdr.Version != 5 {
		t.Errorf("Version=%d want 5", hdr.Version)
	}
	if hdr.IPVersion != 1 {
		t.Errorf("IPVersion=%d want 1", hdr.IPVersion)
	}
	if hdr.AgentIP != "10.0.0.1" {
		t.Errorf("AgentIP=%q want 10.0.0.1", hdr.AgentIP)
	}
	if hdr.SubAgentID != 0 {
		t.Errorf("SubAgentID=%d want 0", hdr.SubAgentID)
	}
	if hdr.SequenceNumber != 77 {
		t.Errorf("SequenceNumber=%d want 77", hdr.SequenceNumber)
	}
	if hdr.UptimeMS != 5000 {
		t.Errorf("UptimeMS=%d want 5000", hdr.UptimeMS)
	}
	if hdr.NumSamples != 1 {
		t.Errorf("NumSamples=%d want 1", hdr.NumSamples)
	}
	if len(samples) != 1 {
		t.Fatalf("len(samples)=%d want 1", len(samples))
	}
	s := samples[0]
	if s.FormatType != 1 {
		t.Errorf("FormatType=%d want 1", s.FormatType)
	}
	if s.Enterprise != 0 {
		t.Errorf("Enterprise=%d want 0", s.Enterprise)
	}
	if s.Length != 100 {
		t.Errorf("Length=%d want 100", s.Length)
	}
}

func TestParseSflowV5_IPv6AgentIP(t *testing.T) {
	ip6 := net.ParseIP("2001:db8::1")
	// header: version + ip_version + ipv6(16) + sub_agent + seq + uptime + num = 40 bytes
	buf := make([]byte, 40)
	putUint32(buf[0:4], 5)
	putUint32(buf[4:8], 2) // IPv6
	copy(buf[8:24], ip6.To16())
	putUint32(buf[24:28], 0)
	putUint32(buf[28:32], 9)
	putUint32(buf[32:36], 6000)
	putUint32(buf[36:40], 0)
	hdr, samples, err := sflow.ParseSflowV5(buf)
	if err != nil {
		t.Fatalf("ParseSflowV5 IPv6: %v", err)
	}
	if hdr.IPVersion != 2 {
		t.Errorf("IPVersion=%d want 2", hdr.IPVersion)
	}
	if hdr.AgentIP != "2001:db8::1" {
		t.Errorf("AgentIP=%q want 2001:db8::1", hdr.AgentIP)
	}
	if len(samples) != 0 {
		t.Errorf("len(samples)=%d want 0", len(samples))
	}
}

func TestParseSflowV5_MultipleSamples(t *testing.T) {
	pkt := makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1,
		sflowSampleSpec{formatType: 1, bodyLen: 16},
		sflowSampleSpec{formatType: 2, bodyLen: 32},
		sflowSampleSpec{formatType: 3, bodyLen: 8},
	)
	hdr, samples, err := sflow.ParseSflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseSflowV5: %v", err)
	}
	if hdr.NumSamples != 3 || len(samples) != 3 {
		t.Fatalf("NumSamples=%d len(samples)=%d want 3/3", hdr.NumSamples, len(samples))
	}
	if samples[1].FormatType != 2 || samples[1].Length != 32 {
		t.Errorf("samples[1]=%+v want formatType=2 length=32", samples[1])
	}
}

func TestParseSflowV5_Truncated(t *testing.T) {
	// Header declares numSamples=1 but the sample envelope is chopped off.
	pkt := makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1, sflowSampleSpec{formatType: 1, bodyLen: 16})
	pkt = pkt[:28]
	_, _, err := sflow.ParseSflowV5(pkt)
	if err == nil {
		t.Fatal("expected error for truncated packet, got nil")
	}
}

func TestParseSflowV5_TruncatedSampleBody(t *testing.T) {
	// Sample header declares bodyLen=64 but the packet ends right after it.
	pkt := makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1, sflowSampleSpec{formatType: 1, bodyLen: 64})
	pkt = pkt[:36] // header(28) + sample header(8), no body
	_, _, err := sflow.ParseSflowV5(pkt)
	if err == nil {
		t.Fatal("expected error for truncated sample body, got nil")
	}
}

func TestParseSflowV5_ZeroSamples(t *testing.T) {
	pkt := makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1)
	hdr, samples, err := sflow.ParseSflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseSflowV5 zero samples: %v", err)
	}
	if hdr.NumSamples != 0 {
		t.Errorf("NumSamples=%d want 0", hdr.NumSamples)
	}
	if len(samples) != 0 {
		t.Errorf("len(samples)=%d want 0", len(samples))
	}
}

func TestParseSflowV5_ShortHeader(t *testing.T) {
	_, _, err := sflow.ParseSflowV5([]byte{0, 0, 0, 5}) // < 8 bytes
	if err == nil {
		t.Fatal("expected error for <8 byte packet, got nil")
	}
}

func TestParseSflowV5_WrongVersion(t *testing.T) {
	buf := make([]byte, 28)
	putUint32(buf[0:4], 4) // not 5
	putUint32(buf[4:8], 1)
	_, _, err := sflow.ParseSflowV5(buf)
	if err == nil {
		t.Fatal("expected error for non-v5 version, got nil")
	}
}

func TestParseSflowV5_BadIPVersion(t *testing.T) {
	buf := make([]byte, 28)
	putUint32(buf[0:4], 5)
	putUint32(buf[4:8], 9) // neither 1 nor 2
	_, _, err := sflow.ParseSflowV5(buf)
	if err == nil {
		t.Fatal("expected error for bad ip_version, got nil")
	}
}

// -----------------------------------------------------------------------------
// Collector lifecycle tests
// -----------------------------------------------------------------------------

func TestSflowCollector_Name(t *testing.T) {
	c := sflow.NewSflowCollector(config.SflowCollectorConfig{}, zap.NewNop())
	if c.Name() != "sflow" {
		t.Fatalf("Name()=%q want %q", c.Name(), "sflow")
	}
}

func TestSflowCollector_Defaults(t *testing.T) {
	c := sflow.NewSflowCollector(config.SflowCollectorConfig{}, zap.NewNop())
	cases := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Address", c.CfgAddressExported(), "0.0.0.0"},
		{"Port", c.CfgPortExported(), 6343},
		{"Protocol", c.CfgProtocolExported(), "udp"},
		{"Workers", c.CfgWorkersExported(), 4},
		{"BufSize", c.CfgBufSizeExported(), 65535},
		{"FlushInterval", c.CfgFlushIntervalExported(), 30 * time.Second},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s=%v want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestSflowCollector_LifecycleWithFakeSource(t *testing.T) {
	src := newFakeSource()
	c := sflow.NewSflowCollector(config.SflowCollectorConfig{
		Enabled: true,
		Tags:    map[string]string{"az": "us-east-1"},
	}, zap.NewNop())
	c.SetPacketSourceExported(src)

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("not running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double Start should fail")
	}

	// Two valid packets from the same agent.
	pkt1 := makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1000,
		sflowSampleSpec{formatType: 1, bodyLen: 64}, // one flow sample
	)
	pkt2 := makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 2, 2000,
		sflowSampleSpec{formatType: 1, bodyLen: 32}, // flow
		sflowSampleSpec{formatType: 2, bodyLen: 48}, // counter
	)
	// One garbage packet: too short to be a valid sFlow header.
	garbage := []byte{0x00, 0x00, 0x00}
	src.push(pkt1)
	src.push(pkt2)
	src.push(garbage)
	waitForPackets(t, c, 3)

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pkts := findMetric(metrics, "network.sflow.packets_received_total"); pkts == nil || pkts.Value != 3 {
		t.Fatalf("packets_received_total=%v want 3", valOr(pkts, -1))
	}
	// pkt1: 1 sample + pkt2: 2 samples + garbage: 0 = 3 samples.
	if samples := findMetric(metrics, "network.sflow.samples_received_total"); samples == nil || samples.Value != 3 {
		t.Fatalf("samples_received_total=%v want 3", valOr(samples, -1))
	}
	if errs := findMetric(metrics, "network.sflow.parse_errors_total"); errs == nil || errs.Value != 1 {
		t.Fatalf("parse_errors_total=%v want 1 (garbage only)", valOr(errs, -1))
	}
	wantBytes := float64(len(pkt1) + len(pkt2) + len(garbage))
	if bytes := findMetric(metrics, "network.sflow.bytes_received_total"); bytes == nil || bytes.Value != wantBytes {
		t.Fatalf("bytes_received_total=%v want %v", valOr(bytes, -1), wantBytes)
	}
	// flow samples: pkt1(1) + pkt2(1) = 2; counter samples: pkt2(1) = 1.
	if fm := findFormatMetric(metrics, "flow"); fm == nil || fm.Value != 2 {
		t.Fatalf("samples_by_format{flow}=%v want 2", valOr(fm, -1))
	}
	if cm := findFormatMetric(metrics, "counter"); cm == nil || cm.Value != 1 {
		t.Fatalf("samples_by_format{counter}=%v want 1", valOr(cm, -1))
	}
	// Listener + agent_ip labels.
	pkts := findMetric(metrics, "network.sflow.packets_received_total")
	if pkts.Labels["listener"] != "0.0.0.0:6343" {
		t.Errorf("listener label=%q want 0.0.0.0:6343", pkts.Labels["listener"])
	}
	if pkts.Labels["agent_ip"] != "10.0.0.1" {
		t.Errorf("agent_ip label=%q want 10.0.0.1", pkts.Labels["agent_ip"])
	}
	// Collector-level tag folded through.
	if pkts.Labels["az"] != "us-east-1" {
		t.Errorf("az tag=%q want us-east-1", pkts.Labels["az"])
	}
	// All metrics are counters.
	for _, m := range metrics {
		if m.Type != collector.MetricTypeCounter {
			t.Errorf("%s type=%v want counter", m.Name, m.Type)
		}
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("still running after Stop")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop should be a no-op, got: %v", err)
	}
}

func TestSflowCollector_CollectResetsCounters(t *testing.T) {
	src := newFakeSource()
	c := sflow.NewSflowCollector(config.SflowCollectorConfig{Enabled: true}, zap.NewNop())
	c.SetPacketSourceExported(src)
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	src.push(makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1, sflowSampleSpec{formatType: 1, bodyLen: 8}))
	waitForPackets(t, c, 1)

	first, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	if pkts := findMetric(first, "network.sflow.packets_received_total"); pkts == nil || pkts.Value != 1 {
		t.Fatalf("first Collect packets=%v want 1", valOr(pkts, -1))
	}

	// Second Collect with no new traffic must return zero deltas.
	second, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	for _, name := range []string{
		"network.sflow.packets_received_total",
		"network.sflow.samples_received_total",
		"network.sflow.bytes_received_total",
		"network.sflow.parse_errors_total",
	} {
		m := findMetric(second, name)
		if m == nil {
			t.Fatalf("second Collect missing %s", name)
		}
		if m.Value != 0 {
			t.Errorf("second Collect %s=%v want 0 (counters should reset)", name, m.Value)
		}
	}
}

func TestSflowCollector_AllFormatLabelsEmitted(t *testing.T) {
	src := newFakeSource()
	c := sflow.NewSflowCollector(config.SflowCollectorConfig{Enabled: true}, zap.NewNop())
	c.SetPacketSourceExported(src)
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	// One packet with one sample of each standard format plus an unknown.
	src.push(makeSflowIPv4(t, net.IPv4(10, 0, 0, 1), 1, 1,
		sflowSampleSpec{formatType: 1, bodyLen: 0},  // flow
		sflowSampleSpec{formatType: 2, bodyLen: 0},  // counter
		sflowSampleSpec{formatType: 3, bodyLen: 0},  // expanded_flow
		sflowSampleSpec{formatType: 4, bodyLen: 0},  // expanded_counter
		sflowSampleSpec{formatType: 99, bodyLen: 0}, // unknown
	))
	waitForPackets(t, c, 1)

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := map[string]float64{
		"flow":             1,
		"counter":          1,
		"expanded_flow":    1,
		"expanded_counter": 1,
		"unknown":          1,
	}
	for fmt, wantVal := range want {
		m := findFormatMetric(metrics, fmt)
		if m == nil {
			t.Errorf("missing samples_by_format{format=%s}", fmt)
			continue
		}
		if m.Value != wantVal {
			t.Errorf("samples_by_format{%s}=%v want %v", fmt, m.Value, wantVal)
		}
		if m.Labels["format"] != fmt {
			t.Errorf("samples_by_format{%s} format label=%q want %q", fmt, m.Labels["format"], fmt)
		}
	}
	if samples := findMetric(metrics, "network.sflow.samples_received_total"); samples == nil || samples.Value != 5 {
		t.Fatalf("samples_received_total=%v want 5", valOr(samples, -1))
	}
}

func TestSflowCollector_BuildMetricsSchema(t *testing.T) {
	snap := sflow.CounterSnapshotExported{
		Packets:                10,
		Samples:                25,
		Bytes:                  4000,
		Errors:                 2,
		SamplesFlow:            10,
		SamplesCounter:         8,
		SamplesExpandedFlow:    4,
		SamplesExpandedCounter: 2,
		SamplesUnknown:         1,
	}
	metrics := sflow.BuildSflowMetricsExported(snap, "0.0.0.0:6343", "10.0.0.1", nil, time.Now())
	want := map[string]float64{
		"network.sflow.packets_received_total": 10,
		"network.sflow.samples_received_total": 25,
		"network.sflow.bytes_received_total":   4000,
		"network.sflow.parse_errors_total":     2,
	}
	for name, wantVal := range want {
		m := findMetric(metrics, name)
		if m == nil {
			t.Errorf("missing %s", name)
			continue
		}
		if m.Value != wantVal {
			t.Errorf("%s=%v want %v", name, m.Value, wantVal)
		}
		if m.Type != collector.MetricTypeCounter {
			t.Errorf("%s type=%v want counter", name, m.Type)
		}
		if m.Labels["listener"] != "0.0.0.0:6343" {
			t.Errorf("%s listener=%q want 0.0.0.0:6343", name, m.Labels["listener"])
		}
		if m.Labels["agent_ip"] != "10.0.0.1" {
			t.Errorf("%s agent_ip=%q want 10.0.0.1", name, m.Labels["agent_ip"])
		}
	}
	formats := map[string]float64{
		"flow": 10, "counter": 8, "expanded_flow": 4, "expanded_counter": 2, "unknown": 1,
	}
	for fmt, wantVal := range formats {
		m := findFormatMetric(metrics, fmt)
		if m == nil {
			t.Errorf("missing samples_by_format{format=%s}", fmt)
			continue
		}
		if m.Value != wantVal {
			t.Errorf("samples_by_format{%s}=%v want %v", fmt, m.Value, wantVal)
		}
	}
}

func TestSflowCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*sflow.SflowCollector)(nil)
}

func TestSflowCollector_StopWithoutStartIsNoop(t *testing.T) {
	c := sflow.NewSflowCollector(config.SflowCollectorConfig{}, zap.NewNop())
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop before Start should be a no-op, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// test helpers
// -----------------------------------------------------------------------------

// waitForPackets polls PeekCountersExported until at least wantPackets have
// been received since the last Collect, or the deadline elapses. Peek does
// not reset counters, so this is safe to call before the real Collect.
func waitForPackets(t *testing.T, c *sflow.SflowCollector, wantPackets uint64) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if c.PeekCountersExported().Packets >= wantPackets {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	got := c.PeekCountersExported().Packets
	t.Fatalf("timed out waiting for %d packets, saw %d", wantPackets, got)
}

func valOr(m *collector.Metric, fallback float64) float64 {
	if m == nil {
		return fallback
	}
	return m.Value
}
