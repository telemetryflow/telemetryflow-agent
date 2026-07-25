// Package netflow_test contains external unit tests for the NetFlow v5/v9/IPFIX
// listener collector. Tests inject fakeSource instances so they run
// deterministically in CI without binding a real UDP socket.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package netflow_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/netflow"
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

// v5FlowInput is the test-side input used by makeV5Packet to construct a
// single NetFlow v5 record.
type v5FlowInput struct {
	srcaddr, dstaddr, nexthop net.IP
	input, output             uint16
	packets, octets           uint32
	first, last               uint32
	srcport, dstport          uint16
	tcpFlags, protocol, tos   uint8
	srcAS, dstAS              uint16
	srcMask, dstMask          uint8
}

// makeV5Packet encodes a NetFlow v5 packet with the given flow records. The
// produced bytes are ready to feed into ParseNetflowV5 or fakeSource.push.
func makeV5Packet(t *testing.T, records ...v5FlowInput) []byte {
	t.Helper()
	buf := make([]byte, 24+48*len(records))
	binaryPutUint16(buf[0:2], 5) // version
	binaryPutUint16(buf[2:4], uint16(len(records)))
	binaryPutUint32(buf[4:8], 1000)        // sysuptime ms
	binaryPutUint32(buf[8:12], 1700000000) // unix secs
	binaryPutUint32(buf[12:16], 0)         // nsecs
	binaryPutUint32(buf[16:20], 42)        // flow sequence
	buf[20] = 1                            // engine type
	buf[21] = 2                            // engine id
	binaryPutUint16(buf[22:24], 0)         // sampling interval
	for i, r := range records {
		off := 24 + i*48
		rec := buf[off : off+48]
		copy(rec[0:4], r.srcaddr.To4())
		copy(rec[4:8], r.dstaddr.To4())
		copy(rec[8:12], r.nexthop.To4())
		binaryPutUint16(rec[12:14], r.input)
		binaryPutUint16(rec[14:16], r.output)
		binaryPutUint32(rec[16:20], r.packets)
		binaryPutUint32(rec[20:24], r.octets)
		binaryPutUint32(rec[24:28], r.first)
		binaryPutUint32(rec[28:32], r.last)
		binaryPutUint16(rec[32:34], r.srcport)
		binaryPutUint16(rec[34:36], r.dstport)
		rec[37] = r.tcpFlags
		rec[38] = r.protocol
		rec[39] = r.tos
		binaryPutUint16(rec[40:42], r.srcAS)
		binaryPutUint16(rec[42:44], r.dstAS)
		rec[44] = r.srcMask
		rec[45] = r.dstMask
	}
	return buf
}

// binaryPutUint16 / binaryPutUint32 are local aliases to avoid importing
// encoding/binary across many call sites; they also keep the test focused on
// layout rather than helper plumbing.
func binaryPutUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func binaryPutUint32(b []byte, v uint32) {
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

func findVersionMetric(metrics []collector.Metric, version string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == "network.netflow.packets_by_version" && metrics[i].Labels["version"] == version {
			return &metrics[i]
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Parser tests
// -----------------------------------------------------------------------------

func TestParseNetflowV5_SingleFlow(t *testing.T) {
	pkt := makeV5Packet(t, v5FlowInput{
		srcaddr:  net.IPv4(10, 0, 0, 1),
		dstaddr:  net.IPv4(192, 168, 1, 100),
		nexthop:  net.IPv4(10, 0, 0, 254),
		input:    1,
		output:   2,
		packets:  42,
		octets:   4096,
		first:    100,
		last:     200,
		srcport:  12345,
		dstport:  80,
		tcpFlags: 0x10, // ACK
		protocol: 6,    // TCP
		tos:      0,
		srcAS:    64512,
		dstAS:    64513,
		srcMask:  24,
		dstMask:  32,
	})
	hdr, flows, err := netflow.ParseNetflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseNetflowV5: %v", err)
	}
	if hdr.Version != 5 {
		t.Errorf("hdr.Version=%d want 5", hdr.Version)
	}
	if hdr.Count != 1 {
		t.Errorf("hdr.Count=%d want 1", hdr.Count)
	}
	if hdr.SysUptime != 1000 {
		t.Errorf("hdr.SysUptime=%d want 1000", hdr.SysUptime)
	}
	if hdr.UnixSeconds != 1700000000 {
		t.Errorf("hdr.UnixSeconds=%d want 1700000000", hdr.UnixSeconds)
	}
	if hdr.FlowSequence != 42 {
		t.Errorf("hdr.FlowSequence=%d want 42", hdr.FlowSequence)
	}
	if hdr.EngineType != 1 || hdr.EngineID != 2 {
		t.Errorf("engine type/id=%d/%d want 1/2", hdr.EngineType, hdr.EngineID)
	}
	if len(flows) != 1 {
		t.Fatalf("len(flows)=%d want 1", len(flows))
	}
	f := flows[0]
	if got, want := f.SrcAddr.String(), "10.0.0.1"; got != want {
		t.Errorf("SrcAddr=%s want %s", got, want)
	}
	if got, want := f.DstAddr.String(), "192.168.1.100"; got != want {
		t.Errorf("DstAddr=%s want %s", got, want)
	}
	if got, want := f.NextHop.String(), "10.0.0.254"; got != want {
		t.Errorf("NextHop=%s want %s", got, want)
	}
	if f.Input != 1 || f.Output != 2 {
		t.Errorf("Input/Output=%d/%d want 1/2", f.Input, f.Output)
	}
	if f.Packets != 42 || f.Octets != 4096 {
		t.Errorf("Packets/Octets=%d/%d want 42/4096", f.Packets, f.Octets)
	}
	if f.SrcPort != 12345 || f.DstPort != 80 {
		t.Errorf("SrcPort/DstPort=%d/%d want 12345/80", f.SrcPort, f.DstPort)
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol=%d want 6", f.Protocol)
	}
	if f.TCPFlags != 0x10 {
		t.Errorf("TCPFlags=0x%x want 0x10", f.TCPFlags)
	}
	if f.SrcAS != 64512 || f.DstAS != 64513 {
		t.Errorf("SrcAS/DstAS=%d/%d want 64512/64513", f.SrcAS, f.DstAS)
	}
	if f.SrcMask != 24 || f.DstMask != 32 {
		t.Errorf("SrcMask/DstMask=%d/%d want 24/32", f.SrcMask, f.DstMask)
	}
}

func TestParseNetflowV5_IPFieldsDoNotAliasPacket(t *testing.T) {
	pkt := makeV5Packet(t, v5FlowInput{
		srcaddr:  net.IPv4(10, 0, 0, 1),
		dstaddr:  net.IPv4(10, 0, 0, 2),
		nexthop:  net.IPv4(10, 0, 0, 254),
		protocol: 17,
	})
	_, flows, err := netflow.ParseNetflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseNetflowV5: %v", err)
	}
	// Mutate the source packet; parsed IPs must be unaffected.
	for i := range pkt {
		pkt[i] = 0xff
	}
	if got := flows[0].SrcAddr.String(); got != "10.0.0.1" {
		t.Errorf("SrcAddr changed after packet mutation: %s", got)
	}
}

func TestParseNetflowV5_TruncatedHeader(t *testing.T) {
	short := make([]byte, 23) // one byte shy of the 24-byte header
	_, _, err := netflow.ParseNetflowV5(short)
	if err == nil {
		t.Fatal("expected error for short header, got nil")
	}
}

func TestParseNetflowV5_TruncatedRecord(t *testing.T) {
	// Header declares count=1 (needs 24+48=72 bytes) but the packet only
	// carries the 24-byte header.
	pkt := make([]byte, 24)
	binaryPutUint16(pkt[0:2], 5)
	binaryPutUint16(pkt[2:4], 1)
	_, _, err := netflow.ParseNetflowV5(pkt)
	if err == nil {
		t.Fatal("expected error for truncated record, got nil")
	}
}

func TestParseNetflowV5_ZeroCount(t *testing.T) {
	pkt := make([]byte, 24)
	binaryPutUint16(pkt[0:2], 5)
	binaryPutUint16(pkt[2:4], 0)
	hdr, flows, err := netflow.ParseNetflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseNetflowV5 with count=0: %v", err)
	}
	if hdr.Count != 0 {
		t.Errorf("hdr.Count=%d want 0", hdr.Count)
	}
	if len(flows) != 0 {
		t.Errorf("len(flows)=%d want 0", len(flows))
	}
}

func TestParseNetflowV5_CountExceedsMax(t *testing.T) {
	pkt := make([]byte, 24)
	binaryPutUint16(pkt[0:2], 5)
	binaryPutUint16(pkt[2:4], 31) // v5 max is 30
	_, _, err := netflow.ParseNetflowV5(pkt)
	if err == nil {
		t.Fatal("expected error for count>30, got nil")
	}
}

func TestParseNetflowV5_WrongVersion(t *testing.T) {
	pkt := make([]byte, 24)
	binaryPutUint16(pkt[0:2], 9) // v9 fed into v5 parser
	binaryPutUint16(pkt[2:4], 0)
	_, _, err := netflow.ParseNetflowV5(pkt)
	if err == nil {
		t.Fatal("expected error for non-v5 version, got nil")
	}
}

func TestParseNetflowV5_MultipleFlows(t *testing.T) {
	pkt := makeV5Packet(t,
		v5FlowInput{srcaddr: net.IPv4(1, 1, 1, 1), dstaddr: net.IPv4(2, 2, 2, 2), packets: 1, octets: 100, protocol: 6},
		v5FlowInput{srcaddr: net.IPv4(3, 3, 3, 3), dstaddr: net.IPv4(4, 4, 4, 4), packets: 2, octets: 200, protocol: 17},
		v5FlowInput{srcaddr: net.IPv4(5, 5, 5, 5), dstaddr: net.IPv4(6, 6, 6, 6), packets: 3, octets: 300, protocol: 6},
	)
	hdr, flows, err := netflow.ParseNetflowV5(pkt)
	if err != nil {
		t.Fatalf("ParseNetflowV5: %v", err)
	}
	if hdr.Count != 3 || len(flows) != 3 {
		t.Fatalf("hdr.Count=%d len(flows)=%d want 3/3", hdr.Count, len(flows))
	}
	if flows[1].Protocol != 17 {
		t.Errorf("flows[1].Protocol=%d want 17", flows[1].Protocol)
	}
	if flows[2].Octets != 300 {
		t.Errorf("flows[2].Octets=%d want 300", flows[2].Octets)
	}
}

// -----------------------------------------------------------------------------
// Collector lifecycle tests
// -----------------------------------------------------------------------------

func TestNetflowCollector_Name(t *testing.T) {
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{}, zap.NewNop())
	if c.Name() != "netflow" {
		t.Fatalf("Name()=%q want %q", c.Name(), "netflow")
	}
}

func TestNetflowCollector_Defaults(t *testing.T) {
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{}, zap.NewNop())
	cases := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Address", c.CfgAddressExported(), "0.0.0.0"},
		{"Port", c.CfgPortExported(), 2055},
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
	protos := c.CfgProtocolsExported()
	if len(protos) != 3 || protos[0] != "5" || protos[1] != "9" || protos[2] != "ipfix" {
		t.Errorf("Protocols=%v want [5 9 ipfix]", protos)
	}
}

func TestNetflowCollector_LifecycleWithFakeSource(t *testing.T) {
	src := newFakeSource()
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{
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

	pkt1 := makeV5Packet(t, v5FlowInput{
		srcaddr: net.IPv4(10, 0, 0, 1), dstaddr: net.IPv4(10, 0, 0, 2),
		nexthop: net.IPv4(10, 0, 0, 254), protocol: 6, packets: 10, octets: 500,
		srcport: 33000, dstport: 443,
	})
	pkt2 := makeV5Packet(t,
		v5FlowInput{srcaddr: net.IPv4(10, 0, 0, 3), dstaddr: net.IPv4(10, 0, 0, 4), protocol: 17, packets: 5, octets: 200},
		v5FlowInput{srcaddr: net.IPv4(10, 0, 0, 5), dstaddr: net.IPv4(10, 0, 0, 6), protocol: 6, packets: 8, octets: 900},
	)
	src.push(pkt1)
	src.push(pkt2)
	// Let the read loop (1ms poll) + worker pool fully drain both datagrams
	// before snapshotting. settle() polls Collect internally and only returns
	// once both packets show up, so timing is deterministic rather than fixed.
	waitForPackets(t, c, 2)

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pkts := findMetric(metrics, "network.netflow.packets_received_total"); pkts == nil || pkts.Value != 2 {
		var got float64 = -1
		if pkts != nil {
			got = pkts.Value
		}
		t.Fatalf("packets_received_total=%v want 2", got)
	}
	if flows := findMetric(metrics, "network.netflow.flows_received_total"); flows == nil || flows.Value != 3 {
		var got float64 = -1
		if flows != nil {
			got = flows.Value
		}
		t.Fatalf("flows_received_total=%v want 3 (1+2 records)", got)
	}
	if errs := findMetric(metrics, "network.netflow.parse_errors_total"); errs == nil || errs.Value != 0 {
		var got float64 = -1
		if errs != nil {
			got = errs.Value
		}
		t.Fatalf("parse_errors_total=%v want 0", got)
	}
	if v := findVersionMetric(metrics, "5"); v == nil || v.Value != 2 {
		var got float64 = -1
		if v != nil {
			got = v.Value
		}
		t.Fatalf("packets_by_version{5}=%v want 2", got)
	}
	// Listener label must be the configured address:port.
	if l := findMetric(metrics, "network.netflow.packets_received_total").Labels["listener"]; l != "0.0.0.0:2055" {
		t.Errorf("listener label=%q want 0.0.0.0:2055", l)
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

func TestNetflowCollector_CollectResetsCounters(t *testing.T) {
	src := newFakeSource()
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{Enabled: true}, zap.NewNop())
	c.SetPacketSourceExported(src)
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	src.push(makeV5Packet(t, v5FlowInput{
		srcaddr: net.IPv4(1, 1, 1, 1), dstaddr: net.IPv4(2, 2, 2, 2),
		nexthop: net.IPv4(1, 1, 1, 254), protocol: 6,
	}))
	waitForPackets(t, c, 1)

	first, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	if pkts := findMetric(first, "network.netflow.packets_received_total"); pkts == nil || pkts.Value != 1 {
		t.Fatalf("first Collect packets=%v want 1", valOr(pkts, -1))
	}

	// Second Collect with no new traffic must return zero deltas.
	second, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	for _, name := range []string{
		"network.netflow.packets_received_total",
		"network.netflow.flows_received_total",
		"network.netflow.bytes_received_total",
		"network.netflow.parse_errors_total",
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

func TestNetflowCollector_ParseErrorOnGarbage(t *testing.T) {
	src := newFakeSource()
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{Enabled: true}, zap.NewNop())
	c.SetPacketSourceExported(src)
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	// Unknown version 0xffff -> unknown bucket + parse error.
	src.push([]byte{0xff, 0xff, 0x00, 0x00})
	// Truncated v5 body -> v5 bucket + parse error.
	trunc := make([]byte, 24)
	binaryPutUint16(trunc[0:2], 5)
	binaryPutUint16(trunc[2:4], 1)
	src.push(trunc)
	waitForPackets(t, c, 2)

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pkts := findMetric(metrics, "network.netflow.packets_received_total"); pkts == nil || pkts.Value != 2 {
		t.Fatalf("packets_received_total=%v want 2", valOr(pkts, -1))
	}
	if errs := findMetric(metrics, "network.netflow.parse_errors_total"); errs == nil || errs.Value != 2 {
		t.Fatalf("parse_errors_total=%v want 2", valOr(errs, -1))
	}
	if v := findVersionMetric(metrics, "unknown"); v == nil || v.Value != 1 {
		t.Fatalf("packets_by_version{unknown}=%v want 1", valOr(v, -1))
	}
	if v := findVersionMetric(metrics, "5"); v == nil || v.Value != 1 {
		t.Fatalf("packets_by_version{5}=%v want 1 (truncated still labeled v5)", valOr(v, -1))
	}
	if flows := findMetric(metrics, "network.netflow.flows_received_total"); flows == nil || flows.Value != 0 {
		t.Fatalf("flows_received_total=%v want 0 (no successful parses)", valOr(flows, -1))
	}
}

func TestNetflowCollector_V9AndIPFIXIncrementVersionCounters(t *testing.T) {
	src := newFakeSource()
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{Enabled: true}, zap.NewNop())
	c.SetPacketSourceExported(src)
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	v9 := make([]byte, 20)
	binaryPutUint16(v9[0:2], 9)
	ipfix := make([]byte, 16)
	binaryPutUint16(ipfix[0:2], 10)
	src.push(v9)
	src.push(ipfix)
	waitForPackets(t, c, 2)

	metrics, _ := c.Collect(context.Background())
	if v := findVersionMetric(metrics, "9"); v == nil || v.Value != 1 {
		t.Fatalf("packets_by_version{9}=%v want 1", valOr(v, -1))
	}
	if v := findVersionMetric(metrics, "ipfix"); v == nil || v.Value != 1 {
		t.Fatalf("packets_by_version{ipfix}=%v want 1", valOr(v, -1))
	}
	if errs := findMetric(metrics, "network.netflow.parse_errors_total"); errs == nil || errs.Value != 0 {
		t.Errorf("parse_errors_total=%v want 0 (v9/ipfix header-only is not an error)", valOr(errs, -1))
	}
}

func TestNetflowCollector_BuildMetricsSchema(t *testing.T) {
	snap := netflow.CounterSnapshotExported{
		Packets:   10,
		Flows:     120,
		Bytes:     6000,
		Errors:    1,
		PktsV5:    8,
		PktsV9:    1,
		PktsIPFIX: 1,
		PktsUnk:   0,
	}
	metrics := netflow.BuildNetflowMetricsExported(snap, "0.0.0.0:2055", time.Now())
	want := map[string]float64{
		"network.netflow.packets_received_total": 10,
		"network.netflow.flows_received_total":   120,
		"network.netflow.bytes_received_total":   6000,
		"network.netflow.parse_errors_total":     1,
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
		if m.Labels["listener"] != "0.0.0.0:2055" {
			t.Errorf("%s listener=%q want 0.0.0.0:2055", name, m.Labels["listener"])
		}
	}
	versions := map[string]float64{"5": 8, "9": 1, "ipfix": 1, "unknown": 0}
	for ver, wantVal := range versions {
		m := findVersionMetric(metrics, ver)
		if m == nil {
			t.Errorf("missing packets_by_version{version=%s}", ver)
			continue
		}
		if m.Value != wantVal {
			t.Errorf("packets_by_version{%s}=%v want %v", ver, m.Value, wantVal)
		}
		if m.Labels["version"] != ver {
			t.Errorf("packets_by_version version label=%q want %q", m.Labels["version"], ver)
		}
	}
}

func TestNetflowCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*netflow.NetflowCollector)(nil)
}

func TestNetflowCollector_StopWithoutStartIsNoop(t *testing.T) {
	c := netflow.NewNetflowCollector(config.NetflowCollectorConfig{}, zap.NewNop())
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
func waitForPackets(t *testing.T, c *netflow.NetflowCollector, wantPackets uint64) {
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
