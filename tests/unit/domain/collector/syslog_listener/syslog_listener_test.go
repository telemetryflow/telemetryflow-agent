// Package syslog_listener_test contains external unit tests for the
// syslog_listener collector. Tests inject fake LineSourceExported sources so
// they run deterministically without binding real UDP/TCP sockets.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package syslog_listener_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/syslog_listener"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- fake source -----------------------------------------------------------

// fakeSource is a test double for syslog_listener.LineSourceExported. It
// returns pre-loaded messages one at a time, then io.EOF.
type fakeSource struct {
	mu    sync.Mutex
	msgs  [][]byte
	idx   int
	calls int
}

func newFakeSource(msgs ...string) *fakeSource {
	buf := make([][]byte, len(msgs))
	for i, m := range msgs {
		buf[i] = []byte(m)
	}
	return &fakeSource{msgs: buf}
}

func (f *fakeSource) Next() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	data := f.msgs[f.idx]
	f.idx++
	return data, nil
}

func (f *fakeSource) Close() error { return nil }

// --- helpers ---------------------------------------------------------------

const (
	rfc3164Line = "<134>Oct 11 22:14:15 mymachine app: hello world"
	rfc5424Line = "<134>1 2024-01-15T14:32:01Z mymachine app 1234 - - hello world"
	garbageLine = "this is total garbage with no priority"
)

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func findMetricByLabel(metrics []collector.Metric, name, label, value string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name != name {
			continue
		}
		if metrics[i].Labels[label] == value {
			return &metrics[i]
		}
	}
	return nil
}

// newCollectorWithFakes wires a collector whose source factory hands out the
// provided fake source per listener. Start() is invoked and the reader
// goroutines are drained before returning so the caller can Collect()
// deterministically.
func newCollectorWithFakes(t *testing.T, cfg config.SyslogListenerConfig, sources ...*fakeSource) *syslog_listener.SyslogListenerCollector {
	t.Helper()
	c := syslog_listener.NewSyslogListenerCollector(cfg, zap.NewNop())
	idx := 0
	c.SetLineSourceFactoryExported(func(_ config.SyslogListener) (syslog_listener.LineSourceExported, error) {
		src := sources[idx]
		idx++
		return src, nil
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop() })
	c.WaitForReadersExported()
	return c
}

// --- parser tests ----------------------------------------------------------

func TestNewParser_RFC3164(t *testing.T) {
	p, err := syslog_listener.NewParserExported("rfc3164", "UTC")
	require.NoError(t, err)
	msg, err := p.Parse([]byte(rfc3164Line))
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.True(t, msg.Valid())

	// <134> = facility 16 (local0) * 8 + severity 6 (informational -> info)
	assert.Equal(t, "info", syslog_listener.SeverityLabelExported(msg), "severity label")
	assert.Equal(t, "local0", syslog_listener.FacilityLabelExported(msg), "facility label")
}

func TestNewParser_RFC5424(t *testing.T) {
	p, err := syslog_listener.NewParserExported("rfc5424", "UTC")
	require.NoError(t, err)
	msg, err := p.Parse([]byte(rfc5424Line))
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.True(t, msg.Valid())

	assert.Equal(t, "info", syslog_listener.SeverityLabelExported(msg), "severity label")
	assert.Equal(t, "local0", syslog_listener.FacilityLabelExported(msg), "facility label")
}

func TestNewParser_Cisco(t *testing.T) {
	p, err := syslog_listener.NewParserExported("cisco", "UTC")
	require.NoError(t, err)
	require.NotNil(t, p, "cisco format should build an RFC3164+Cisco parser")
}

func TestNewParser_DefaultIsEmptyRFC3164(t *testing.T) {
	p, err := syslog_listener.NewParserExported("", "UTC")
	require.NoError(t, err)
	_, err = p.Parse([]byte(rfc3164Line))
	require.NoError(t, err)
}

func TestNewParser_UnsupportedFormatErrors(t *testing.T) {
	_, err := syslog_listener.NewParserExported("bogus", "UTC")
	require.Error(t, err)
}

func TestNewParser_InvalidTimezoneErrors(t *testing.T) {
	_, err := syslog_listener.NewParserExported("rfc3164", "Not/A/Zone")
	require.Error(t, err)
}

// TestParse_GarbageIncrementsParseError verifies a non-parseable line is
// reported as an error and never produces a valid message.
func TestParse_GarbageIncrementsParseError(t *testing.T) {
	p, err := syslog_listener.NewParserExported("rfc3164", "UTC")
	require.NoError(t, err)
	msg, err := p.Parse([]byte(garbageLine))
	require.Error(t, err)
	var nilMsg = msg
	if nilMsg != nil {
		t.Fatalf("expected nil message on parse error, got valid=%v", nilMsg.Valid())
	}
}

// TestSeverityLabel_NormalizesInformational confirms the only mismatched
// keyword ("informational") collapses to "info".
func TestSeverityLabel_NormalizesInformational(t *testing.T) {
	p, err := syslog_listener.NewParserExported("rfc5424", "UTC")
	require.NoError(t, err)

	// severity 0 = emergency ... 6 = informational ... 7 = debug
	cases := []struct {
		pri  string
		want string
	}{
		{"<0>1 - - - - - -", "emergency"},
		{"<1>1 - - - - - -", "alert"},
		{"<2>1 - - - - - -", "critical"},
		{"<3>1 - - - - - -", "error"},
		{"<4>1 - - - - - -", "warning"},
		{"<5>1 - - - - - -", "notice"},
		{"<6>1 - - - - - -", "info"},
		{"<7>1 - - - - - -", "debug"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			msg, err := p.Parse([]byte(tc.pri))
			require.NoError(t, err)
			require.NotNil(t, msg)
			assert.Equal(t, tc.want, syslog_listener.SeverityLabelExported(msg))
		})
	}
}

// --- lifecycle tests -------------------------------------------------------

func TestSyslogListenerCollector_Name(t *testing.T) {
	c := syslog_listener.NewSyslogListenerCollector(config.SyslogListenerConfig{}, zap.NewNop())
	assert.Equal(t, "syslog_listener", c.Name())
}

func TestSyslogListenerCollector_Lifecycle(t *testing.T) {
	c := syslog_listener.NewSyslogListenerCollector(config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 0}},
	}, zap.NewNop())
	c.SetLineSourceFactoryExported(func(_ config.SyslogListener) (syslog_listener.LineSourceExported, error) {
		return newFakeSource(rfc3164Line), nil
	})

	assert.False(t, c.IsRunning())
	require.NoError(t, c.Start(context.Background()))
	assert.True(t, c.IsRunning())
	assert.Error(t, c.Start(context.Background()), "double Start should fail")
	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
	assert.NoError(t, c.Stop(), "double Stop should be a no-op")
}

func TestSyslogListenerCollector_StartWithoutListenersErrors(t *testing.T) {
	c := syslog_listener.NewSyslogListenerCollector(config.SyslogListenerConfig{}, zap.NewNop())
	err := c.Start(context.Background())
	require.Error(t, err)
}

func TestSyslogListenerCollector_StartInvalidTimezoneErrors(t *testing.T) {
	c := syslog_listener.NewSyslogListenerCollector(config.SyslogListenerConfig{
		Timezone:  "Not/A/Zone",
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 0}},
	}, zap.NewNop())
	err := c.Start(context.Background())
	require.Error(t, err)
}

// --- defaults --------------------------------------------------------------

func TestSyslogListenerCollector_Defaults(t *testing.T) {
	c := syslog_listener.NewSyslogListenerCollector(config.SyslogListenerConfig{}, zap.NewNop())
	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"DefaultFormat", c.CfgDefaultFormatExported(), "rfc3164"},
		{"Timezone", c.CfgTimezoneExported(), "UTC"},
		{"FlushInterval", c.CfgFlushIntervalExported(), 30 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
		})
	}
}

// --- Collect counter tests -------------------------------------------------

// TestCollect_CountersAfterMixedFeed injects 3 valid + 1 invalid line through
// a fake source and asserts the aggregate counters match. The listener is
// configured for RFC3164 (the default format), so all feed lines must be
// RFC3164-shaped; cross-format parsing is covered by the dedicated RFC5424
// listener test below.
func TestSyslogListenerCollector_Collect_CountersAfterMixedFeed(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{
			Protocol: "udp",
			Address:  "127.0.0.1",
			Port:     514,
		}},
	}
	src := newFakeSource(rfc3164Line, rfc3164Line, rfc3164Line, garbageLine)
	c := newCollectorWithFakes(t, cfg, src)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	// 3 totals + N by_severity + N by_facility. All three valid messages are
	// facility=local0 / severity=info, so there is exactly one severity bucket
	// and one facility bucket.
	recvd := findMetric(metrics, "network.syslog.messages_received_total")
	require.NotNil(t, recvd, "messages_received_total emitted")
	assert.Equal(t, 3.0, recvd.Value, "3 valid messages parsed")

	errs := findMetric(metrics, "network.syslog.parse_errors_total")
	require.NotNil(t, errs, "parse_errors_total emitted")
	assert.Equal(t, 1.0, errs.Value, "1 garbage line")

	bySev := findMetricByLabel(metrics, "network.syslog.messages_by_severity", "severity", "info")
	require.NotNil(t, bySev, "messages_by_severity{severity=\"info\"}")
	assert.Equal(t, 3.0, bySev.Value)

	byFac := findMetricByLabel(metrics, "network.syslog.messages_by_facility", "facility", "local0")
	require.NotNil(t, byFac, "messages_by_facility{facility=\"local0\"}")
	assert.Equal(t, 3.0, byFac.Value)

	// bytes_received_total should equal the sum of all four input line lengths.
	totalBytes := 3*len(rfc3164Line) + len(garbageLine)
	bytes := findMetric(metrics, "network.syslog.bytes_received_total")
	require.NotNil(t, bytes, "bytes_received_total emitted")
	assert.Equal(t, float64(totalBytes), bytes.Value)
}

// TestSyslogListenerCollector_Collect_RFC5424Listener exercises a listener
// configured for RFC5424 format end-to-end through the collector, verifying
// that the 5424 parser and severity/facility labeling work in the full
// lifecycle (not just at the parser unit level).
func TestSyslogListenerCollector_Collect_RFC5424Listener(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{
			Protocol: "tcp",
			Address:  "127.0.0.1",
			Port:     601,
			Format:   "rfc5424",
		}},
	}
	src := newFakeSource(rfc5424Line, rfc5424Line)
	c := newCollectorWithFakes(t, cfg, src)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	recvd := findMetric(metrics, "network.syslog.messages_received_total")
	require.NotNil(t, recvd)
	assert.Equal(t, 2.0, recvd.Value)
	assert.Equal(t, "tcp", recvd.Labels["protocol"])
	assert.Equal(t, "127.0.0.1:601", recvd.Labels["listener"])

	bySev := findMetricByLabel(metrics, "network.syslog.messages_by_severity", "severity", "info")
	require.NotNil(t, bySev)
	assert.Equal(t, 2.0, bySev.Value)

	byFac := findMetricByLabel(metrics, "network.syslog.messages_by_facility", "facility", "local0")
	require.NotNil(t, byFac)
	assert.Equal(t, 2.0, byFac.Value)
}

// TestSyslogListenerCollector_Collect_Labels verifies every metric carries the
// listener address and protocol labels.
func TestSyslogListenerCollector_Collect_Labels(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{
			Protocol: "udp",
			Address:  "127.0.0.1",
			Port:     514,
		}},
	}
	src := newFakeSource(rfc3164Line)
	c := newCollectorWithFakes(t, cfg, src)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, metrics)
	for _, m := range metrics {
		assert.Equal(t, "127.0.0.1:514", m.Labels["listener"], "%s listener label", m.Name)
		assert.Equal(t, "udp", m.Labels["protocol"], "%s protocol label", m.Name)
		assert.Equal(t, collector.MetricTypeCounter, m.Type, "%s type", m.Name)
	}
}

// TestSyslogListenerCollector_Collect_ResetsCounters confirms the second
// Collect cycle reports a fresh delta (counters are snapshotted and reset).
func TestSyslogListenerCollector_Collect_ResetsCounters(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 514}},
	}
	src := newFakeSource(rfc3164Line, rfc3164Line)
	c := newCollectorWithFakes(t, cfg, src)

	first, err := c.Collect(context.Background())
	require.NoError(t, err)
	recvd1 := findMetric(first, "network.syslog.messages_received_total")
	require.NotNil(t, recvd1)
	assert.Equal(t, 2.0, recvd1.Value, "first cycle sees 2 messages")

	second, err := c.Collect(context.Background())
	require.NoError(t, err)
	recvd2 := findMetric(second, "network.syslog.messages_received_total")
	require.NotNil(t, recvd2)
	assert.Equal(t, 0.0, recvd2.Value, "second cycle resets to 0 (no new messages)")

	// Totals are still emitted (at zero) so the schema stays stable.
	require.NotNil(t, findMetric(second, "network.syslog.parse_errors_total"))
	require.NotNil(t, findMetric(second, "network.syslog.bytes_received_total"))
}

// TestSyslogListenerCollector_Collect_SeverityBreakdown feeds lines with
// different severities and checks each severity bucket lands in its own
// by_severity metric.
func TestSyslogListenerCollector_Collect_SeverityBreakdown(t *testing.T) {
	// priority = facility*8 + severity. Use facility=user (1):
	//   <3>  -> error, <4> -> warning, <6> -> info
	lines := []string{
		"<3>Jan  2 03:04:05 host a: boom",
		"<4>Jan  2 03:04:05 host a: careful",
		"<6>Jan  2 03:04:05 host a: fyi",
		"<6>Jan  2 03:04:05 host a: fyi again",
	}
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 514}},
	}
	c := newCollectorWithFakes(t, cfg, newFakeSource(lines...))

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1.0, findMetricByLabel(metrics, "network.syslog.messages_by_severity", "severity", "error").Value)
	assert.Equal(t, 1.0, findMetricByLabel(metrics, "network.syslog.messages_by_severity", "severity", "warning").Value)
	assert.Equal(t, 2.0, findMetricByLabel(metrics, "network.syslog.messages_by_severity", "severity", "info").Value)
}

// TestSyslogListenerCollector_Collect_FacilityBreakdown feeds lines spanning
// multiple facilities and checks the by_facility buckets.
func TestSyslogListenerCollector_Collect_FacilityBreakdown(t *testing.T) {
	lines := []string{
		"<4>Jan  2 03:04:05 host a: kern warning",   // facility=kern(0) severity=warning(4)
		"<12>Jan  2 03:04:05 host a: user warning",  // facility=user(1) severity=warning(4)
		"<20>Jan  2 03:04:05 host a: mail warning",  // facility=mail(2) severity=warning(4)
		"<20>Jan  2 03:04:05 host a: mail warning2", // facility=mail(2) severity=warning(4)
	}
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 514}},
	}
	c := newCollectorWithFakes(t, cfg, newFakeSource(lines...))

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1.0, findMetricByLabel(metrics, "network.syslog.messages_by_facility", "facility", "kern").Value)
	assert.Equal(t, 1.0, findMetricByLabel(metrics, "network.syslog.messages_by_facility", "facility", "user").Value)
	assert.Equal(t, 2.0, findMetricByLabel(metrics, "network.syslog.messages_by_facility", "facility", "mail").Value)
}

// TestSyslogListenerCollector_Collect_MultipleListeners confirms each listener
// emits its own labeled metric set and counters are tracked independently.
func TestSyslogListenerCollector_Collect_MultipleListeners(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{
			{Protocol: "udp", Address: "10.0.0.1", Port: 514},
			{Protocol: "tcp", Address: "10.0.0.2", Port: 601},
		},
	}
	src1 := newFakeSource(rfc3164Line)              // 1 valid message
	src2 := newFakeSource(garbageLine, rfc3164Line) // 1 parse error + 1 valid message
	c := newCollectorWithFakes(t, cfg, src1, src2)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	udpRecvd := findMetricByLabel(metrics, "network.syslog.messages_received_total", "listener", "10.0.0.1:514")
	require.NotNil(t, udpRecvd)
	assert.Equal(t, 1.0, udpRecvd.Value)
	assert.Equal(t, "udp", udpRecvd.Labels["protocol"])

	tcpRecvd := findMetricByLabel(metrics, "network.syslog.messages_received_total", "listener", "10.0.0.2:601")
	require.NotNil(t, tcpRecvd)
	assert.Equal(t, 1.0, tcpRecvd.Value)
	assert.Equal(t, "tcp", tcpRecvd.Labels["protocol"])

	tcpErrs := findMetricByLabel(metrics, "network.syslog.parse_errors_total", "listener", "10.0.0.2:601")
	require.NotNil(t, tcpErrs)
	assert.Equal(t, 1.0, tcpErrs.Value)
}

// TestSyslogListenerCollector_Collect_ContextCancellation verifies Collect
// honors ctx cancellation.
func TestSyslogListenerCollector_Collect_ContextCancellation(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 514}},
	}
	c := newCollectorWithFakes(t, cfg, newFakeSource(rfc3164Line))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Collect(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestSyslogListenerCollector_Collect_EmptyCycleStillEmitsTotals verifies a
// listener with zero activity still reports the three total counters (at 0)
// and no by_severity / by_facility buckets.
func TestSyslogListenerCollector_Collect_EmptyCycleStillEmitsTotals(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 514}},
	}
	c := newCollectorWithFakes(t, cfg, newFakeSource()) // no messages

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, findMetric(metrics, "network.syslog.messages_received_total"))
	require.NotNil(t, findMetric(metrics, "network.syslog.parse_errors_total"))
	require.NotNil(t, findMetric(metrics, "network.syslog.bytes_received_total"))
	assert.Nil(t, findMetric(metrics, "network.syslog.messages_by_severity"), "no severity buckets on empty cycle")
}

// TestSyslogListenerCollector_SourceFactoryError confirms Start propagates
// errors from the source factory.
func TestSyslogListenerCollector_SourceFactoryError(t *testing.T) {
	cfg := config.SyslogListenerConfig{
		Listeners: []config.SyslogListener{{Protocol: "udp", Port: 514}},
	}
	c := syslog_listener.NewSyslogListenerCollector(cfg, zap.NewNop())
	boom := errors.New("bind: permission denied")
	c.SetLineSourceFactoryExported(func(_ config.SyslogListener) (syslog_listener.LineSourceExported, error) {
		return nil, boom
	})
	err := c.Start(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.False(t, c.IsRunning())
}

// TestSyslogListenerCollector_SatisfiesInterface is a compile-time guard
// mirrored at runtime.
func TestSyslogListenerCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*syslog_listener.SyslogListenerCollector)(nil)
}
