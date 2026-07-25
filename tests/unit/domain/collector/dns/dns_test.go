// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package dns_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/dns"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// fakeResolver is a test double for the dns.ResolverExported interface. It
// records the last call's arguments and returns a configured result/err.
type fakeResolver struct {
	result dns.DNSResultExported
	err    error

	lastServer  string
	lastPort    int
	lastQuery   config.DNSQuery
	lastTimeout time.Duration
	calls       int
}

func (f *fakeResolver) Query(server string, port int, q config.DNSQuery, timeout time.Duration) (dns.DNSResultExported, error) {
	f.calls++
	f.lastServer = server
	f.lastPort = port
	f.lastQuery = q
	f.lastTimeout = timeout
	return f.result, f.err
}

func newCollector(t *testing.T, cfg config.DNSCollectorConfig, res dns.ResolverExported) *dns.DNSCollector {
	t.Helper()
	c := dns.NewDNSCollector(cfg, zap.NewNop())
	c.SetResolverExported(res)
	return c
}

func metricByName(t *testing.T, ms []collector.Metric, name string) collector.Metric {
	t.Helper()
	for _, m := range ms {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("metric %q not emitted", name)
	return collector.Metric{}
}

// TestDNSCollector_Collect covers the per-cycle emission matrix.
func TestDNSCollector_Collect(t *testing.T) {
	tests := []struct {
		name       string
		result     dns.DNSResultExported
		err        error
		wantState  float64
		wantRcode  float64
		wantRecord float64
	}{
		{
			name:       "successful query emits state=1 and positive RTT",
			result:     dns.DNSResultExported{Rcode: 0, Records: 2, ElapsedMs: 12.5},
			wantState:  1,
			wantRcode:  0,
			wantRecord: 2,
		},
		{
			name:      "timeout emits state=0",
			result:    dns.DNSResultExported{Rcode: 0, Records: 0, ElapsedMs: 0},
			err:       errors.New("i/o timeout"),
			wantState: 0,
			wantRcode: 0,
		},
		{
			name:       "NXDOMAIN emits state=0 with result_code=3",
			result:     dns.DNSResultExported{Rcode: 3, Records: 0, ElapsedMs: 8.0},
			wantState:  0,
			wantRcode:  3,
			wantRecord: 0,
		},
		{
			name:       "SERVFAIL emits state=0 with result_code=2",
			result:     dns.DNSResultExported{Rcode: 2, Records: 0, ElapsedMs: 9.0},
			wantState:  0,
			wantRcode:  2,
			wantRecord: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeResolver{result: tt.result, err: tt.err}
			cfg := config.DNSCollectorConfig{
				Servers: []config.DNSServer{{Address: "1.1.1.1", Name: "cloudflare"}},
				Queries: []config.DNSQuery{{Domain: "example.com", RecordType: "A"}},
			}
			c := newCollector(t, cfg, fake)
			ms, err := c.Collect(context.Background())
			require.NoError(t, err)
			require.Len(t, ms, 4)

			m := metricByName(t, ms, "network.dns.state")
			assert.Equal(t, tt.wantState, m.Value, "state mismatch")

			rc := metricByName(t, ms, "network.dns.result_code")
			assert.Equal(t, tt.wantRcode, rc.Value, "result_code mismatch")

			rec := metricByName(t, ms, "network.dns.records_returned")
			assert.Equal(t, tt.wantRecord, rec.Value, "records_returned mismatch")

			rtt := metricByName(t, ms, "network.dns.query_time_ms")
			if tt.err == nil {
				assert.Greater(t, rtt.Value, 0.0, "query_time_ms should be positive on success")
			}
		})
	}
}

// TestDNSCollector_Defaults verifies Port/Timeout/RecordType defaults flow
// through to the resolver.
func TestDNSCollector_Defaults(t *testing.T) {
	fake := &fakeResolver{result: dns.DNSResultExported{Rcode: 0, Records: 1, ElapsedMs: 5.0}}
	cfg := config.DNSCollectorConfig{
		// Port, Timeout, and RecordType intentionally unset.
		Servers: []config.DNSServer{{Address: "8.8.8.8", Name: "google"}},
		Queries: []config.DNSQuery{{Domain: "example.com"}},
	}
	c := newCollector(t, cfg, fake)

	ms, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, ms, 4)

	require.Equal(t, 1, fake.calls, "resolver should be called once")
	assert.Equal(t, 53, fake.lastPort, "default port should be 53")
	assert.Equal(t, 5*time.Second, fake.lastTimeout, "default timeout should be 5s")
	assert.Equal(t, "A", fake.lastQuery.RecordType, "default record type should be A")

	state := metricByName(t, ms, "network.dns.state")
	assert.Equal(t, "A", state.Labels["record_type"])
}

// TestDNSCollector_Labels verifies the required label set is present.
func TestDNSCollector_Labels(t *testing.T) {
	fake := &fakeResolver{result: dns.DNSResultExported{Rcode: 0, Records: 1, ElapsedMs: 4.0}}
	cfg := config.DNSCollectorConfig{
		Servers: []config.DNSServer{{Address: "9.9.9.9", Name: "quad9"}},
		Queries: []config.DNSQuery{{Domain: "foo.test", RecordType: "MX"}},
	}
	c := newCollector(t, cfg, fake)

	ms, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, ms, 4)

	for _, m := range ms {
		assert.Equal(t, "9.9.9.9", m.Labels["server"], "%s: server label", m.Name)
		assert.Equal(t, "quad9", m.Labels["server_name"], "%s: server_name label", m.Name)
		assert.Equal(t, "foo.test", m.Labels["domain"], "%s: domain label", m.Name)
		assert.Equal(t, "MX", m.Labels["record_type"], "%s: record_type label", m.Name)
	}
}

// TestDNSCollector_EmptyConfig verifies a no-op when servers or queries are missing.
func TestDNSCollector_EmptyConfig(t *testing.T) {
	fake := &fakeResolver{result: dns.DNSResultExported{Rcode: 0, Records: 0, ElapsedMs: 0}}

	t.Run("no servers", func(t *testing.T) {
		c := newCollector(t, config.DNSCollectorConfig{
			Queries: []config.DNSQuery{{Domain: "x.test"}},
		}, fake)
		ms, err := c.Collect(context.Background())
		require.NoError(t, err)
		assert.Empty(t, ms)
		assert.Equal(t, 0, fake.calls)
	})

	t.Run("no queries", func(t *testing.T) {
		c := newCollector(t, config.DNSCollectorConfig{
			Servers: []config.DNSServer{{Address: "1.1.1.1"}},
		}, fake)
		ms, err := c.Collect(context.Background())
		require.NoError(t, err)
		assert.Empty(t, ms)
		assert.Equal(t, 0, fake.calls)
	})
}

// TestDNSCollector_ContextCancellation verifies Collect honors ctx cancellation.
func TestDNSCollector_ContextCancellation(t *testing.T) {
	fake := &fakeResolver{result: dns.DNSResultExported{Rcode: 0, Records: 0, ElapsedMs: 1.0}}
	cfg := config.DNSCollectorConfig{
		Servers: []config.DNSServer{
			{Address: "1.1.1.1"},
			{Address: "8.8.8.8"},
		},
		Queries: []config.DNSQuery{{Domain: "a.test"}, {Domain: "b.test"}},
	}
	c := newCollector(t, cfg, fake)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Collect(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestRecordType verifies record-type mapping for all supported types plus errors.
func TestRecordType(t *testing.T) {
	tests := []struct {
		in   string
		want uint16
		err  bool
	}{
		{"A", 1, false},
		{"", 1, false},
		{"AAAA", 28, false},
		{"TXT", 16, false},
		{"MX", 15, false},
		{"NS", 2, false},
		{"CNAME", 5, false},
		{"PTR", 12, false},
		{"BOGUS", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := dns.RecordTypeExported(tt.in)
			if tt.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDNSCollector_Lifecycle exercises Name/Start/IsRunning/Stop.
func TestDNSCollector_Lifecycle(t *testing.T) {
	c := dns.NewDNSCollector(config.DNSCollectorConfig{}, zap.NewNop())
	assert.Equal(t, "dns", c.Name())
	assert.False(t, c.IsRunning())

	require.NoError(t, c.Start(context.Background()))
	assert.True(t, c.IsRunning())

	assert.Error(t, c.Start(context.Background()), "double Start should error")

	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())

	assert.NoError(t, c.Stop(), "double Stop should be a no-op")
}
