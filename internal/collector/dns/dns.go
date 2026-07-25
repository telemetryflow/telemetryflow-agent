// Package dns implements a TelemetryFlow Agent collector that issues DNS
// probes against one or more servers and emits per-query RTT, result code,
// answer count, and success state metrics. It uses github.com/miekg/dns as
// the on-the-wire resolver.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "dns"

// DNSCollector monitors one or more DNS servers by issuing configured queries.
type DNSCollector struct {
	cfg      config.DNSCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
	resolver resolver
}

// NewDNSCollector constructs a DNSCollector with the default miekg/dns resolver.
func NewDNSCollector(cfg config.DNSCollectorConfig, logger *zap.Logger) *DNSCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	c := &DNSCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
	c.resolver = &miekgResolver{logger: c.logger}
	return c
}

func (c *DNSCollector) Name() string    { return collectorName }
func (c *DNSCollector) IsRunning() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.running }

func (c *DNSCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("dns collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("DNS collector starting",
		zap.Int("servers", len(c.cfg.Servers)),
		zap.Int("queries", len(c.cfg.Queries)),
	)
	return nil
}

func (c *DNSCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across every (server x query) pair.
func (c *DNSCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Servers) == 0 || len(c.cfg.Queries) == 0 {
		return nil, nil
	}
	port := c.cfg.Port
	if port == 0 {
		port = 53
	}
	timeout := c.cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var all []collector.Metric
	for _, srv := range c.cfg.Servers {
		for _, q := range c.cfg.Queries {
			select {
			case <-ctx.Done():
				return all, ctx.Err()
			default:
			}
			all = append(all, c.collectOne(srv, q, port, timeout)...)
		}
	}
	return all, nil
}

func (c *DNSCollector) collectOne(srv config.DNSServer, q config.DNSQuery, port int, timeout time.Duration) []collector.Metric {
	recordType := q.RecordType
	if recordType == "" {
		recordType = "A"
	}
	query := config.DNSQuery{Domain: q.Domain, RecordType: recordType}

	result, err := c.resolver.query(srv.Address, port, query, timeout)

	labels := map[string]string{
		"server":      srv.Address,
		"server_name": srv.Name,
		"domain":      q.Domain,
		"record_type": recordType,
	}

	state := 1.0
	if err != nil || result.rcode != 0 {
		state = 0
	}

	return []collector.Metric{
		buildMetric("network.dns.query_time_ms", result.elapsedMs, collector.MetricTypeGauge, "ms",
			"DNS query round-trip time in milliseconds", labels),
		buildMetric("network.dns.result_code", float64(result.rcode), collector.MetricTypeGauge, "",
			"DNS result code (0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, 4=NOTIMP, 5=REFUSED)", labels),
		buildMetric("network.dns.records_returned", float64(result.records), collector.MetricTypeGauge, "",
			"Number of DNS answer records returned", labels),
		buildMetric("network.dns.state", state, collector.MetricTypeGauge, "",
			"DNS query state (0=fail, 1=ok)", labels),
	}
}

func buildMetric(name string, value float64, typ collector.MetricType, unit, desc string, labels map[string]string) collector.Metric {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return collector.Metric{
		Name:        name,
		Type:        typ,
		Value:       value,
		Timestamp:   time.Now(),
		Unit:        unit,
		Description: desc,
		Labels:      out,
	}
}

// dnsResult is the normalized outcome of a single DNS query.
type dnsResult struct {
	rcode     int     // DNS RCODE (0=NOERROR, 3=NXDOMAIN, ...)
	records   int     // number of answer records returned
	elapsedMs float64 // measured RTT in milliseconds
}

// resolver abstracts a single DNS query so tests can inject a fake.
type resolver interface {
	query(server string, port int, q config.DNSQuery, timeout time.Duration) (dnsResult, error)
}

// miekgResolver is the production resolver backed by github.com/miekg/dns.
type miekgResolver struct {
	logger *zap.Logger
}

func (r *miekgResolver) query(server string, port int, q config.DNSQuery, timeout time.Duration) (dnsResult, error) {
	qtype, err := recordType(q.RecordType)
	if err != nil {
		return dnsResult{}, err
	}
	c := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q.Domain), qtype)
	m.RecursionDesired = true

	addr := net.JoinHostPort(server, strconv.Itoa(port))
	start := time.Now()
	reply, _, err := c.Exchange(m, addr)
	elapsed := time.Since(start)
	if err != nil {
		return dnsResult{elapsedMs: float64(elapsed.Milliseconds())}, err
	}
	return dnsResult{
		rcode:     reply.Rcode,
		records:   len(reply.Answer),
		elapsedMs: float64(elapsed.Milliseconds()),
	}, nil
}

// recordType maps a textual DNS record type to its numeric miekg/dns constant.
func recordType(s string) (uint16, error) {
	switch s {
	case "", "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "MX":
		return dns.TypeMX, nil
	case "NS":
		return dns.TypeNS, nil
	case "CNAME":
		return dns.TypeCNAME, nil
	case "PTR":
		return dns.TypePTR, nil
	default:
		return 0, fmt.Errorf("unsupported dns record type %q", s)
	}
}
