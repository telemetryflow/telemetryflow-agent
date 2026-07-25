// Package syslog_listener implements a TelemetryFlow Agent collector that runs
// a syslog receiver. It listens for syslog messages over UDP, TCP, or Unix
// sockets, parses each message with github.com/leodido/go-syslog/v4, and
// emits aggregate counter metrics per Collect cycle.
//
// The collector is service-style: Start() opens one socket per configured
// listener and spawns a background goroutine that parses incoming lines and
// updates per-listener counters. Collect() snapshots and resets those counters
// so each cycle reports the delta since the previous cycle. Per-message
// metrics and OTEL log records are deferred to M3 once the log bridge is wired.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package syslog_listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/ciscoios"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "syslog_listener"

// SyslogListenerCollector listens for syslog messages and emits aggregate
// counters every Collect cycle.
type SyslogListenerCollector struct {
	cfg    config.SyslogListenerConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	// sourceFactory opens a LineSource for each listener. Production uses
	// defaultSourceFactory; tests inject a fake via SetLineSourceFactoryExported.
	sourceFactory func(config.SyslogListener) (LineSourceExported, error)

	runtimes []*listenerRuntime
	wg       sync.WaitGroup // tracks background reader goroutines
}

// listenerRuntime holds the per-listener parser, source, and counters.
type listenerRuntime struct {
	cfg      config.SyslogListener
	addr     string // resolved "host:port" used as the listener label
	parser   syslog.Machine
	source   LineSourceExported
	counters *listenerCounters
}

// listenerCounters holds the delta counters accumulated since the last Collect.
// The mutex guards every field; the background goroutine writes while Collect
// reads and resets.
type listenerCounters struct {
	mu               sync.Mutex
	messagesReceived int64
	parseErrors      int64
	bytesReceived    int64
	bySeverity       map[string]int64
	byFacility       map[string]int64
}

// countersSnapshot is an immutable copy of listenerCounters taken at Collect time.
type countersSnapshot struct {
	messagesReceived int64
	parseErrors      int64
	bytesReceived    int64
	bySeverity       map[string]int64
	byFacility       map[string]int64
}

func newListenerCounters() *listenerCounters {
	return &listenerCounters{
		bySeverity: make(map[string]int64),
		byFacility: make(map[string]int64),
	}
}

// NewSyslogListenerCollector constructs a SyslogListenerCollector with sensible
// defaults applied to DefaultFormat ("rfc3164"), Timezone ("UTC"), and
// FlushInterval (30s) when they are empty/zero.
func NewSyslogListenerCollector(cfg config.SyslogListenerConfig, logger *zap.Logger) *SyslogListenerCollector {
	if cfg.DefaultFormat == "" {
		cfg.DefaultFormat = "rfc3164"
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "UTC"
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	return &SyslogListenerCollector{
		cfg:           cfg,
		logger:        logger.Named(collectorName),
		sourceFactory: defaultSourceFactory,
	}
}

func (c *SyslogListenerCollector) Name() string { return collectorName }

func (c *SyslogListenerCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start opens one source per configured listener and spawns a background
// goroutine that parses incoming messages and updates counters.
func (c *SyslogListenerCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("syslog_listener collector already running")
	}
	if len(c.cfg.Listeners) == 0 {
		return fmt.Errorf("syslog_listener collector has no listeners configured")
	}

	loc, locErr := time.LoadLocation(c.cfg.Timezone)
	if locErr != nil {
		return fmt.Errorf("syslog_listener: invalid timezone %q: %w", c.cfg.Timezone, locErr)
	}

	runtimes := make([]*listenerRuntime, 0, len(c.cfg.Listeners))
	for _, lcfg := range c.cfg.Listeners {
		format := lcfg.Format
		if format == "" {
			format = c.cfg.DefaultFormat
		}
		parser, err := newParser(format, loc)
		if err != nil {
			// Tear down any sources opened so far.
			for _, rt := range runtimes {
				_ = rt.source.Close()
			}
			return fmt.Errorf("syslog_listener %s: %w", listenerAddress(lcfg), err)
		}
		source, err := c.sourceFactory(lcfg)
		if err != nil {
			for _, rt := range runtimes {
				_ = rt.source.Close()
			}
			return fmt.Errorf("syslog_listener %s: %w", listenerAddress(lcfg), err)
		}
		runtimes = append(runtimes, &listenerRuntime{
			cfg:      lcfg,
			addr:     listenerAddress(lcfg),
			parser:   parser,
			source:   source,
			counters: newListenerCounters(),
		})
	}

	c.runtimes = runtimes
	c.running = true
	c.stopChan = make(chan struct{})

	for _, rt := range runtimes {
		c.wg.Add(1)
		go c.readLoop(ctx, rt)
	}

	c.logger.Info("Syslog listener collector starting",
		zap.Int("listeners", len(runtimes)),
		zap.String("default_format", c.cfg.DefaultFormat),
		zap.String("timezone", c.cfg.Timezone),
		zap.Duration("flush_interval", c.cfg.FlushInterval),
	)
	return nil
}

// Stop closes all sources and waits for the background goroutines to exit.
func (c *SyslogListenerCollector) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	close(c.stopChan)
	for _, rt := range c.runtimes {
		_ = rt.source.Close()
	}
	c.mu.Unlock()

	// Wait outside the lock so blocked goroutines can exit.
	c.wg.Wait()

	c.mu.Lock()
	c.runtimes = nil
	c.mu.Unlock()
	return nil
}

// Collect snapshots and resets every listener's counters and emits the
// aggregate metrics for this cycle. Each metric carries the listener address
// and protocol labels.
func (c *SyslogListenerCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	c.mu.RLock()
	runtimes := c.runtimes
	c.mu.RUnlock()

	if len(runtimes) == 0 {
		return nil, nil
	}

	now := time.Now()
	var all []collector.Metric
	for _, rt := range runtimes {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		snap := rt.counters.snapshotAndReset()
		all = append(all, buildSyslogMetrics(snap, rt, now)...)
	}
	return all, nil
}

// readLoop drains the source one message at a time until the source returns an
// error (io.EOF on graceful close, or a socket error on Stop). Each message is
// parsed and counted.
func (c *SyslogListenerCollector) readLoop(ctx context.Context, rt *listenerRuntime) {
	defer c.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		default:
		}

		data, err := rt.source.Next()
		if len(data) > 0 {
			processMessage(rt, data)
		}
		if err != nil {
			if err != io.EOF {
				select {
				case <-c.stopChan:
					// Expected shutdown path; don't log.
				default:
					c.logger.Debug("syslog source ended",
						zap.String("listener", rt.addr),
						zap.String("protocol", rt.cfg.Protocol),
						zap.Error(err),
					)
				}
			}
			return
		}
	}
}

// processMessage parses one syslog message and updates the listener counters.
// Parsing happens outside the lock; counter updates take it briefly.
func processMessage(rt *listenerRuntime, data []byte) {
	msg, parseErr := rt.parser.Parse(data)

	rt.counters.mu.Lock()
	defer rt.counters.mu.Unlock()

	rt.counters.bytesReceived += int64(len(data))

	if parseErr != nil || msg == nil || !msg.Valid() {
		rt.counters.parseErrors++
		return
	}

	rt.counters.messagesReceived++
	rt.counters.bySeverity[severityLabel(msg)]++
	rt.counters.byFacility[facilityLabel(msg)]++
}

// snapshotAndReset returns an immutable copy of the counters and zeroes every
// accumulator so the next Collect cycle reports a fresh delta.
func (lc *listenerCounters) snapshotAndReset() countersSnapshot {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	snap := countersSnapshot{
		messagesReceived: lc.messagesReceived,
		parseErrors:      lc.parseErrors,
		bytesReceived:    lc.bytesReceived,
		bySeverity:       make(map[string]int64, len(lc.bySeverity)),
		byFacility:       make(map[string]int64, len(lc.byFacility)),
	}
	for k, v := range lc.bySeverity {
		snap.bySeverity[k] = v
	}
	for k, v := range lc.byFacility {
		snap.byFacility[k] = v
	}

	lc.messagesReceived = 0
	lc.parseErrors = 0
	lc.bytesReceived = 0
	lc.bySeverity = make(map[string]int64)
	lc.byFacility = make(map[string]int64)
	return snap
}

// buildSyslogMetrics maps a counters snapshot to the network.syslog.* metric
// namespace. Listeners with no activity in the cycle still emit the three
// total counters (at zero) so consumers see a stable schema.
func buildSyslogMetrics(snap countersSnapshot, rt *listenerRuntime, now time.Time) []collector.Metric {
	base := map[string]string{
		"listener": rt.addr,
		"protocol": listenerProtocol(rt.cfg),
	}
	mk := func(name string, v float64, typ collector.MetricType, desc string, extra map[string]string) collector.Metric {
		labels := make(map[string]string, len(base)+len(extra))
		for k, val := range base {
			labels[k] = val
		}
		for k, val := range extra {
			labels[k] = val
		}
		return collector.Metric{
			Name:        name,
			Type:        typ,
			Value:       v,
			Timestamp:   now,
			Description: desc,
			Labels:      labels,
		}
	}

	out := make([]collector.Metric, 0, 3+len(snap.bySeverity)+len(snap.byFacility))
	out = append(out,
		mk("network.syslog.messages_received_total", float64(snap.messagesReceived), collector.MetricTypeCounter,
			"Total syslog messages successfully parsed since last collection", nil),
		mk("network.syslog.parse_errors_total", float64(snap.parseErrors), collector.MetricTypeCounter,
			"Total syslog messages that failed to parse since last collection", nil),
		mk("network.syslog.bytes_received_total", float64(snap.bytesReceived), collector.MetricTypeCounter,
			"Total syslog bytes received since last collection", nil),
	)
	for sev, n := range snap.bySeverity {
		out = append(out, mk("network.syslog.messages_by_severity", float64(n), collector.MetricTypeCounter,
			"Syslog messages by severity since last collection", map[string]string{"severity": sev}))
	}
	for fac, n := range snap.byFacility {
		out = append(out, mk("network.syslog.messages_by_facility", float64(n), collector.MetricTypeCounter,
			"Syslog messages by facility since last collection", map[string]string{"facility": fac}))
	}
	return out
}

// newParser builds a go-syslog Machine for the configured format. The location
// is applied to RFC 3164 timestamps (which omit year and timezone).
func newParser(format string, loc *time.Location) (syslog.Machine, error) {
	switch strings.ToLower(format) {
	case "", "rfc3164":
		return rfc3164.NewParser(rfc3164.WithTimezone(loc)), nil
	case "rfc5424":
		return rfc5424.NewParser(), nil
	case "cisco":
		return rfc3164.NewParser(
			rfc3164.WithTimezone(loc),
			rfc3164.WithCiscoIOSComponents(ciscoios.All),
		), nil
	default:
		return nil, fmt.Errorf("unsupported syslog format %q", format)
	}
}

// severityLabel returns the severity label for a parsed message. The go-syslog
// library returns "informational" for severity 6; the metric schema uses "info"
// to match the canonical syslog severity keyword set.
func severityLabel(msg syslog.Message) string {
	if p := msg.SeverityLevel(); p != nil && *p != "" {
		if *p == "informational" {
			return "info"
		}
		return *p
	}
	return "unknown"
}

// facilityLabel returns the facility label for a parsed message.
func facilityLabel(msg syslog.Message) string {
	if p := msg.FacilityLevel(); p != nil && *p != "" {
		return *p
	}
	return "unknown"
}

func listenerProtocol(lcfg config.SyslogListener) string {
	if lcfg.Protocol == "" {
		return "udp"
	}
	return strings.ToLower(lcfg.Protocol)
}

func listenerAddress(lcfg config.SyslogListener) string {
	addr := lcfg.Address
	if addr == "" {
		addr = "0.0.0.0"
	}
	return net.JoinHostPort(addr, strconv.Itoa(lcfg.Port))
}

// Compile-time guard: SyslogListenerCollector satisfies collector.Collector.
var _ collector.Collector = (*SyslogListenerCollector)(nil)

// ----------------------------------------------------------------------------
// Production source factory
// ----------------------------------------------------------------------------

// defaultSourceFactory opens a real socket for the configured listener.
func defaultSourceFactory(lcfg config.SyslogListener) (LineSourceExported, error) {
	switch listenerProtocol(lcfg) {
	case "udp":
		addr, err := net.ResolveUDPAddr("udp", listenerAddress(lcfg))
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, err
		}
		return &udpSource{conn: conn, buf: make([]byte, 65536)}, nil
	case "tcp":
		ln, err := net.Listen("tcp", listenerAddress(lcfg))
		if err != nil {
			return nil, err
		}
		return newTCPLineSource(ln), nil
	case "unix":
		ln, err := net.Listen("unix", lcfg.Address)
		if err != nil {
			return nil, err
		}
		return newUnixLineSource(ln), nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", lcfg.Protocol)
	}
}

// udpSource wraps a *net.UDPConn. Each Next() returns one datagram.
type udpSource struct {
	conn *net.UDPConn
	buf  []byte
}

func (s *udpSource) Next() ([]byte, error) {
	n, _, err := s.conn.ReadFrom(s.buf)
	if err != nil {
		return nil, err
	}
	return s.buf[:n], nil
}

func (s *udpSource) Close() error { return s.conn.Close() }

// lineSource multiplexes newline-delimited messages from one or more accepted
// stream connections (TCP or Unix) into a single channel. Each Next() returns
// the next complete line.
type lineSource struct {
	listener net.Listener
	lines    chan []byte
	done     chan struct{}
	once     sync.Once
}

func newTCPLineSource(ln net.Listener) *lineSource {
	s := &lineSource{
		listener: ln,
		lines:    make(chan []byte, 256),
		done:     make(chan struct{}),
	}
	go s.acceptLoop()
	return s
}

func newUnixLineSource(ln net.Listener) *lineSource {
	return newTCPLineSource(ln)
}

func (s *lineSource) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *lineSource) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 65536), 1<<20)
	for scanner.Scan() {
		line := make([]byte, len(scanner.Bytes()))
		copy(line, scanner.Bytes())
		select {
		case s.lines <- line:
		case <-s.done:
			return
		}
	}
}

func (s *lineSource) Next() ([]byte, error) {
	select {
	case line, ok := <-s.lines:
		if !ok {
			return nil, io.EOF
		}
		return line, nil
	case <-s.done:
		return nil, io.EOF
	}
}

func (s *lineSource) Close() error {
	s.once.Do(func() { close(s.done) })
	return s.listener.Close()
}
