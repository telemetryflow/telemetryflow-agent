// Package ping implements a TelemetryFlow Agent network collector that probes
// configured hosts with ICMP echo requests ("pings") and emits per-target RTT,
// packet-loss, TTL, and reachability metrics under the network.ping.* namespace.
//
// The collector supports two transports via golang.org/x/net/icmp:
//   - privileged ("ip4:icmp"): raw sockets, requires root or CAP_NET_RAW.
//   - unprivileged ("udp4"): datagram ICMP via the Linux
//     `net.ipv4.ping_group_range` sysctl or macOS SO_DGRAM_ICMP.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package ping

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "ping"

// pingPayload is the bytes echoed back in each request. Distinguishes our
// probes from unrelated ICMP traffic on shared sockets.
const pingPayload = "TFO-PING-PLEASE-IGNORE"

// PingCollector probes one or more hosts via ICMP echo requests and emits
// per-target metrics on every Collect cycle.
type PingCollector struct {
	cfg      config.PingCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	pinger pinger
}

// pinger abstracts the actual ICMP probe so tests can inject fakes without
// touching the network. Production code uses defaultPinger.
type pinger interface {
	ping(host string, count int, timeout time.Duration) (pingStats, error)
}

// pingStats is the result of probing a single host.
type pingStats struct {
	host            string
	resolvedIP      string
	packetsSent     int
	packetsReceived int
	rtts            []time.Duration
	ttl             int
	state           int // 0 = down, 1 = up
}

// NewPingCollector constructs a PingCollector with sensible defaults applied
// to Count (5), Timeout (5s), and IntervalBetween (1s) when they are zero.
func NewPingCollector(cfg config.PingCollectorConfig, logger *zap.Logger) *PingCollector {
	if cfg.Count == 0 {
		cfg.Count = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.IntervalBetween <= 0 {
		cfg.IntervalBetween = 1 * time.Second
	}
	c := &PingCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
	c.pinger = &defaultPinger{
		privileged: cfg.Privileged,
		interval:   cfg.IntervalBetween,
		logger:     c.logger,
	}
	return c
}

func (c *PingCollector) Name() string { return collectorName }

func (c *PingCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *PingCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("ping collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("Ping collector starting", zap.Int("targets", len(c.cfg.Targets)))
	return nil
}

func (c *PingCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect probes every configured target once and emits metrics. Failures
// (DNS resolution, packet loss, socket errors) do not skip a target; instead
// that target emits a state=0 metric set so dashboards can alert on the
// transition.
func (c *PingCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Targets) == 0 {
		return nil, nil
	}
	count := c.cfg.Count
	timeout := c.cfg.Timeout
	now := time.Now()
	var all []collector.Metric
	for _, target := range c.cfg.Targets {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		stats, err := c.pinger.ping(target.Host, count, timeout)
		if err != nil {
			c.logger.Warn("Ping probe failed",
				zap.String("host", target.Host),
				zap.Error(err),
			)
		}
		all = append(all, buildPingMetrics(stats, target, now)...)
	}
	return all, nil
}

// buildPingMetrics maps pingStats to the network.ping.* metric namespace.
// It always emits the full metric set so consumers can rely on a stable
// schema regardless of probe outcome.
func buildPingMetrics(stats pingStats, target config.PingTarget, now time.Time) []collector.Metric {
	label := target.Name
	if label == "" {
		label = target.Host
	}
	base := map[string]string{
		"target": label,
		"host":   stats.resolvedIP,
	}
	mk := func(name string, v float64, desc string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        collector.MetricTypeGauge,
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

	var minMs, maxMs, avgMs, stddevMs float64
	if n := len(stats.rtts); n > 0 {
		min := stats.rtts[0]
		max := stats.rtts[0]
		var sumMs float64
		for _, r := range stats.rtts {
			ms := durationToMs(r)
			sumMs += ms
			if r < min {
				min = r
			}
			if r > max {
				max = r
			}
		}
		avgMs = sumMs / float64(n)
		minMs = durationToMs(min)
		maxMs = durationToMs(max)
		if n > 1 {
			var sqdiff float64
			for _, r := range stats.rtts {
				d := durationToMs(r) - avgMs
				sqdiff += d * d
			}
			stddevMs = math.Sqrt(sqdiff / float64(n))
		}
	}

	loss := 100.0
	if stats.packetsSent > 0 {
		loss = float64(stats.packetsSent-stats.packetsReceived) / float64(stats.packetsSent) * 100.0
	}

	out := make([]collector.Metric, 0, 9)
	out = append(out,
		mk("network.ping.rtt_min_ms", minMs, "Minimum round-trip time in milliseconds"),
		mk("network.ping.rtt_avg_ms", avgMs, "Average round-trip time in milliseconds"),
		mk("network.ping.rtt_max_ms", maxMs, "Maximum round-trip time in milliseconds"),
		mk("network.ping.rtt_stddev_ms", stddevMs, "Round-trip time standard deviation in milliseconds"),
		mk("network.ping.packets_sent", float64(stats.packetsSent), "Packets sent in this probe cycle"),
		mk("network.ping.packets_received", float64(stats.packetsReceived), "Packets received in this probe cycle"),
		mk("network.ping.loss_percent", loss, "Packet loss percentage (0-100)"),
		mk("network.ping.ttl", float64(stats.ttl), "Time-to-live of last received reply (0 when unavailable)"),
		mk("network.ping.state", float64(stats.state), "Target state: 1 = up, 0 = down"),
	)
	return out
}

func durationToMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1e6
}

// defaultPinger implements pinger using golang.org/x/net/icmp.
type defaultPinger struct {
	privileged bool
	interval   time.Duration
	logger     *zap.Logger
}

func (p *defaultPinger) ping(host string, count int, timeout time.Duration) (pingStats, error) {
	stats := pingStats{host: host}

	ips, err := net.LookupIP(host)
	if err != nil {
		return stats, fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(ips) == 0 {
		return stats, fmt.Errorf("lookup %s: no addresses", host)
	}
	// Prefer IPv4 to match the ip4/udp4 transport below.
	var ip net.IP
	for _, cand := range ips {
		if v4 := cand.To4(); v4 != nil {
			ip = v4
			break
		}
	}
	if ip == nil {
		ip = ips[0]
	}
	stats.resolvedIP = ip.String()

	network := "udp4"
	if p.privileged {
		network = "ip4:icmp"
	}
	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		if p.privileged {
			// Fall back to unprivileged UDP mode when raw sockets are denied.
			c, err = icmp.ListenPacket("udp4", "")
			if err != nil {
				return stats, fmt.Errorf("listen: %w", err)
			}
		} else {
			return stats, fmt.Errorf("listen: %w", err)
		}
	}
	defer func() { _ = c.Close() }()

	// ipv4.PacketConn gives access to TTL via ControlMessage on platforms
	// that expose IP_RECVTTL / IP_OPTIONS. It is non-nil for both udp4 and
	// ip4:icmp transports created by icmp.ListenPacket for ICMPv4.
	var pconn *ipv4.PacketConn
	if pc := c.IPv4PacketConn(); pc != nil {
		pconn = pc
		_ = pconn.SetControlMessage(ipv4.FlagTTL, true)
	}

	var dst net.Addr
	if p.privileged {
		dst = &net.IPAddr{IP: ip}
	} else {
		dst = &net.UDPAddr{IP: ip}
	}

	id := os.Getpid() & 0xffff
	proto := ipv4.ICMPTypeEcho.Protocol()

	for i := 0; i < count; i++ {
		// Timeout applies per reply wait, not to the whole cycle. This keeps
		// multi-packet probes useful even when timeout < count*interval.
		_ = c.SetReadDeadline(time.Now().Add(timeout))

		seq := i + 1
		wm := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte(pingPayload)},
		}
		wb, mErr := wm.Marshal(nil)
		if mErr != nil {
			continue
		}

		start := time.Now()
		if _, wErr := c.WriteTo(wb, dst); wErr != nil {
			continue
		}
		stats.packetsSent++

		rb := make([]byte, 1500)
		var n int
		var cm *ipv4.ControlMessage
		var rErr error
		if pconn != nil {
			n, cm, _, rErr = pconn.ReadFrom(rb)
		} else {
			n, _, rErr = c.ReadFrom(rb)
		}
		if rErr != nil {
			p.sleepBetween(i, count)
			continue
		}
		elapsed := time.Since(start)

		rm, pErr := icmp.ParseMessage(proto, rb[:n])
		if pErr != nil {
			p.sleepBetween(i, count)
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			p.sleepBetween(i, count)
			continue
		}
		stats.packetsReceived++
		stats.rtts = append(stats.rtts, elapsed)
		if cm != nil && cm.TTL > 0 {
			stats.ttl = cm.TTL
		}
		p.sleepBetween(i, count)
	}

	if stats.packetsReceived > 0 {
		stats.state = 1
	}
	return stats, nil
}

// sleepBetween waits IntervalBetween after every packet except the last so
// probe cycles don't waste time sleeping once the loop is done.
func (p *defaultPinger) sleepBetween(i, count int) {
	if i < count-1 {
		time.Sleep(p.interval)
	}
}

// Compile-time guard: PingCollector satisfies the collector.Collector interface.
var _ collector.Collector = (*PingCollector)(nil)
