// Package memcache implements a TelemetryFlow Agent collector for Memcached
// instances. It connects over TCP and collects the `stats`, `stats settings`,
// and (optionally) `stats slabs` / `stats items` output. No external client
// library is required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package memcache

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "memcache"

// MemcacheCollector monitors one or more Memcached instances.
type MemcacheCollector struct {
	cfg      config.MemcacheCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

func NewMemcacheCollector(cfg config.MemcacheCollectorConfig, logger *zap.Logger) *MemcacheCollector {
	if cfg.StatsInterval == 0 {
		cfg.StatsInterval = 15 * time.Second
	}
	return &MemcacheCollector{cfg: cfg, logger: logger.Named(collectorName), stopChan: make(chan struct{})}
}

func (c *MemcacheCollector) Name() string    { return collectorName }
func (c *MemcacheCollector) IsRunning() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.running }

func (c *MemcacheCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("memcache collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("Memcache collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *MemcacheCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances.
func (c *MemcacheCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		m, err := c.collectInstance(inst)
		if err != nil {
			c.logger.Warn("Memcache collection failed", zap.String("instance", inst.Name), zap.Error(err))
			continue
		}
		all = append(all, m...)
	}
	return all, nil
}

func (c *MemcacheCollector) collectInstance(inst config.MemcacheInstanceConfig) ([]collector.Metric, error) {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(inst.Host, strconv.Itoa(inst.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	r := bufio.NewReader(conn)
	stats, err := queryStats(conn, r, "stats")
	if err != nil {
		return nil, fmt.Errorf("stats: %w", err)
	}
	var slabs map[string]string
	if inst.CollectSlabStats {
		if s, err := queryStats(conn, r, "stats slabs"); err == nil {
			slabs = s
		}
	}

	labels := c.instanceLabels(inst)
	return BuildMemcacheMetrics(stats, slabs, labels), nil
}

func (c *MemcacheCollector) instanceLabels(inst config.MemcacheInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["memcache_instance"] = inst.Name
	labels["memcache_host"] = inst.Host
	labels["db_system"] = "memcache"
	return labels
}

// queryStats sends a stats command and parses STAT lines until END.
func queryStats(conn net.Conn, r *bufio.Reader, cmd string) (map[string]string, error) {
	if _, err := conn.Write([]byte(cmd + "\r\n")); err != nil {
		return nil, fmt.Errorf("write %s: %w", cmd, err)
	}
	out := make(map[string]string)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", cmd, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "END" || line == "ERROR" {
			break
		}
		if !strings.HasPrefix(line, "STAT ") {
			continue
		}
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) != 2 {
			continue
		}
		out[parts[0]] = parts[1]
	}
	return out, nil
}

// BuildMemcacheMetrics maps Memcached STAT key/value pairs to collector.Metric
// under the db.memcache.* namespace.
func BuildMemcacheMetrics(stats, slabs, labels map[string]string) []collector.Metric {
	now := time.Now()
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string) collector.Metric {
		m := collector.Metric{
			Name: name, Type: typ, Value: v, Timestamp: now, Unit: unit, Description: desc,
			Labels: make(map[string]string, len(labels)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		return m
	}
	var out []collector.Metric
	gauge := func(key, metric, unit, desc string) {
		if raw, ok := stats[key]; ok {
			mk2 := mk("db.memcache."+metric, toF(raw), collector.MetricTypeGauge, unit, desc)
			out = append(out, mk2)
		}
	}
	counter := func(key, metric, unit, desc string) {
		if raw, ok := stats[key]; ok {
			mk2 := mk("db.memcache."+metric, toF(raw), collector.MetricTypeCounter, unit, desc)
			out = append(out, mk2)
		}
	}

	gauge("uptime", "uptime_seconds", "s", "Server uptime in seconds")
	gauge("curr_connections", "current_connections", "", "Current connections")
	gauge("total_connections", "total_connections", "", "Total connections opened")
	counter("cmd_get", "cmd_get", "", "GET commands")
	counter("cmd_set", "cmd_set", "", "SET commands")
	counter("get_hits", "get_hits", "", "GET hits")
	counter("get_misses", "get_misses", "", "GET misses")
	counter("bytes_read", "bytes_read", "bytes", "Bytes read from network")
	counter("bytes_written", "bytes_written", "bytes", "Bytes written to network")
	gauge("bytes", "bytes", "bytes", "Current bytes in use")
	gauge("limit_maxbytes", "maxbytes", "bytes", "Storage capacity")
	gauge("curr_items", "current_items", "", "Current items stored")
	counter("total_items", "total_items", "", "Total items ever stored")
	counter("evictions", "evictions", "", "Evictions due to memory limit")
	gauge("threads", "threads", "", "Worker threads")

	// Hit ratio derived from get_hits / (get_hits + get_misses).
	hits := toF(stats["get_hits"])
	misses := toF(stats["get_misses"])
	if hits+misses > 0 {
		out = append(out, mk("db.memcache.get_hit_ratio", hits/(hits+misses), collector.MetricTypeGauge, "ratio", "GET hit ratio"))
	}

	// Slab stats: slabId stats are emitted with a slab label.
	for k, v := range slabs {
		// e.g. "1:chunk_size" -> slab=1, metric=chunk_size
		idx := strings.IndexByte(k, ':')
		if idx <= 0 {
			continue
		}
		slab := k[:idx]
		field := k[idx+1:]
		m := mk("db.memcache.slab."+field, toF(v), collector.MetricTypeGauge, "", "Slab "+field+" for slab "+slab)
		m.Labels["memcache_slab"] = slab
		out = append(out, m)
	}
	return out
}

func toF(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
