// Package valkey implements a TelemetryFlow Agent collector for Valkey cache
// instances. Valkey speaks the Redis-compatible RESP wire protocol, so this
// collector reuses the redis package's RESP client and INFO parser. Metrics
// are emitted under the db.valkey.* namespace.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package valkey

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/redis"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "valkey"

// ValkeyCollector monitors one or more Valkey instances over RESP.
type ValkeyCollector struct {
	cfg    config.ValkeyCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewValkeyCollector creates a new ValkeyCollector.
func NewValkeyCollector(cfg config.ValkeyCollectorConfig, logger *zap.Logger) *ValkeyCollector {
	if cfg.InfoInterval == 0 {
		cfg.InfoInterval = 15 * time.Second
	}
	return &ValkeyCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *ValkeyCollector) Name() string { return collectorName }

func (c *ValkeyCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *ValkeyCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("valkey collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("Valkey collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("info_interval", c.cfg.InfoInterval),
	)
	return nil
}

func (c *ValkeyCollector) Stop() error {
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
func (c *ValkeyCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("Valkey collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *ValkeyCollector) collectInstance(ctx context.Context, inst config.ValkeyInstanceConfig) ([]collector.Metric, error) {
	client := redis.NewRespClient(inst.Host, inst.Port, inst.Password, inst.DB, inst.TLSEnabled, inst.TLSSkipVerify, 10*time.Second)
	if err := client.Connect(); err != nil {
		return nil, err
	}
	defer client.Close()

	info, err := client.BulkString([]string{"INFO", "all"})
	if err != nil {
		return nil, fmt.Errorf("INFO all: %w", err)
	}
	parsed := redis.ParseInfo(info)

	var commandStats map[string]string
	if inst.CollectCommandStats {
		if cmdInfo, err := client.BulkString([]string{"INFO", "commandstats"}); err == nil {
			commandStats = redis.ParseInfo(cmdInfo)
		}
	}

	labels := c.instanceLabels(inst)
	return BuildValkeyMetrics(parsed, commandStats, labels), nil
}

func (c *ValkeyCollector) instanceLabels(inst config.ValkeyInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["valkey_instance"] = inst.Name
	labels["valkey_host"] = inst.Host
	labels["db_system"] = "valkey"
	return labels
}

// BuildValkeyMetrics maps INFO key/value pairs to collector.Metric under the
// db.valkey.* namespace. Exported for external test coverage.
func BuildValkeyMetrics(info, commandStats, labels map[string]string) []collector.Metric {
	now := time.Now()
	mk := func(name string, v float64, typ collector.MetricType, unit string, desc string) collector.Metric {
		m := collector.Metric{
			Name: name, Type: typ, Value: v, Timestamp: now,
			Unit: unit, Description: desc,
			Labels: make(map[string]string, len(labels)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		return m
	}

	var out []collector.Metric
	gauge := func(infoKey, metric string, unit, desc string) {
		if raw, ok := info[infoKey]; ok {
			out = append(out, mk("db.valkey."+metric, redis.ToFloat(raw), collector.MetricTypeGauge, unit, desc))
		}
	}
	counter := func(infoKey, metric string, unit, desc string) {
		if raw, ok := info[infoKey]; ok {
			out = append(out, mk("db.valkey."+metric, redis.ToFloat(raw), collector.MetricTypeCounter, unit, desc))
		}
	}

	counter("uptime_in_seconds", "uptime_seconds", "s", "Server uptime in seconds")
	gauge("connected_clients", "connected_clients", "", "Connected client count")
	counter("rejected_connections", "rejected_connections", "", "Connections rejected due to maxclients")
	gauge("blocked_clients", "blocked_clients", "", "Clients blocked on commands")
	gauge("used_memory", "used_memory", "bytes", "Memory allocated by Valkey")
	gauge("used_memory_rss", "used_memory_rss", "bytes", "Memory as seen by the OS (RSS)")
	gauge("used_memory_peak", "used_memory_peak", "bytes", "Peak memory usage")
	gauge("maxmemory", "maxmemory", "bytes", "Configured maxmemory")
	gauge("mem_fragmentation_ratio", "mem_fragmentation_ratio", "", "used_memory_rss / used_memory")
	counter("expired_keys", "expired_keys", "", "Keys expired")
	counter("evicted_keys", "evicted_keys", "", "Keys evicted by maxmemory policy")
	gauge("keyspace_hits", "keyspace_hits", "", "Successful key lookups")
	gauge("keyspace_misses", "keyspace_misses", "", "Failed key lookups")
	counter("total_commands_processed", "total_commands_processed", "", "Commands processed")
	counter("instantaneous_ops_per_sec", "ops_per_sec", "ops/s", "Instantaneous ops per second")
	counter("net_input_bytes", "net_input_bytes", "bytes", "Network input bytes")
	counter("net_output_bytes", "net_output_bytes", "bytes", "Network output bytes")
	gauge("connected_slaves", "connected_slaves", "", "Connected replicas")
	counter("rdb_bgsave_in_progress", "rdb_bgsave_in_progress", "", "RDB bgsave in progress flag")
	gauge("aof_enabled", "aof_enabled", "", "AOF enabled flag")

	// Keyspace section.
	for k, v := range info {
		if !strings.HasPrefix(k, "db") || !strings.Contains(v, "keys=") {
			continue
		}
		dbName := k
		for _, p := range strings.Split(v, ",") {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			m := mk("db.valkey.keyspace."+kv[0], redis.ToFloat(kv[1]), collector.MetricTypeGauge, "", "Keyspace stat "+kv[0]+" for "+dbName)
			m.Labels["valkey_db"] = dbName
			out = append(out, m)
		}
	}

	// Command stats.
	for k, v := range commandStats {
		if !strings.HasPrefix(k, "cmdstat_") {
			continue
		}
		cmd := strings.TrimPrefix(k, "cmdstat_")
		for _, p := range strings.Split(v, ",") {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			m := mk("db.valkey.command."+kv[0], redis.ToFloat(kv[1]), collector.MetricTypeCounter, "", "Command stat "+kv[0]+" for "+cmd)
			m.Labels["valkey_command"] = cmd
			out = append(out, m)
		}
	}

	return out
}
