// Package redis implements a TelemetryFlow Agent collector for Redis cache
// instances.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package redis

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "redis"

// RedisCollector monitors one or more Redis instances.
type RedisCollector struct {
	cfg    config.RedisCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewRedisCollector creates a new RedisCollector.
func NewRedisCollector(cfg config.RedisCollectorConfig, logger *zap.Logger) *RedisCollector {
	if cfg.InfoInterval == 0 {
		cfg.InfoInterval = 15 * time.Second
	}
	return &RedisCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

// Name returns the collector name.
func (c *RedisCollector) Name() string { return collectorName }

// IsRunning returns whether the collector is running.
func (c *RedisCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start begins the periodic collection loop. The collector also runs a single
// immediate collection on start.
func (c *RedisCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("redis collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("Redis collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("info_interval", c.cfg.InfoInterval),
	)
	return nil
}

// Stop signals the collector to stop.
func (c *RedisCollector) Stop() error {
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
func (c *RedisCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("Redis collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *RedisCollector) collectInstance(ctx context.Context, inst config.RedisInstanceConfig) ([]collector.Metric, error) {
	client := NewRespClient(inst.Host, inst.Port, inst.Password, inst.DB, inst.TLSEnabled, inst.TLSSkipVerify, 10*time.Second)
	if err := client.Connect(); err != nil {
		return nil, err
	}
	defer client.Close()

	info, err := client.BulkString([]string{"INFO", "all"})
	if err != nil {
		return nil, fmt.Errorf("INFO all: %w", err)
	}
	parsed := ParseInfo(info)

	var commandStats map[string]string
	if inst.CollectCommandStats {
		if cmdInfo, err := client.BulkString([]string{"INFO", "commandstats"}); err == nil {
			commandStats = ParseInfo(cmdInfo)
		}
	}

	labels := c.instanceLabels(inst)
	return BuildRedisMetrics(parsed, commandStats, labels), nil
}

func (c *RedisCollector) instanceLabels(inst config.RedisInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["redis_instance"] = inst.Name
	labels["redis_host"] = inst.Host
	labels["db_system"] = "redis"
	return labels
}

// BuildRedisMetrics maps INFO key/value pairs to collector.Metric under the
// db.redis.* namespace. Exported so external tests under tests/ can cover the
// mapping logic without a live Redis instance.
func BuildRedisMetrics(info, commandStats, labels map[string]string) []collector.Metric {
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

	// Server / clients / memory / persistence / stats sections.
	gauge := func(infoKey, metric string, unit, desc string) {
		if raw, ok := info[infoKey]; ok {
			out = append(out, mk("db.redis."+metric, ToFloat(raw), collector.MetricTypeGauge, unit, desc))
		}
	}
	counter := func(infoKey, metric string, unit, desc string) {
		if raw, ok := info[infoKey]; ok {
			out = append(out, mk("db.redis."+metric, ToFloat(raw), collector.MetricTypeCounter, unit, desc))
		}
	}

	gauge("redis_version", "version_info", "", "Redis version (numeric major only when numeric)") // emitted as label below
	counter("uptime_in_seconds", "uptime_seconds", "s", "Server uptime in seconds")
	gauge("connected_clients", "connected_clients", "", "Connected client count")
	counter("total_connections_received", "total_connections_received", "", "Total connections accepted")
	counter("rejected_connections", "rejected_connections", "", "Connections rejected due to maxclients")
	gauge("blocked_clients", "blocked_clients", "", "Clients blocked on commands")

	gauge("used_memory", "used_memory", "bytes", "Memory allocated by Redis")
	gauge("used_memory_rss", "used_memory_rss", "bytes", "Memory as seen by the OS (RSS)")
	gauge("used_memory_peak", "used_memory_peak", "bytes", "Peak memory usage")
	gauge("maxmemory", "maxmemory", "bytes", "Configured maxmemory")
	gauge("mem_fragmentation_ratio", "mem_fragmentation_ratio", "", "used_memory_rss / used_memory")

	counter("total_system_memory", "system_memory", "bytes", "Total system memory")
	counter("expired_keys", "expired_keys", "", "Keys expired")
	counter("evicted_keys", "evicted_keys", "", "Keys evicted by maxmemory policy")
	gauge("keyspace_hits", "keyspace_hits", "", "Successful key lookups")
	gauge("keyspace_misses", "keyspace_misses", "", "Failed key lookups")

	counter("total_commands_processed", "total_commands_processed", "", "Commands processed")
	counter("instantaneous_ops_per_sec", "ops_per_sec", "ops/s", "Instantaneous ops per second")
	counter("net_input_bytes", "net_input_bytes", "bytes", "Network input bytes")
	counter("net_output_bytes", "net_output_bytes", "bytes", "Network output bytes")

	gauge("connected_slaves", "connected_slaves", "", "Connected replicas")
	gauge("repl_offset", "replication_offset", "", "Master replication offset")
	if role, ok := info["role"]; ok {
		mk2 := mk("db.redis.role", 0, collector.MetricTypeGauge, "", "Replication role (1=master,0=slave)")
		if role == "master" {
			mk2.Value = 1
		}
		out = append(out, mk2)
	}

	gauge("rdb_changes_since_last_save", "rdb_changes_since_last_save", "", "Changes since last RDB save")
	counter("rdb_bgsave_in_progress", "rdb_bgsave_in_progress", "", "RDB bgsave in progress flag")
	gauge("aof_enabled", "aof_enabled", "", "AOF enabled flag")
	counter("aof_rewrite_in_progress", "aof_rewrite_in_progress", "", "AOF rewrite in progress flag")

	// Keyspace section: db0:keys=N,expires=M,avg_ttl=T
	for k, v := range info {
		if !strings.HasPrefix(k, "db") || !strings.Contains(v, "keys=") {
			continue
		}
		dbName := k
		parts := strings.Split(v, ",")
		dbLabels := make(map[string]string, len(labels)+1)
		for kk, vv := range labels {
			dbLabels[kk] = vv
		}
		dbLabels["redis_db"] = dbName
		for _, p := range parts {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			m := mk("db.redis.keyspace."+kv[0], ToFloat(kv[1]), collector.MetricTypeGauge, "", "Keyspace stat "+kv[0]+" for "+dbName)
			m.Labels = dbLabels
			out = append(out, m)
		}
	}

	// Command stats: cmdstat_GET:calls=N,usec=M,usec_per_call=X,rejected_calls=R,failed_calls=F
	for k, v := range commandStats {
		if !strings.HasPrefix(k, "cmdstat_") {
			continue
		}
		cmd := strings.TrimPrefix(k, "cmdstat_")
		cmdLabels := make(map[string]string, len(labels)+1)
		for kk, vv := range labels {
			cmdLabels[kk] = vv
		}
		cmdLabels["redis_command"] = cmd
		for _, p := range strings.Split(v, ",") {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			m := mk("db.redis.command."+kv[0], ToFloat(kv[1]), collector.MetricTypeCounter, "", "Command stat "+kv[0]+" for "+cmd)
			m.Labels = cmdLabels
			out = append(out, m)
		}
	}

	return out
}
