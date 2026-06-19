// Package memcache_test contains black-box unit tests for the Memcache collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package memcache_test

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	memcachecol "github.com/telemetryflow/telemetryflow-agent/internal/collector/memcache"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// startFakeMemcache serves canned STAT responses for stats / stats slabs.
func startFakeMemcache(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeMemcache(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func handleFakeMemcache(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch cmd {
		case "stats":
			body := "STAT pid 1\r\nSTAT uptime 100\r\nSTAT curr_connections 5\r\n" +
				"STAT total_connections 10\r\nSTAT cmd_get 100\r\nSTAT cmd_set 50\r\n" +
				"STAT get_hits 90\r\nSTAT get_misses 10\r\nSTAT bytes_read 1024\r\n" +
				"STAT bytes_written 2048\r\nSTAT bytes 512\r\nSTAT limit_maxbytes 67108864\r\n" +
				"STAT curr_items 8\r\nSTAT total_items 20\r\nSTAT evictions 1\r\nSTAT threads 4\r\nEND\r\n"
			_, _ = conn.Write([]byte(body))
		case "stats slabs":
			body := "STAT 1:chunk_size 96\r\nSTAT 1:chunks_per_page 10922\r\n" +
				"STAT 1:total_pages 1\r\nSTAT 1:total_chunks 10922\r\nSTAT 1:used_chunks 5\r\nEND\r\n"
			_, _ = conn.Write([]byte(body))
		case "stats settings":
			_, _ = conn.Write([]byte("STAT maxbytes 67108864\r\nEND\r\n"))
		default:
			_, _ = conn.Write([]byte("ERROR\r\n"))
		}
	}
}

func TestBuildMemcacheMetrics(t *testing.T) {
	stats := map[string]string{
		"uptime": "100", "curr_connections": "5", "cmd_get": "100", "cmd_set": "50",
		"get_hits": "90", "get_misses": "10", "bytes": "512", "curr_items": "8", "evictions": "1", "threads": "4",
	}
	slabs := map[string]string{"1:chunk_size": "96", "bad_no_colon": "x"}
	metrics := memcachecol.BuildMemcacheMetrics(stats, slabs, map[string]string{"env": "ci"})
	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
		if m.Labels["env"] != "ci" {
			t.Fatalf("label not preserved on %s", m.Name)
		}
	}
	for _, want := range []string{
		"db.memcache.uptime_seconds", "db.memcache.current_connections",
		"db.memcache.cmd_get", "db.memcache.get_hit_ratio",
		"db.memcache.slab.chunk_size",
	} {
		if !names[want] {
			t.Errorf("missing metric %s", want)
		}
	}
}

func TestMemcacheCollector_LifecycleAndCollect(t *testing.T) {
	addr, stop := startFakeMemcache(t)
	defer stop()
	host, port := hostPort(addr)
	cfg := config.MemcacheCollectorConfig{
		Enabled: true,
		Instances: []config.MemcacheInstanceConfig{
			{Name: "m", Host: host, Port: port, CollectSlabStats: true, Tags: map[string]string{"tier": "cache"}},
		},
		Tags: map[string]string{"env": "ci"},
	}
	c := memcachecol.NewMemcacheCollector(cfg, zap.NewNop())
	if c.Name() != "memcache" {
		t.Fatalf("name=%q", c.Name())
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("not running")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double start should fail")
	}
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(m) == 0 {
		t.Fatal("expected metrics")
	}
	for _, met := range m {
		if met.Labels["memcache_instance"] != "m" || met.Labels["tier"] != "cache" {
			t.Errorf("labels missing on %s: %+v", met.Name, met.Labels)
		}
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestMemcacheCollector_SlabsDisabled(t *testing.T) {
	addr, stop := startFakeMemcache(t)
	defer stop()
	host, port := hostPort(addr)
	cfg := config.MemcacheCollectorConfig{
		Enabled: true,
		Instances: []config.MemcacheInstanceConfig{
			{Name: "m", Host: host, Port: port, CollectSlabStats: false},
		},
	}
	c := memcachecol.NewMemcacheCollector(cfg, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

func TestMemcacheCollector_NoInstances(t *testing.T) {
	c := memcachecol.NewMemcacheCollector(config.MemcacheCollectorConfig{Enabled: true}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestMemcacheCollector_ConnectionFailure(t *testing.T) {
	cfg := config.MemcacheCollectorConfig{
		Enabled: true,
		Instances: []config.MemcacheInstanceConfig{
			{Name: "down", Host: "127.0.0.1", Port: 1},
		},
	}
	c := memcachecol.NewMemcacheCollector(cfg, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("top-level error: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected no metrics, got %d", len(m))
	}
}

func TestMemcacheCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*memcachecol.MemcacheCollector)(nil)
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	return h, port
}
