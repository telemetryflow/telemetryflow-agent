// Package valkey_test contains black-box unit tests for the Valkey collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package valkey_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/redis"
	valkeycol "github.com/telemetryflow/telemetryflow-agent/internal/collector/valkey"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func startFakeValkey(t *testing.T, infoBody string) (string, func()) {
	t.Helper()
	return startFakeValkeyExt(t, fakeValkeyBodies{info: infoBody})
}

// fakeValkeyBodies configures the canned replies returned by the fake server
// for non-INFO commands. Empty fields yield a default -ERR reply.
type fakeValkeyBodies struct {
	info    string
	cluster string
	latency string
}

func startFakeValkeyExt(t *testing.T, bodies fakeValkeyBodies) (string, func()) {
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
			go handleFakeValkey(conn, bodies)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func handleFakeValkey(conn net.Conn, bodies fakeValkeyBodies) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		args, err := readArr(r)
		if err != nil {
			return
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH", "SELECT":
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "INFO":
			body := bodies.info
			if len(args) > 1 && strings.EqualFold(args[1], "commandstats") {
				body = "cmdstat_GET:calls=10,usec=20\r\n"
			}
			_, _ = conn.Write([]byte("$" + strconv.Itoa(len(body)) + "\r\n" + body + "\r\n"))
		case "CLUSTER":
			if bodies.cluster == "" {
				_, _ = conn.Write([]byte("-ERR cluster disabled\r\n"))
			} else {
				_, _ = conn.Write([]byte("$" + strconv.Itoa(len(bodies.cluster)) + "\r\n" + bodies.cluster + "\r\n"))
			}
		case "LATENCY":
			if bodies.latency == "" {
				_, _ = conn.Write([]byte("-ERR latency disabled\r\n"))
			} else {
				_, _ = conn.Write([]byte("$" + strconv.Itoa(len(bodies.latency)) + "\r\n" + bodies.latency + "\r\n"))
			}
		default:
			_, _ = conn.Write([]byte("-ERR unknown\r\n"))
		}
	}
}

func readArr(r *bufio.Reader) ([]string, error) {
	first, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	first = strings.TrimRight(first, "\r\n")
	if first == "" || first[0] != '*' {
		return nil, io.ErrUnexpectedEOF
	}
	n, _ := strconv.Atoi(first[1:])
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		ln, _ := strconv.Atoi(hdr[1:])
		buf := make([]byte, ln+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:ln]))
	}
	return args, nil
}

func TestBuildValkeyMetrics(t *testing.T) {
	info := map[string]string{
		"connected_clients":        "8",
		"used_memory":              "524288",
		"total_commands_processed": "500",
		"db0":                      "keys=50,expires=10,avg_ttl=1200",
		"role":                     "master",
	}
	cmd := map[string]string{"cmdstat_GET": "calls=10,usec=20"}
	metrics := valkeycol.BuildValkeyMetrics(valkeycol.MetricsInput{
		Info: info, CommandStats: cmd, Labels: map[string]string{"env": "stg"},
	})
	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
		if m.Labels["env"] != "stg" {
			t.Fatalf("label not preserved on %s", m.Name)
		}
	}
	for _, want := range []string{
		"db.valkey.connected_clients", "db.valkey.used_memory",
		"db.valkey.total_commands_processed", "db.valkey.keyspace.keys",
		"db.valkey.command.calls",
	} {
		if !names[want] {
			t.Errorf("missing metric %s", want)
		}
	}
}

func TestBuildValkeyMetrics_Malformed(t *testing.T) {
	// Mix valid and malformed parts: valid entries emit metrics, malformed
	// parts (no '=') are skipped without panic.
	m := valkeycol.BuildValkeyMetrics(valkeycol.MetricsInput{
		Info:         map[string]string{"db0": "keys=5,badentry,noeq"},
		CommandStats: map[string]string{"cmdstat_GET": "calls=9,badentry"},
	})
	if len(m) < 2 {
		t.Fatalf("expected metrics despite malformed parts, got %d", len(m))
	}
}

func TestValkeyCollector_LifecycleAndCollect(t *testing.T) {
	infoBody := "connected_clients:4\r\nused_memory:2048\r\nused_memory_rss:4096\r\n" +
		"mem_fragmentation_ratio:2.0\r\nused_memory_peak:8192\r\nmaxmemory:0\r\n" +
		"total_commands_processed:7\r\ninstantaneous_ops_per_sec:1\r\nnet_input_bytes:2\r\n" +
		"net_output_bytes:3\r\nkeyspace_hits:4\r\nkeyspace_misses:1\r\nexpired_keys:0\r\n" +
		"blocked_clients:0\r\nconnected_slaves:0\r\naof_enabled:0\r\nrdb_bgsave_in_progress:0\r\n" +
		"db0:keys=2,expires=0,avg_ttl=0\r\n"
	addr, stop := startFakeValkey(t, infoBody)
	defer stop()
	host, port := hostPort(addr)

	cfg := config.ValkeyCollectorConfig{
		Enabled: true,
		Instances: []config.ValkeyInstanceConfig{
			{Name: "v", Host: host, Port: port, CollectCommandStats: true, Tags: map[string]string{"team": "cache"}},
		},
		Tags: map[string]string{"env": "ci"},
	}
	c := valkeycol.NewValkeyCollector(cfg, zap.NewNop())
	if c.Name() != "valkey" {
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
		if met.Labels["valkey_instance"] != "v" {
			t.Errorf("missing instance label on %s", met.Name)
		}
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestValkeyCollector_NoInstances(t *testing.T) {
	c := valkeycol.NewValkeyCollector(config.ValkeyCollectorConfig{Enabled: true}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestValkeyCollector_ConnectionFailure(t *testing.T) {
	cfg := config.ValkeyCollectorConfig{
		Enabled: true,
		Instances: []config.ValkeyInstanceConfig{
			{Name: "down", Host: "127.0.0.1", Port: 1},
		},
	}
	c := valkeycol.NewValkeyCollector(cfg, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect top-level error: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected no metrics, got %d", len(m))
	}
}

func TestValkeyCollector_CommandStatsDisabled(t *testing.T) {
	addr, stop := startFakeValkey(t, "connected_clients:1\r\n")
	defer stop()
	host, port := hostPort(addr)
	cfg := config.ValkeyCollectorConfig{
		Enabled: true,
		Instances: []config.ValkeyInstanceConfig{
			{Name: "v", Host: host, Port: port, CollectCommandStats: false},
		},
	}
	c := valkeycol.NewValkeyCollector(cfg, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

func TestValkeyCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*valkeycol.ValkeyCollector)(nil)
	var _ = redis.ToFloat // ensure cross-package reuse compiles
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	return h, port
}

// ===========================================================================
// Parity with Redis: version semver, cluster, and latency metrics.
// ===========================================================================

func TestBuildValkeyMetrics_VersionSemver(t *testing.T) {
	// valkey_version mirrors redis_version; the same semver split applies.
	info := map[string]string{"valkey_version": "8.0.2"}
	metrics := valkeycol.BuildValkeyMetrics(valkeycol.MetricsInput{Info: info})
	want := map[string]float64{
		"db.valkey.version_major": 8,
		"db.valkey.version_minor": 0,
		"db.valkey.version_patch": 2,
	}
	saw := map[string]float64{}
	for _, m := range metrics {
		if _, ok := want[m.Name]; ok {
			saw[m.Name] = m.Value
		}
	}
	for name, wantVal := range want {
		if saw[name] != wantVal {
			t.Errorf("%s = %v; want %v", name, saw[name], wantVal)
		}
	}
}

func TestBuildValkeyMetrics_ClusterEnabledFlag(t *testing.T) {
	info := map[string]string{"cluster_enabled": "1"}
	metrics := valkeycol.BuildValkeyMetrics(valkeycol.MetricsInput{Info: info})
	found := false
	for _, m := range metrics {
		if m.Name == "db.valkey.cluster_enabled" && m.Value == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected db.valkey.cluster_enabled=1 metric; not emitted")
	}
}

func TestBuildValkeyMetrics_ClusterInfoMetrics(t *testing.T) {
	info := map[string]string{"cluster_enabled": "1"}
	cluster := map[string]string{
		"cluster_state":          "ok",
		"cluster_slots_assigned": "16384",
		"cluster_slots_ok":       "16300",
	}
	metrics := valkeycol.BuildValkeyMetrics(valkeycol.MetricsInput{
		Info: info, ClusterInfo: cluster,
	})
	saw := map[string]float64{}
	for _, m := range metrics {
		saw[m.Name] = m.Value
	}
	if saw["db.valkey.cluster_state"] != 1 {
		t.Errorf("cluster_state = %v; want 1 (ok)", saw["db.valkey.cluster_state"])
	}
	if saw["db.valkey.cluster_slots_assigned"] != 16384 {
		t.Errorf("cluster_slots_assigned = %v; want 16384", saw["db.valkey.cluster_slots_assigned"])
	}
	if saw["db.valkey.cluster_slots_ok"] != 16300 {
		t.Errorf("cluster_slots_ok = %v; want 16300", saw["db.valkey.cluster_slots_ok"])
	}
}

func TestBuildValkeyMetrics_Latency(t *testing.T) {
	// LATENCY data uses redis.LatencyEvent — the same struct the redis
	// package exposes — and is tagged with valkey_event.
	latency := map[string]redis.LatencyEvent{
		"expire-cycle": {Event: "expire-cycle", LatencyMs: 12, MaxLatencyMs: 40, Timestamp: 1700},
	}
	metrics := valkeycol.BuildValkeyMetrics(valkeycol.MetricsInput{
		Latency: latency, Labels: map[string]string{"env": "prod"},
	})
	saw := map[string]map[string]float64{}
	for _, m := range metrics {
		if m.Name != "db.valkey.latency_ms" && m.Name != "db.valkey.latency_max_ms" {
			continue
		}
		if saw[m.Name] == nil {
			saw[m.Name] = map[string]float64{}
		}
		saw[m.Name][m.Labels["valkey_event"]] = m.Value
		if m.Labels["env"] != "prod" {
			t.Errorf("base label env=prod missing on %s", m.Name)
		}
	}
	if saw["db.valkey.latency_ms"]["expire-cycle"] != 12 {
		t.Errorf("latency_ms wrong: %v", saw["db.valkey.latency_ms"])
	}
	if saw["db.valkey.latency_max_ms"]["expire-cycle"] != 40 {
		t.Errorf("latency_max_ms wrong: %v", saw["db.valkey.latency_max_ms"])
	}
}

func TestValkeyCollector_ClusterAndLatencyPath(t *testing.T) {
	infoBody := "valkey_version:8.0.2\r\ncluster_enabled:1\r\nconnected_clients:1\r\n"
	clusterBody := "cluster_state:ok\r\ncluster_slots_assigned:16384\r\ncluster_slots_ok:16384\r\n"
	latencyBody := "expire-cycle 1700000000 12 40\r\n"
	addr, stop := startFakeValkeyExt(t, fakeValkeyBodies{
		info:    infoBody,
		cluster: clusterBody,
		latency: latencyBody,
	})
	defer stop()
	host, port := hostPort(addr)

	cfg := config.ValkeyCollectorConfig{
		Enabled: true,
		Instances: []config.ValkeyInstanceConfig{
			{
				Name: "c", Host: host, Port: port,
				CollectLatency: true, CollectCommandStats: false,
			},
		},
	}
	c := valkeycol.NewValkeyCollector(cfg, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := map[string]bool{
		"db.valkey.version_major":          true,
		"db.valkey.version_minor":          true,
		"db.valkey.version_patch":          true,
		"db.valkey.cluster_enabled":        true,
		"db.valkey.cluster_state":          true,
		"db.valkey.cluster_slots_assigned": true,
		"db.valkey.cluster_slots_ok":       true,
		"db.valkey.latency_ms":             true,
		"db.valkey.latency_max_ms":         true,
	}
	saw := map[string]bool{}
	for _, m := range metrics {
		saw[m.Name] = true
	}
	for name := range want {
		if !saw[name] {
			t.Errorf("missing metric %s", name)
		}
	}
}
