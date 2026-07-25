// Package redis_test contains black-box unit tests for the Redis collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package redis_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	rediscol "github.com/telemetryflow/telemetryflow-agent/internal/collector/redis"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// startFakeRedis starts a minimal RESP server that replies to AUTH/SELECT/INFO.
// It returns the host:port and a stop function.
func startFakeRedis(t *testing.T, infoBody string) (string, func()) {
	t.Helper()
	return startFakeRedisExt(t, fakeRedisBodies{info: infoBody})
}

// fakeRedisBodies configures the canned replies returned by startFakeRedisExt
// for non-INFO commands. Empty fields yield the default -ERR reply.
type fakeRedisBodies struct {
	info    string
	cluster string
	latency string
}

func startFakeRedisExt(t *testing.T, bodies fakeRedisBodies) (string, func()) {
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
			go handleFakeRedis(conn, bodies)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func handleFakeRedis(conn net.Conn, bodies fakeRedisBodies) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		args, err := readRESPArray(r)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "AUTH":
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "SELECT":
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "INFO":
			body := bodies.info
			if len(args) > 1 && strings.EqualFold(args[1], "commandstats") {
				body = "cmdstat_GET:calls=500,usec=1000,usec_per_call=2.00\r\n"
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
			_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

// readRESPArray reads one RESP command array from the client.
func readRESPArray(r *bufio.Reader) ([]string, error) {
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
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, io.ErrUnexpectedEOF
		}
		ln, _ := strconv.Atoi(hdr[1:])
		buf := make([]byte, ln+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:ln]))
	}
	return args, nil
}

func TestParseInfo_BasicKeyValues(t *testing.T) {
	info := "# Server\r\nredis_version:7.2.0\r\nuptime_in_seconds:3600\r\n\r\n# Clients\r\nconnected_clients:42\r\n"
	m := rediscol.ParseInfo(info)
	if m["redis_version"] != "7.2.0" {
		t.Errorf("redis_version = %q", m["redis_version"])
	}
	if m["connected_clients"] != "42" {
		t.Errorf("connected_clients = %q", m["connected_clients"])
	}
	if _, ok := m["# Server"]; ok {
		t.Error("section header should not be stored")
	}
}

func TestParseInfo_IgnoresBlankAndMalformed(t *testing.T) {
	m := rediscol.ParseInfo("\r\n# Comment\r\n:noname\r\ngood:1\r\n")
	if len(m) != 1 {
		t.Fatalf("expected 1 key, got %d: %v", len(m), m)
	}
	if m["good"] != "1" {
		t.Errorf("good = %q", m["good"])
	}
}

func TestToFloat(t *testing.T) {
	if rediscol.ToFloat("3.5") != 3.5 {
		t.Error("3.5 parse failed")
	}
	if rediscol.ToFloat("notanumber") != 0 {
		t.Error("non-numeric should yield 0")
	}
}

func TestBuildRedisMetrics(t *testing.T) {
	info := map[string]string{
		"connected_clients":        "10",
		"used_memory":              "1048576",
		"mem_fragmentation_ratio":  "2.0",
		"total_commands_processed": "1000",
		"keyspace_hits":            "800",
		"db0":                      "keys=100,expires=20,avg_ttl=3600",
		"role":                     "master",
	}
	cmd := map[string]string{"cmdstat_GET": "calls=500,usec=1000,usec_per_call=2.00"}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{
		Info: info, CommandStats: cmd, Labels: map[string]string{"env": "prod"},
	})

	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
		if m.Labels["env"] != "prod" {
			t.Fatalf("label not preserved on %s", m.Name)
		}
	}
	for _, want := range []string{
		"db.redis.connected_clients", "db.redis.used_memory",
		"db.redis.mem_fragmentation_ratio", "db.redis.total_commands_processed",
		"db.redis.keyspace.keys", "db.redis.command.calls", "db.redis.role",
	} {
		if !names[want] {
			t.Errorf("missing metric %s", want)
		}
	}
}

func TestRedisCollector_LifecycleAndCollect(t *testing.T) {
	infoBody := "# Server\r\nredis_version:7.0.0\r\nuptime_in_seconds:100\r\n" +
		"connected_clients:5\r\nused_memory:2048\r\nused_memory_rss:4096\r\n" +
		"mem_fragmentation_ratio:2.0\r\nused_memory_peak:8192\r\nmaxmemory:0\r\n" +
		"total_commands_processed:42\r\ninstantaneous_ops_per_sec:7\r\n" +
		"net_input_bytes:10\r\nnet_output_bytes:20\r\nkeyspace_hits:30\r\n" +
		"keyspace_misses:3\r\nexpired_keys:1\r nevicted_keys:0\r\n" +
		"connected_slaves:0\r\nrepl_offset:0\r\nrole:slave\r\n" +
		"rdb_changes_since_last_save:0\r\naof_enabled:0\r\n" +
		"db0:keys=5,expires=1,avg_ttl=99\r\n"

	addr, stop := startFakeRedis(t, infoBody)
	defer stop()

	host, port := hostPort(addr)
	cfg := config.RedisCollectorConfig{
		Enabled: true,
		Instances: []config.RedisInstanceConfig{
			{Name: "test", Host: host, Port: port, Password: "secret", CollectCommandStats: true},
		},
		Tags: map[string]string{"env": "ci"},
	}
	c := rediscol.NewRedisCollector(cfg, testLogger())
	if c.Name() != "redis" {
		t.Fatalf("name = %q", c.Name())
	}
	if c.IsRunning() {
		t.Fatal("should not be running before Start")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("should be running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double Start should error")
	}

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics from fake server")
	}
	saw := map[string]bool{}
	for _, m := range metrics {
		saw[m.Name] = true
		if m.Labels["redis_instance"] != "test" {
			t.Errorf("missing redis_instance label on %s", m.Name)
		}
	}
	if !saw["db.redis.connected_clients"] {
		t.Error("connected_clients metric missing")
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("should not be running after Stop")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestRedisCollector_NoInstances(t *testing.T) {
	c := rediscol.NewRedisCollector(config.RedisCollectorConfig{Enabled: true}, testLogger())
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil metrics, got %d", len(m))
	}
}

func TestRedisCollector_ConnectionFailure(t *testing.T) {
	// Point at a closed port to exercise the error path (warn + skip).
	cfg := config.RedisCollectorConfig{
		Enabled: true,
		Instances: []config.RedisInstanceConfig{
			{Name: "down", Host: "127.0.0.1", Port: 1},
		},
	}
	c := rediscol.NewRedisCollector(cfg, testLogger())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should not return top-level error: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected no metrics on failure, got %d", len(m))
	}
}

func TestRedisCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*rediscol.RedisCollector)(nil)
}

func startFakeRedisTLS(t *testing.T, infoBody string) (string, func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go handleFakeRedis(conn, fakeRedisBodies{info: infoBody})
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestRedisCollector_TLSPath(t *testing.T) {
	infoBody := "connected_clients:3\r\nused_memory:1024\r\nrole:master\r\n"
	addr, stop := startFakeRedisTLS(t, infoBody)
	defer stop()
	host, port := hostPort(addr)

	cfg := config.RedisCollectorConfig{
		Enabled: true,
		Instances: []config.RedisInstanceConfig{
			{Name: "tls", Host: host, Port: port, TLSEnabled: true, TLSSkipVerify: true},
		},
	}
	c := rediscol.NewRedisCollector(cfg, testLogger())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect over TLS: %v", err)
	}
	if len(m) == 0 {
		t.Fatal("expected metrics over TLS path")
	}
}

func TestRespClient_BulkStringReplyVariants(t *testing.T) {
	cases := []struct {
		name    string
		reply   string
		wantErr bool
	}{
		{"error_reply", "-ERR boom\r\n", true},
		{"simple_string", "+OK\r\n", false},
		{"nil_bulk", "$-1\r\n", false},
		{"integer_reply", ":5\r\n", true}, // unexpected for bulk parser
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			go func() {
				conn, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				// consume one command, then reply with tc.reply
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte(tc.reply))
			}()
			host, port := hostPort(ln.Addr().String())
			cli := rediscol.NewRespClient(host, port, "", 0, false, false, time.Second)
			if err := cli.Connect(); err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer cli.Close()
			_, err = cli.BulkString([]string{"PING"})
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewRespClient_DefaultTimeout(t *testing.T) {
	// Passing zero timeout should fall back to the 10s default (exercises the
	// timeout<=0 branch in NewRespClient).
	c := rediscol.NewRespClient("127.0.0.1", 1, "", 0, false, false, 0)
	if err := c.Connect(); err == nil {
		t.Fatal("expected connection error to closed port")
	}
}

// startFakeRedisAuthFailing rejects AUTH with an error reply to cover the
// AUTH-failure branch of Connect.
func startFakeRedisAuthFailing(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			handleAuthFailing(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func handleAuthFailing(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	args, err := readRESPArray(r)
	if err != nil {
		return
	}
	if strings.EqualFold(args[0], "AUTH") {
		_, _ = conn.Write([]byte("-ERR invalid password\r\n"))
	}
}

func TestRespClient_AuthAndSelectFailure(t *testing.T) {
	t.Run("auth_rejected", func(t *testing.T) {
		addr, stop := startFakeRedisAuthFailing(t)
		defer stop()
		host, port := hostPort(addr)
		c := rediscol.NewRespClient(host, port, "wrong", 0, false, false, time.Second)
		if err := c.Connect(); err == nil {
			t.Fatal("expected AUTH failure error")
		}
	})
	t.Run("select_rejected", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			r := bufio.NewReader(conn)
			args, _ := readRESPArray(r)
			if strings.EqualFold(args[0], "AUTH") {
				_, _ = conn.Write([]byte("+OK\r\n"))
			}
			args2, _ := readRESPArray(r)
			if strings.EqualFold(args2[0], "SELECT") {
				_, _ = conn.Write([]byte("-ERR invalid DB index\r\n"))
			}
		}()
		host, port := hostPort(ln.Addr().String())
		c := rediscol.NewRespClient(host, port, "pw", 7, false, false, time.Second)
		if err := c.Connect(); err == nil {
			t.Fatal("expected SELECT failure error")
		}
	})
}

func TestBuildRedisMetrics_MalformedLines(t *testing.T) {
	// Malformed keyspace/commandstat entries (no '=') should be skipped.
	info := map[string]string{
		"db0": "keys=5,badentry,noeq",
	}
	cmd := map[string]string{
		"cmdstat_GET": "calls=5,badentry",
	}
	// Should not panic; valid entries still emitted.
	m := rediscol.BuildRedisMetrics(rediscol.MetricsInput{
		Info: info, CommandStats: cmd,
	})
	if len(m) < 2 {
		t.Fatalf("expected at least 2 metrics, got %d", len(m))
	}
}

func TestRedisCollector_CommandStatsDisabled(t *testing.T) {
	addr, stop := startFakeRedis(t, "connected_clients:1\r\nrole:master\r\n")
	defer stop()
	host, port := hostPort(addr)
	cfg := config.RedisCollectorConfig{
		Enabled: true,
		Instances: []config.RedisInstanceConfig{
			{Name: "x", Host: host, Port: port, CollectCommandStats: false, Tags: map[string]string{"tier": "cache"}},
		},
	}
	c := rediscol.NewRedisCollector(cfg, testLogger())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, met := range m {
		if met.Labels["tier"] != "cache" {
			t.Fatalf("instance tag not propagated on %s", met.Name)
		}
	}
}

// TestRespClient_BulkProtocolErrors covers the BulkString / readSimple /
// readFull error branches by feeding the client malformed or truncated replies.
func TestRespClient_BulkProtocolErrors(t *testing.T) {
	cases := []struct {
		name    string
		after   func(conn net.Conn) // writes canned bytes after reading one command
		wantErr bool
	}{
		{
			name:    "bad_bulk_length",
			after:   func(c net.Conn) { _, _ = c.Write([]byte("$abc\r\n")) },
			wantErr: true,
		},
		{
			name:    "truncated_bulk_body",
			after:   func(c net.Conn) { _, _ = c.Write([]byte("$10\r\nshort")) }, // announces 10, sends 5 then EOF
			wantErr: true,
		},
		{
			name:    "close_before_reply",
			after:   func(c net.Conn) {}, // server closes immediately
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			go func() {
				conn, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf) // consume one command
				tc.after(conn)
			}()
			host, port := hostPort(ln.Addr().String())
			c := rediscol.NewRespClient(host, port, "", 0, false, false, time.Second)
			if err := c.Connect(); err != nil {
				t.Fatalf("connect: %v", err)
			}
			_, err = c.BulkString([]string{"INFO"})
			if tc.wantErr && err == nil {
				t.Fatal("expected protocol error, got nil")
			}
			c.Close()
		})
	}
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	return h, port
}

func testLogger() *zap.Logger { return zap.NewNop() }

// ===========================================================================
// Bug 1 (P0): redis_version is a semver string; ToFloat on it returned 0.
// ParseSemver splits it into numeric major/minor/patch components.
// ===========================================================================

func TestParseSemver(t *testing.T) {
	cases := []struct {
		name                string
		in                  string
		major, minor, patch int
	}{
		{name: "typical_semver", in: "7.2.5", major: 7, minor: 2, patch: 5},
		{name: "major_only", in: "7", major: 7, minor: 0, patch: 0},
		{name: "major_minor", in: "7.2", major: 7, minor: 2, patch: 0},
		{name: "with_prerelease", in: "7.2.5-rc1", major: 7, minor: 2, patch: 5},
		{name: "empty", in: "", major: 0, minor: 0, patch: 0},
		{name: "non_numeric", in: "abc", major: 0, minor: 0, patch: 0},
		{name: "mixed", in: "7.x.5", major: 7, minor: 0, patch: 5},
		{name: "leading_zero", in: "07.02.05", major: 7, minor: 2, patch: 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			maj, min, patch := rediscol.ParseSemver(tc.in)
			if maj != tc.major || min != tc.minor || patch != tc.patch {
				t.Errorf("ParseSemver(%q) = (%d,%d,%d); want (%d,%d,%d)",
					tc.in, maj, min, patch, tc.major, tc.minor, tc.patch)
			}
		})
	}
}

func TestBuildRedisMetrics_VersionSemver(t *testing.T) {
	// Regression for the P0 bug where db.redis.version_info was always 0.
	// Input "7.2.5" must produce version_major=7, version_minor=2, version_patch=5.
	info := map[string]string{"redis_version": "7.2.5"}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{Info: info})
	want := map[string]float64{
		"db.redis.version_major": 7,
		"db.redis.version_minor": 2,
		"db.redis.version_patch": 5,
	}
	saw := map[string]float64{}
	for _, m := range metrics {
		if v, ok := want[m.Name]; ok {
			saw[m.Name] = m.Value
			_ = v
		}
	}
	for name, wantVal := range want {
		if saw[name] != wantVal {
			t.Errorf("%s = %v; want %v", name, saw[name], wantVal)
		}
	}
	// Sanity: the old broken metric name must no longer be emitted.
	for _, m := range metrics {
		if m.Name == "db.redis.version_info" {
			t.Errorf("legacy db.redis.version_info metric still emitted: %+v", m)
		}
	}
}

func TestBuildRedisMetrics_VersionMalformed(t *testing.T) {
	// Non-semver input must yield 0,0,0 rather than panicking.
	info := map[string]string{"redis_version": "nonsense"}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{Info: info})
	for _, m := range metrics {
		switch m.Name {
		case "db.redis.version_major", "db.redis.version_minor", "db.redis.version_patch":
			if m.Value != 0 {
				t.Errorf("%s = %v; want 0 for malformed input", m.Name, m.Value)
			}
		}
	}
}

// ===========================================================================
// Bug 3 (P1): CLUSTER INFO parsing.
// ===========================================================================

func TestParseClusterInfo(t *testing.T) {
	body := "cluster_enabled:1\r\ncluster_state:ok\r\n" +
		"cluster_slots_assigned:16384\r\ncluster_slots_ok:16384\r\n" +
		"cluster_known_nodes:6\r\n"
	m := rediscol.ParseClusterInfo(body)
	if m["cluster_state"] != "ok" {
		t.Errorf("cluster_state = %q", m["cluster_state"])
	}
	if m["cluster_slots_assigned"] != "16384" {
		t.Errorf("cluster_slots_assigned = %q", m["cluster_slots_assigned"])
	}
	if m["cluster_slots_ok"] != "16384" {
		t.Errorf("cluster_slots_ok = %q", m["cluster_slots_ok"])
	}
}

func TestBuildRedisMetrics_ClusterEnabledFlag(t *testing.T) {
	// cluster_enabled lives in INFO and must always emit a gauge, independent
	// of whether CLUSTER INFO was fetched.
	info := map[string]string{"cluster_enabled": "1"}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{Info: info})
	found := false
	for _, m := range metrics {
		if m.Name == "db.redis.cluster_enabled" && m.Value == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected db.redis.cluster_enabled=1 metric; not emitted")
	}
}

func TestBuildRedisMetrics_ClusterInfoMetrics(t *testing.T) {
	// When CLUSTER INFO is supplied, cluster_state + slots_* must be emitted.
	info := map[string]string{"cluster_enabled": "1"}
	cluster := map[string]string{
		"cluster_state":          "ok",
		"cluster_slots_assigned": "16384",
		"cluster_slots_ok":       "16300",
	}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{
		Info: info, ClusterInfo: cluster,
	})
	saw := map[string]float64{}
	for _, m := range metrics {
		saw[m.Name] = m.Value
	}
	if saw["db.redis.cluster_state"] != 1 {
		t.Errorf("cluster_state = %v; want 1 (ok)", saw["db.redis.cluster_state"])
	}
	if saw["db.redis.cluster_slots_assigned"] != 16384 {
		t.Errorf("cluster_slots_assigned = %v; want 16384", saw["db.redis.cluster_slots_assigned"])
	}
	if saw["db.redis.cluster_slots_ok"] != 16300 {
		t.Errorf("cluster_slots_ok = %v; want 16300", saw["db.redis.cluster_slots_ok"])
	}
}

func TestBuildRedisMetrics_ClusterStateFail(t *testing.T) {
	// cluster_state values other than "ok" must encode as 0.
	cluster := map[string]string{"cluster_state": "fail"}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{ClusterInfo: cluster})
	for _, m := range metrics {
		if m.Name == "db.redis.cluster_state" && m.Value != 0 {
			t.Errorf("cluster_state=fail should yield 0, got %v", m.Value)
		}
	}
}

// ===========================================================================
// Bug 2 (P1): LATENCY LATEST parsing.
// ===========================================================================

func TestParseLatencyLatest(t *testing.T) {
	body := "expire-cycle 1700000000 12 40\r\n" +
		"rdb-unicopy-aof-write 1700000001 5 25\r\n"
	m := rediscol.ParseLatencyLatest(body)
	if len(m) != 2 {
		t.Fatalf("expected 2 events, got %d: %v", len(m), m)
	}
	ev, ok := m["expire-cycle"]
	if !ok {
		t.Fatal("missing expire-cycle event")
	}
	if ev.Timestamp != 1700000000 {
		t.Errorf("timestamp = %d", ev.Timestamp)
	}
	if ev.LatencyMs != 12 {
		t.Errorf("latency_ms = %v", ev.LatencyMs)
	}
	if ev.MaxLatencyMs != 40 {
		t.Errorf("max_latency_ms = %v", ev.MaxLatencyMs)
	}
}

func TestParseLatencyLatest_Malformed(t *testing.T) {
	// Lines with too few fields or blank lines are skipped without panic.
	body := "\r\none-field-only\r\nok 1700 5\r\n"
	m := rediscol.ParseLatencyLatest(body)
	if len(m) != 1 {
		t.Fatalf("expected 1 event after skipping malformed lines, got %d: %v", len(m), m)
	}
	if _, ok := m["ok"]; !ok {
		t.Errorf("missing 'ok' event: %v", m)
	}
}

func TestBuildRedisMetrics_Latency(t *testing.T) {
	// LATENCY data must produce latency_ms + latency_max_ms per event, tagged
	// with redis_event.
	latency := map[string]rediscol.LatencyEvent{
		"expire-cycle": {Event: "expire-cycle", LatencyMs: 12, MaxLatencyMs: 40, Timestamp: 1700},
	}
	metrics := rediscol.BuildRedisMetrics(rediscol.MetricsInput{
		Latency: latency, Labels: map[string]string{"env": "prod"},
	})
	saw := map[string]map[string]float64{} // metric_name -> label_value -> value
	for _, m := range metrics {
		if m.Name != "db.redis.latency_ms" && m.Name != "db.redis.latency_max_ms" {
			continue
		}
		if saw[m.Name] == nil {
			saw[m.Name] = map[string]float64{}
		}
		saw[m.Name][m.Labels["redis_event"]] = m.Value
		if m.Labels["env"] != "prod" {
			t.Errorf("base label env=prod missing on %s", m.Name)
		}
	}
	if saw["db.redis.latency_ms"]["expire-cycle"] != 12 {
		t.Errorf("latency_ms wrong: %v", saw["db.redis.latency_ms"])
	}
	if saw["db.redis.latency_max_ms"]["expire-cycle"] != 40 {
		t.Errorf("latency_max_ms wrong: %v", saw["db.redis.latency_max_ms"])
	}
}

// ===========================================================================
// End-to-end (fake server) coverage for cluster + latency collection paths.
// ===========================================================================

func TestRedisCollector_ClusterAndLatencyPath(t *testing.T) {
	infoBody := "redis_version:7.2.5\r\ncluster_enabled:1\r\nconnected_clients:1\r\nrole:master\r\n"
	clusterBody := "cluster_state:ok\r\ncluster_slots_assigned:16384\r\ncluster_slots_ok:16384\r\n"
	latencyBody := "expire-cycle 1700000000 12 40\r\n"
	addr, stop := startFakeRedisExt(t, fakeRedisBodies{
		info:    infoBody,
		cluster: clusterBody,
		latency: latencyBody,
	})
	defer stop()
	host, port := hostPort(addr)

	cfg := config.RedisCollectorConfig{
		Enabled: true,
		Instances: []config.RedisInstanceConfig{
			{
				Name: "c", Host: host, Port: port,
				CollectLatency: true, CollectCommandStats: false,
			},
		},
	}
	c := rediscol.NewRedisCollector(cfg, testLogger())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := map[string]bool{
		"db.redis.version_major":          true,
		"db.redis.version_minor":          true,
		"db.redis.version_patch":          true,
		"db.redis.cluster_enabled":        true,
		"db.redis.cluster_state":          true,
		"db.redis.cluster_slots_assigned": true,
		"db.redis.cluster_slots_ok":       true,
		"db.redis.latency_ms":             true,
		"db.redis.latency_max_ms":         true,
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
