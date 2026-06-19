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
			go handleFakeRedis(conn, infoBody)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func handleFakeRedis(conn net.Conn, infoBody string) {
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
			body := infoBody
			if len(args) > 1 && strings.EqualFold(args[1], "commandstats") {
				body = "cmdstat_GET:calls=500,usec=1000,usec_per_call=2.00\r\n"
			}
			_, _ = conn.Write([]byte("$" + strconv.Itoa(len(body)) + "\r\n" + body + "\r\n"))
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
	metrics := rediscol.BuildRedisMetrics(info, cmd, map[string]string{"env": "prod"})

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
			go handleFakeRedis(conn, infoBody)
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
	m := rediscol.BuildRedisMetrics(info, cmd, nil)
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
