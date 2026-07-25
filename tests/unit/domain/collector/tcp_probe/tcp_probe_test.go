// Package tcp_probe_test contains black-box unit tests for the tcp_probe collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package tcp_probe_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	tcpprobe "github.com/telemetryflow/telemetryflow-agent/internal/collector/tcp_probe"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// startEchoListener opens a TCP listener that echoes received bytes back.
func startEchoListener(t *testing.T) (string, func()) {
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
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// startAcceptListener opens a listener that accepts and immediately closes.
func startAcceptListener(t *testing.T) (string, func()) {
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
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// startUDPEcho opens a UDP listener that echoes received datagrams.
func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenpacket: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	stop := func() { _ = pc.Close() }
	return pc.LocalAddr().String(), stop
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	return h, port
}

func TestTCPProbeCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*tcpprobe.TCPProbeCollector)(nil)
}

func TestTCPProbeCollector_Name(t *testing.T) {
	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{}, zap.NewNop())
	if c.Name() != "tcp_probe" {
		t.Fatalf("name=%q", c.Name())
	}
}

func TestTCPProbeCollector_Lifecycle(t *testing.T) {
	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{}, zap.NewNop())
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("not running")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double start should fail")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestTCPProbeCollector_NoTargets(t *testing.T) {
	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{Enabled: true}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestTCPProbeCollector_OpenPort(t *testing.T) {
	addr, stop := startAcceptListener(t)
	defer stop()
	host, port := hostPort(addr)

	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{
		Enabled: true,
		Targets: []config.TCPProbeTarget{
			{Name: "ep", Host: host, Port: port},
		},
	}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantNames := map[string]bool{
		"network.tcp.connect_time_ms":  false,
		"network.tcp.response_time_ms": false,
		"network.tcp.state":            false,
		"network.tcp.string_found":     false,
	}
	var state float64
	for _, met := range m {
		if want, ok := wantNames[met.Name]; ok && !want {
			wantNames[met.Name] = true
		}
		if met.Labels["target"] != "ep" || met.Labels["host"] != host ||
			met.Labels["port"] != strconv.Itoa(port) || met.Labels["protocol"] != "tcp" {
			t.Errorf("labels wrong on %s: %+v", met.Name, met.Labels)
		}
		if met.Name == "network.tcp.state" {
			state = met.Value
		}
		if met.Name == "network.tcp.connect_time_ms" && met.Value < 0 {
			t.Errorf("connect_time_ms negative: %v", met.Value)
		}
	}
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("missing metric %s", name)
		}
	}
	if state != 1 {
		t.Errorf("expected state=1 for open port, got %v", state)
	}
}

func TestTCPProbeCollector_ClosedPort(t *testing.T) {
	// Find a port that's not listening: open then close immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := hostPort(ln.Addr().String())
	_ = ln.Close()

	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{
		Enabled: true,
		Targets: []config.TCPProbeTarget{
			{Name: "down", Host: host, Port: port, Timeout: time.Second},
		},
	}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var state float64
	var stateSeen bool
	for _, met := range m {
		if met.Name == "network.tcp.state" {
			state = met.Value
			stateSeen = true
		}
	}
	if !stateSeen {
		t.Fatal("expected state metric even on failure")
	}
	if state != 0 {
		t.Errorf("expected state=0 for closed port, got %v", state)
	}
}

func TestTCPProbeCollector_SendExpect(t *testing.T) {
	addr, stop := startEchoListener(t)
	defer stop()
	host, port := hostPort(addr)

	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{
		Enabled: true,
		Targets: []config.TCPProbeTarget{
			{Name: "echo", Host: host, Port: port, Send: "PING", Expect: "PIN"},
		},
	}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var found float64
	var state float64
	var respSeen bool
	for _, met := range m {
		switch met.Name {
		case "network.tcp.string_found":
			found = met.Value
		case "network.tcp.state":
			state = met.Value
		case "network.tcp.response_time_ms":
			respSeen = true
			if met.Value < 0 {
				t.Errorf("response_time_ms negative: %v", met.Value)
			}
		}
	}
	if state != 1 {
		t.Errorf("expected state=1, got %v", state)
	}
	if found != 1 {
		t.Errorf("expected string_found=1, got %v", found)
	}
	if !respSeen {
		t.Error("expected response_time_ms metric")
	}
}

func TestTCPProbeCollector_UDPSmoke(t *testing.T) {
	addr, stop := startUDPEcho(t)
	defer stop()
	host, port := hostPort(addr)

	// UDP semantics are loose: just confirm we don't crash and emit metrics.
	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{
		Enabled: true,
		Targets: []config.TCPProbeTarget{
			{Name: "udp", Host: host, Port: port, Protocol: "udp", Send: "hi", Expect: "hi"},
		},
	}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var stateMetric bool
	for _, met := range m {
		if met.Labels["protocol"] != "udp" {
			t.Errorf("expected protocol=udp label, got %+v", met.Labels)
		}
		if met.Name == "network.tcp.state" {
			stateMetric = true
		}
	}
	if !stateMetric {
		t.Error("expected state metric emitted for UDP target")
	}
}

func TestTCPProbeCollector_Defaults(t *testing.T) {
	c := tcpprobe.NewTCPProbeCollector(config.TCPProbeCollectorConfig{
		Enabled: true,
		Targets: []config.TCPProbeTarget{
			{Name: "x", Host: "127.0.0.1", Port: 12345},
		},
	}, zap.NewNop())
	// Defaults are applied inside the constructor; verify by probing against a
	// closed port and checking that the cycle completes without hanging.
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()

	done := make(chan struct{})
	go func() {
		_, _ = c.Collect(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Collect hung; default timeout likely not applied")
	}
}
