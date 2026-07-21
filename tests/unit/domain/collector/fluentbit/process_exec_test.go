// Package fluentbit_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package fluentbit_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/fluentbit"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return p
}

func TestProcessManager_AccessorsInitialState(t *testing.T) {
	pm := fluentbit.NewProcessManager("/bin/true", "/tmp/x.conf", 0, false, time.Second, 3, zap.NewNop())
	if pm.IsRunning() {
		t.Error("should not be running")
	}
	if pm.PID() != 0 {
		t.Error("PID should be 0")
	}
	if pm.RestartCount() != 0 {
		t.Error("restart count should be 0")
	}
	if pm.UptimeSeconds() != 0 {
		t.Error("uptime should be 0")
	}
	// Stop with no started process returns nil.
	if err := pm.Stop(); err != nil {
		t.Errorf("Stop on idle: %v", err)
	}
}

func TestProcessManager_StderrBufferEviction(t *testing.T) {
	pm := fluentbit.NewProcessManager("/bin/true", "/tmp/x", 0, false, time.Second, 0, zap.NewNop())
	total := fluentbit.StderrBufferSizeExported() + 10
	for i := 0; i < total; i++ {
		pm.AppendStderrExported(fmt.Sprintf("line-%d", i))
	}
	lines := pm.RecentStderr()
	if len(lines) != fluentbit.StderrBufferSizeExported() {
		t.Fatalf("expected buffer capped at %d, got %d", fluentbit.StderrBufferSizeExported(), len(lines))
	}
	// Oldest lines evicted; last line should be present.
	if lines[len(lines)-1] != fmt.Sprintf("line-%d", total-1) {
		t.Errorf("unexpected last line %q", lines[len(lines)-1])
	}
	if strings.HasPrefix(lines[0], "line-0") && lines[0] == "line-0" {
		t.Error("oldest line should have been evicted")
	}
}

func TestRunWithAutoRestart_BinaryNotFound(t *testing.T) {
	// A bare name (no path separator) missing from PATH makes exec.Cmd.Start
	// return exec.ErrNotFound, which RunWithAutoRestart treats as fatal.
	t.Setenv("PATH", t.TempDir())
	pm := fluentbit.NewProcessManager("tfo-nonexistent-fluent-bit-xyz", "/tmp/x.conf", 0, true, time.Millisecond, 2, zap.NewNop())
	err := pm.RunWithAutoRestart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestRunWithAutoRestart_RestartDisabled(t *testing.T) {
	script := writeScript(t, "exit 1\n")
	pm := fluentbit.NewProcessManager(script, "/tmp/x.conf", 0, false, time.Millisecond, 0, zap.NewNop())
	err := pm.RunWithAutoRestart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "restart_on_crash is disabled") {
		t.Fatalf("expected restart-disabled error, got %v", err)
	}
}

func TestRunWithAutoRestart_MaxRestartsExceeded(t *testing.T) {
	script := writeScript(t, "exit 1\n")
	pm := fluentbit.NewProcessManager(script, "/tmp/x.conf", 0, true, time.Millisecond, 1, zap.NewNop())
	err := pm.RunWithAutoRestart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeded max restarts") {
		t.Fatalf("expected max-restarts error, got %v", err)
	}
	if pm.RestartCount() < 2 {
		t.Errorf("expected restart count >= 2, got %d", pm.RestartCount())
	}
}

func TestRunWithAutoRestart_ContextCancelDuringRun(t *testing.T) {
	script := writeScript(t, "exec sleep 30\n")
	pm := fluentbit.NewProcessManager(script, "/tmp/x.conf", 0, true, time.Millisecond, 0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- pm.RunWithAutoRestart(ctx) }()

	// Wait until the process is actually running.
	waitFor(t, func() bool { return pm.IsRunning() })
	if pm.PID() == 0 {
		t.Error("expected non-zero PID while running")
	}
	if pm.UptimeSeconds() < 0 {
		t.Error("uptime should be non-negative")
	}
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunWithAutoRestart did not return after cancel")
	}
}

func TestRunWithAutoRestart_ContextCancelDuringRestartDelay(t *testing.T) {
	// Process exits immediately (success); restart delay is long so cancel lands
	// during the delay wait.
	script := writeScript(t, "exit 0\n")
	pm := fluentbit.NewProcessManager(script, "/tmp/x.conf", 0, true, 3*time.Second, 0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- pm.RunWithAutoRestart(ctx) }()

	time.Sleep(300 * time.Millisecond) // let it run once and enter the delay
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not return after cancel during restart delay")
	}
}

func TestProcessManager_StopGraceful(t *testing.T) {
	script := writeScript(t, "exec sleep 30\n")
	pm := fluentbit.NewProcessManager(script, "/tmp/x.conf", 0, false, time.Millisecond, 0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- pm.RunWithAutoRestart(ctx) }()
	waitFor(t, func() bool { return pm.IsRunning() })

	// Stop exercises the SIGTERM path. Because RunWithAutoRestart is concurrently
	// waiting on the same process, Stop may observe an already-reaped process; that
	// benign race ("process already finished") is acceptable here.
	if err := pm.Stop(); err != nil {
		t.Logf("Stop returned (benign race allowed): %v", err)
	}
	// RunWithAutoRestart should now return (restart disabled -> error).
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after Stop")
	}
}

func TestProcessManager_IsHealthy_NoPort(t *testing.T) {
	pm := fluentbit.NewProcessManager("/bin/true", "/tmp/x", 0, false, time.Second, 0, zap.NewNop())
	// healthPort <= 0 -> falls back to IsRunning (false here).
	if pm.IsHealthy() {
		t.Error("expected unhealthy when not running and no health port")
	}
}

func TestProcessManager_IsHealthy_HTTP(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{"ok", http.StatusOK, true},
		{"error", http.StatusInternalServerError, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			port := srv.Listener.Addr().(*net.TCPAddr).Port
			pm := fluentbit.NewProcessManager("/bin/true", "/tmp/x", port, false, time.Second, 0, zap.NewNop())
			if got := pm.IsHealthy(); got != tc.want {
				t.Errorf("IsHealthy = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProcessManager_IsHealthy_ConnectionRefused(t *testing.T) {
	// Reserve then release a port so nothing is listening.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	pm := fluentbit.NewProcessManager("/bin/true", "/tmp/x", port, false, time.Second, 0, zap.NewNop())
	if pm.IsHealthy() {
		t.Error("expected unhealthy on connection refused")
	}
}

func TestSigtermExported(t *testing.T) {
	if fluentbit.SigtermExported() == nil {
		t.Error("sigterm signal should not be nil")
	}
}

func TestCollector_StartRunsProcess(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	// A binary that exits quickly; restart disabled so Start returns an error.
	bin := writeScript(t, "exit 0\n")
	cfgDir := filepath.Join(t.TempDir(), "cd")
	c, err := fluentbit.NewFluentBitCollector(
		config.FluentBitCollectorConfig{
			BinaryPath:     bin,
			ConfigDir:      cfgDir,
			RestartOnCrash: false,
		},
		config.TelemetryFlowConfig{Endpoint: "http://localhost:4318"},
		"agent", zap.NewNop())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected Start to return an error (restart disabled)")
	}
	if c.IsRunning() {
		t.Error("should not be running after Start returns")
	}

	// Config files should have been generated.
	if _, statErr := os.Stat(filepath.Join(cfgDir, "fluent-bit.conf")); statErr != nil {
		t.Errorf("expected generated config: %v", statErr)
	}

	// Collect now reports process metrics (process object exists).
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(metrics) < 4 {
		t.Errorf("expected process metrics, got %d", len(metrics))
	}

	// Stop cleans up.
	if err := c.Stop(); err != nil {
		t.Errorf("stop: %v", err)
	}
}

func TestCollector_StartWriteConfigError(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	bin := writeScript(t, "exit 0\n")
	// Make ConfigDir unusable: a path under a regular file.
	f := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := fluentbit.NewFluentBitCollector(
		config.FluentBitCollectorConfig{BinaryPath: bin, ConfigDir: filepath.Join(f, "sub")},
		config.TelemetryFlowConfig{Endpoint: "http://localhost:4318"},
		"agent", zap.NewNop())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected Start to fail writing config")
	}
}

func TestCollector_StartGenerateConfigError(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	bin := writeScript(t, "exit 0\n")
	c, err := fluentbit.NewFluentBitCollector(
		config.FluentBitCollectorConfig{BinaryPath: bin, ConfigDir: t.TempDir()},
		config.TelemetryFlowConfig{Endpoint: "ht tp://bad host"},
		"agent", zap.NewNop())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected Start to fail generating config")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
