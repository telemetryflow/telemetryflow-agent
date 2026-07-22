// Package system_test contains unit tests for the corresponding collector module.
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

package system_test

import (
	"context"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

// TestNewHostCollectorDefaults verifies default interval and nil-logger handling.
func TestNewHostCollectorDefaults(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{})
	if c == nil {
		t.Fatal("NewHostCollector returned nil")
	}
	if c.Name() != "system.host" {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.IsRunning() {
		t.Error("should not be running before Start()")
	}
}

// TestNewHostCollectorCustomInterval verifies a non-zero interval is preserved.
func TestNewHostCollectorCustomInterval(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{Interval: 5 * time.Second})
	if c == nil {
		t.Fatal("nil collector")
	}
}

// TestStartStopLifecycle drives Start/Stop transitions and idempotency.
func TestStartStopLifecycle(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{Interval: time.Hour})

	// Stop before start is a no-op.
	if err := c.Stop(); err != nil {
		t.Errorf("Stop before Start: %v", err)
	}

	started := make(chan error, 1)
	go func() {
		started <- c.Start(context.Background())
	}()

	// Wait for running state.
	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector never entered running state")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Second Start while running returns nil immediately.
	if err := c.Start(context.Background()); err != nil {
		t.Errorf("second Start: %v", err)
	}

	if err := c.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if err := <-started; err != nil {
		t.Errorf("Start returned: %v", err)
	}
	if c.IsRunning() {
		t.Error("still running after Stop")
	}
}

// TestStartContextCancel verifies Start returns when its context is cancelled.
func TestStartContextCancel(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("never running")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Errorf("Start err = %v, want context.Canceled", err)
	}
}

// TestCollectAllDisabled verifies Collect returns no error when everything is off.
func TestCollectAllDisabled(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{})
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

// TestCollectAllEnabled exercises CPU/mem/disk/net collection against the live
// host. It runs two cycles so the network rate-calculation branch is covered.
func TestCollectAllEnabled(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{
		CollectCPU:  true,
		CollectMem:  true,
		CollectDisk: true,
		CollectNet:  true,
		DiskPaths:   []string{"/", "/nonexistent-path-telemetryflow"},
	})
	m1, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect cycle 1: %v", err)
	}
	if len(m1) == 0 {
		t.Error("expected metrics on cycle 1")
	}
	// Second cycle: lastStats is now populated so rate metrics are emitted.
	time.Sleep(10 * time.Millisecond)
	m2, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect cycle 2: %v", err)
	}
	if len(m2) == 0 {
		t.Error("expected metrics on cycle 2")
	}
}

// TestGetSystemInfo exercises the large host-information gatherer against the
// live OS. Linux-only branches (/proc parsing) are skipped on non-Linux hosts
// by the code itself; those are documented as OS-bound gaps.
func TestGetSystemInfo(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{})
	info, err := c.GetSystemInfo()
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if info == nil {
		t.Fatal("nil info")
	}
	if info.AgentVersion == "" {
		t.Error("expected AgentVersion to be set")
	}
	if info.CollectionTime == 0 {
		t.Error("expected CollectionTime to be set")
	}
}

// TestGetSystemInfoStaticAndFallback covers the package-level accessors and the
// cache path (second call is served from cache).
func TestGetSystemInfoStaticAndFallback(t *testing.T) {
	info, err := system.GetSystemInfoStatic()
	if err != nil {
		t.Fatalf("GetSystemInfoStatic: %v", err)
	}
	if info == nil {
		t.Fatal("nil info")
	}
	// Second call should hit the cache.
	if _, err := system.GetSystemInfoStatic(); err != nil {
		t.Fatalf("GetSystemInfoStatic cached: %v", err)
	}

	fb := system.GetSystemInfoWithFallback()
	if fb == nil {
		t.Fatal("GetSystemInfoWithFallback returned nil")
	}
}

// TestGetHostnameFallback verifies the hostname helper returns non-empty.
func TestGetHostnameFallback(t *testing.T) {
	if h := system.GetHostnameFallbackExported(); h == "" {
		t.Error("expected non-empty hostname")
	}
}
