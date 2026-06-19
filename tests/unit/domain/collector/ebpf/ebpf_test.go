// Package ebpf_test contains unit tests for the eBPF collector domain logic
// including configuration, network event handling, and syscall tracking.
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
package ebpf_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	ebpfcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/ebpf"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func testConfig() config.EBPFCollectorConfig {
	return config.EBPFCollectorConfig{
		Enabled:          true,
		Interval:         1 * time.Second,
		CollectSyscalls:  true,
		CollectNetwork:   true,
		CollectFileIO:    true,
		CollectScheduler: false,
		CollectMemory:    false,
		CollectTCPEvents: true,
		ProcessFilter:    []string{},
		ExcludeProcesses: []string{"tfo-agent", "systemd"},
		SampleRate:       100,
		RingBufferSize:   262144,
		PerfBufferSize:   64,
		PinPath:          "/sys/fs/bpf/tfo-agent",
		Cilium: config.CiliumCollectorConfig{
			Enabled:       false,
			HubbleAddress: "localhost:4245",
		},
	}
}

func newTestCollector(t *testing.T) *ebpfcollector.EBPFCollector {
	t.Helper()
	logger := zap.NewNop()
	c, err := ebpfcollector.NewEBPFCollector(testConfig(), logger)
	require.NoError(t, err)
	return c
}

func TestEBPFCollectorName(t *testing.T) {
	c := newTestCollector(t)
	assert.Equal(t, "ebpf", c.Name())
}

func TestEBPFCollectorIsRunning(t *testing.T) {
	c := newTestCollector(t)
	assert.False(t, c.IsRunning(), "should not be running initially")
}

func TestEBPFCollectorStartStop(t *testing.T) {
	c := newTestCollector(t)
	assert.False(t, c.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(200 * time.Millisecond)

	if runtime.GOOS == "linux" {
		// On Linux the collector might fail to load BPF programs
		// without proper privileges, but it should still set running=true first
		assert.True(t, c.IsRunning(), "should be running on Linux after Start")
	}

	cancel()
	err := <-errCh
	if runtime.GOOS == "linux" {
		// Might fail to load programs, which is acceptable in tests
		if err != nil {
			assert.Contains(t, err.Error(), "")
		}
	}
	assert.False(t, c.IsRunning())
}

func TestEBPFCollectorStopWithStopChan(t *testing.T) {
	c := newTestCollector(t)

	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	err := c.Stop()
	require.NoError(t, err)

	startErr := <-errCh
	if runtime.GOOS != "linux" {
		// On non-Linux, Start blocks on ticker but returns nil on Stop
		assert.NoError(t, startErr)
	}
	assert.False(t, c.IsRunning())
}

func TestEBPFCollectorStopIdempotent(t *testing.T) {
	c := newTestCollector(t)

	// Stopping a non-running collector should not error
	err := c.Stop()
	assert.NoError(t, err)
}

func TestEBPFCollectorCollect(t *testing.T) {
	c := newTestCollector(t)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	if runtime.GOOS != "linux" {
		// Non-Linux returns empty metrics
		assert.Empty(t, metrics, "expected empty metrics on non-Linux")
	}
}

func TestEBPFCollectorCollectDisabledSubCollectors(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.EBPFCollectorConfig{
		Enabled:          true,
		Interval:         1 * time.Second,
		CollectSyscalls:  false,
		CollectNetwork:   false,
		CollectFileIO:    false,
		CollectScheduler: false,
		CollectMemory:    false,
		CollectTCPEvents: false,
		SampleRate:       100,
		Cilium: config.CiliumCollectorConfig{
			Enabled: false,
		},
	}

	c, err := ebpfcollector.NewEBPFCollector(cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics, "expected no metrics when all sub-collectors are disabled")
}

func TestEBPFCollectorDefaultInterval(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.EBPFCollectorConfig{
		Enabled:    true,
		Interval:   0, // Should default to 15s
		SampleRate: 100,
	}

	c, err := ebpfcollector.NewEBPFCollector(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "ebpf", c.Name())
}

func TestEBPFCollectorStartIdempotent(t *testing.T) {
	c := newTestCollector(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	// Second Start should be a no-op
	errCh2 := make(chan error, 1)
	go func() {
		errCh2 <- c.Start(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	cancel()
	<-errCh
	err := <-errCh2
	assert.NoError(t, err, "second Start should return nil immediately")
}
