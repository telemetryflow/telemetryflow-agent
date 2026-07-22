// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package timescaledb_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	tsdb "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestCollectorLifecycle(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())

	if c.Name() != "timescaledb" {
		t.Errorf("expected name timescaledb, got %s", c.Name())
	}
	if c.IsRunning() {
		t.Fatal("should not be running before Start")
	}

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()

	waitFor(t, c.IsRunning)

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("should not be running after Stop")
	}
}

func TestCollectorStart_AlreadyRunning(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()
	waitFor(t, c.IsRunning)

	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected error when starting already-running collector")
	}

	_ = c.Stop()
	<-done
}

func TestCollectorStart_ContextCancel(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	waitFor(t, c.IsRunning)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Start returned error on ctx cancel: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("should not be running after context cancel")
	}
}

func TestCollectorStop_NotRunning(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop on non-running collector should be nil, got %v", err)
	}
}

func TestCollectorCollect_NoInstances(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil metrics with no instances, got %d", len(metrics))
	}
}

// --- QAN collector lifecycle ---

func TestQANCollectorLifecycle(t *testing.T) {
	c := tsdb.NewQANTimescaleDBCollector(tsdb.QANTimescaleDBConfig{}, zap.NewNop())

	if c.Name() != "qan-timescaledb-pgstatements" {
		t.Errorf("unexpected name: %s", c.Name())
	}
	if c.AgentType() == "" {
		t.Error("expected non-empty agent type")
	}
	if c.IsRunning() {
		t.Fatal("should not be running before Start")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("should be running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected error on double Start")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("should not be running after Stop")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("second Stop should be nil, got %v", err)
	}
}

func TestQANCollectorCollect_NoInstances(t *testing.T) {
	c := tsdb.NewQANTimescaleDBCollector(tsdb.QANTimescaleDBConfig{}, zap.NewNop())
	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buckets != nil {
		t.Fatalf("expected nil buckets, got %d", len(buckets))
	}
}
