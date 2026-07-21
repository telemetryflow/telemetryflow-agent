// Package mongodb_test contains unit tests for the corresponding collector module.
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
package mongodb_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestMongoDBCollector_Lifecycle(t *testing.T) {
	c := mongodb.NewMongoDBCollector(config.MongoDBCommunityCollectorConfig{}, zap.NewNop())

	if c.Name() != "mongodb_community" {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.IsRunning() {
		t.Error("expected not running before Start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// Wait until running.
	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !c.IsRunning() {
		t.Fatal("collector did not start")
	}

	// Second Start should error.
	if err := c.Start(ctx); err == nil {
		t.Error("expected error on double Start")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}

	if c.IsRunning() {
		t.Error("expected not running after cancel")
	}
	// Stop is idempotent.
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() = %v", err)
	}
}

func TestMongoDBCollector_CollectNoInstances(t *testing.T) {
	c := mongodb.NewMongoDBCollector(config.MongoDBCommunityCollectorConfig{}, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics, got %d", len(metrics))
	}
}

// TestMongoDBCollector_CollectConnectionFailure drives the full Collect fan-out
// (collectInstance, collectAllCollStats, collectAllQueryMetrics) and the
// ensureConnection error path using an unparseable URI that fails fast without
// any network I/O. It never reaches a real database.
func TestMongoDBCollector_CollectConnectionFailure(t *testing.T) {
	c := mongodb.NewMongoDBCollector(config.MongoDBCommunityCollectorConfig{
		Instances: []config.MongoDBCommunityInstanceConfig{
			{Name: "bad", URI: "not-a-valid-uri"},
		},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() should tolerate connection failure, got %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics on connection failure, got %d", len(metrics))
	}
}

// TestQANMongoDBCollector_CollectConnectionFailure drives QAN CollectQAN /
// collectInstance / ensureConnection error paths via an unparseable URI.
func TestQANMongoDBCollector_CollectConnectionFailure(t *testing.T) {
	c := mongodb.NewQANMongoDBCollector(mongodb.QANMongoDBConfig{
		Instances: []config.MongoDBCommunityInstanceConfig{
			{Name: "bad", URI: "not-a-valid-uri"},
		},
	}, zap.NewNop())

	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("CollectQAN() should tolerate connection failure, got %v", err)
	}
	if len(buckets) != 0 {
		t.Errorf("expected no buckets, got %d", len(buckets))
	}
}

func TestQANMongoDBCollector_Lifecycle(t *testing.T) {
	c := mongodb.NewQANMongoDBCollector(mongodb.QANMongoDBConfig{}, zap.NewNop())

	if c.Name() != "qan-mongodb-profiler" {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.IsRunning() {
		t.Error("expected not running")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if !c.IsRunning() {
		t.Error("expected running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Error("expected error on double Start")
	}
	// AgentType should be stable.
	_ = c.AgentType()

	if err := c.Stop(); err != nil {
		t.Errorf("Stop() = %v", err)
	}
	if c.IsRunning() {
		t.Error("expected not running after Stop")
	}
	// Stop idempotent.
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop() = %v", err)
	}
}

func TestQANMongoDBCollector_CollectNoInstances(t *testing.T) {
	c := mongodb.NewQANMongoDBCollector(mongodb.QANMongoDBConfig{}, zap.NewNop())
	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("CollectQAN() = %v", err)
	}
	if buckets != nil {
		t.Errorf("expected nil buckets, got %d", len(buckets))
	}
}
