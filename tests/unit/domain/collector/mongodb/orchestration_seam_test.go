// Package mongodb_test — orchestration-path tests that drive the per-instance
// collect flow (Collect -> collectInstance / collectAllCollStats /
// collectAllQueryMetrics) through an injected fake MongoAPI via
// mongodb.SetAPIFactoryExported. Before the api-factory seam these paths built
// a real *mongo.Client inline and could only run against a live MongoDB.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package mongodb_test

import (
	"context"
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func oneInstanceMongoCfg() config.MongoDBCommunityCollectorConfig {
	return config.MongoDBCommunityCollectorConfig{
		Instances: []config.MongoDBCommunityInstanceConfig{
			{Name: "m1", URI: "mongodb://localhost:27017"},
		},
	}
}

// TestCollect_OrchestrationViaFakeAPI drives Collect -> collectInstance and the
// collectAll* helpers through the fake. serverStatus returns a canned doc (so
// the success-append branch runs); every other leaf op has no canned result and
// returns an error (so the log-and-continue branches run). A second Collect
// exercises the rate-computation path (inst.prevTime now set).
func TestCollect_OrchestrationViaFakeAPI(t *testing.T) {
	fake := newFakeAPI()
	fake.runCommand["admin|serverStatus"] = cannedResult{doc: bson.M{
		"connections": bson.M{"current": 5, "available": 95, "totalCreated": 100, "active": 3},
		"opcounters":  bson.M{"insert": 1, "query": 2, "update": 3, "delete": 4, "getmore": 5, "command": 6},
	}}

	mongodb.SetAPIFactoryExported(func() (mongodb.MongoAPI, error) { return fake, nil })
	defer mongodb.SetAPIFactoryExported(nil)

	c := mongodb.NewMongoDBCollector(oneInstanceMongoCfg(), zap.NewNop())

	first, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect #1: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("expected serverStatus metrics from the fake, got none")
	}

	// Second pass: inst.prevTime is now set, so computeRates runs.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect #2: %v", err)
	}
}

// TestCollect_FactoryError covers the path where the API factory fails:
// collectInstance returns the error (Collect logs + continues) and the
// collectAll* helpers hit their `continue` branch. No error surfaces.
func TestCollect_FactoryError(t *testing.T) {
	mongodb.SetAPIFactoryExported(func() (mongodb.MongoAPI, error) {
		return nil, errors.New("connection refused")
	})
	defer mongodb.SetAPIFactoryExported(nil)

	c := mongodb.NewMongoDBCollector(oneInstanceMongoCfg(), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should tolerate factory error: %v", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("expected no metrics on factory error, got %d", len(metrics))
	}
}
