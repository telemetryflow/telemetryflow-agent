// Package mongodb_test — closes the last fake-API-reachable branch: the
// MongoDB 7.0+ queues.execution admission-ticket path in collectWiredTiger
// (the pre-7.0 wiredTiger.concurrentTransactions path is covered elsewhere).
//
// The remaining uncovered statements in this package (collectInstance,
// collectAllCollStats/QueryMetrics, qan collectInstance, connection.go,
// mongo_api.go clientAPI) all construct a real *mongo.Client internally and
// cannot be exercised without a live MongoDB or a production-side seam, so they
// are intentionally untouched.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package mongodb_test

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

// TestCollectWiredTiger_QueuesExecution7x drives the MongoDB 7.0+ branch where
// admission tickets live under serverStatus().queues.execution.{read,write}
// instead of the pre-7.0 wiredTiger.concurrentTransactions location.
func TestCollectWiredTiger_QueuesExecution7x(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{
		doc: bson.M{
			// wiredTiger must be present (else collectWiredTiger returns early).
			"wiredTiger": bson.M{},
			// 7.0+ authoritative ticket location.
			"queues": bson.M{
				"execution": bson.M{
					"read": bson.M{
						"available":    int32(100),
						"out":          int32(5),
						"totalTickets": int32(128),
					},
					"write": bson.M{
						"available":    int32(120),
						"out":          int32(8),
						"totalTickets": int32(128),
					},
				},
			},
		},
	}

	metrics, err := mongodb.CollectWiredTigerExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("CollectWiredTigerExported: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.wiredtiger.tickets.read.available", 100)
	requireValue(t, metrics, "db.mongodb.wiredtiger.tickets.read.out", 5)
	requireValue(t, metrics, "db.mongodb.wiredtiger.tickets.write.total", 128)
}
