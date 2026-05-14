// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestWiredTiger_TicketMetrics(t *testing.T) {
	result := bson.M{
		"wiredTiger": bson.M{
			"concurrentTransactions": bson.M{
				"read": bson.M{
					"out":          int32(10),
					"available":    int32(118),
					"totalTickets": int32(128),
				},
				"write": bson.M{
					"out":          int32(5),
					"available":    int32(123),
					"totalTickets": int32(128),
				},
			},
		},
	}

	wt, ok := result["wiredTiger"].(bson.M)
	if !ok {
		t.Fatal("wiredTiger not found")
	}

	concurrent, ok := wt["concurrentTransactions"].(bson.M)
	if !ok {
		t.Fatal("concurrentTransactions not found")
	}

	readTickets, ok := concurrent["read"].(bson.M)
	if !ok {
		t.Fatal("read tickets not found")
	}
	if mongodb.AsIntExported(readTickets["available"]) != 118 {
		t.Errorf("read.available = %d, want 118", mongodb.AsIntExported(readTickets["available"]))
	}

	writeTickets, ok := concurrent["write"].(bson.M)
	if !ok {
		t.Fatal("write tickets not found")
	}
	if mongodb.AsIntExported(writeTickets["out"]) != 5 {
		t.Errorf("write.out = %d, want 5", mongodb.AsIntExported(writeTickets["out"]))
	}
}

func TestWiredTiger_CheckpointMetrics(t *testing.T) {
	result := bson.M{
		"wiredTiger": bson.M{
			"checkpoint": bson.M{
				"total":        int32(100),
				"pagesWritten": int32(500),
			},
		},
	}

	wt, ok := result["wiredTiger"].(bson.M)
	if !ok {
		t.Fatal("wiredTiger not found")
	}

	checkpoint, ok := wt["checkpoint"].(bson.M)
	if !ok {
		t.Fatal("checkpoint not found")
	}

	if mongodb.AsIntExported(checkpoint["total"]) != 100 {
		t.Errorf("checkpoint.total = %d, want 100", mongodb.AsIntExported(checkpoint["total"]))
	}
}

func TestWiredTiger_MissingSection(t *testing.T) {
	result := bson.M{
		"connections": bson.M{"current": int32(10)},
	}

	if _, ok := result["wiredTiger"]; ok {
		t.Error("MMAPv1 should not have wiredTiger section")
	}
}
