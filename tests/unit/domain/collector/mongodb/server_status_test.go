// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestCollectServerStatus_Connections(t *testing.T) {
	result := bson.M{
		"connections": bson.M{
			"current":      int32(100),
			"available":    int32(900),
			"totalCreated": int32(5000),
			"active":       int32(50),
		},
	}

	labels := map[string]string{"db.system": "mongodb"}
	var all []collector.Metric
	prefix := "db.mongodb."

	connections, ok := result["connections"].(bson.M)
	if !ok {
		t.Fatal("connections not found in result")
	}

	all = append(all,
		mongodb.GaugeExported(prefix+"connections.current", float64(mongodb.AsIntExported(connections["current"])), labels),
		mongodb.GaugeExported(prefix+"connections.available", float64(mongodb.AsIntExported(connections["available"])), labels),
		mongodb.CounterExported(prefix+"connections.total_created", float64(mongodb.AsIntExported(connections["totalCreated"])), labels),
		mongodb.GaugeExported(prefix+"connections.active", float64(mongodb.AsIntExported(connections["active"])), labels),
	)

	if len(all) != 4 {
		t.Fatalf("expected 4 connection metrics, got %d", len(all))
	}

	wantNames := []string{
		prefix + "connections.current",
		prefix + "connections.available",
		prefix + "connections.total_created",
		prefix + "connections.active",
	}
	for i, name := range wantNames {
		if all[i].Name != name {
			t.Errorf("metric[%d].Name = %q, want %q", i, all[i].Name, name)
		}
	}

	if all[0].Value != 100 {
		t.Errorf("connections.current = %v, want 100", all[0].Value)
	}
	if all[1].Value != 900 {
		t.Errorf("connections.available = %v, want 900", all[1].Value)
	}
}

func TestCollectServerStatus_Opcounters(t *testing.T) {
	result := bson.M{
		"opcounters": bson.M{
			"insert":  int32(100),
			"query":   int32(200),
			"update":  int32(50),
			"delete":  int32(10),
			"getmore": int32(300),
			"command": int32(500),
		},
	}

	prefix := "db.mongodb.opcounters."

	opcounters, ok := result["opcounters"].(bson.M)
	if !ok {
		t.Fatal("opcounters not found")
	}

	metrics := map[string]float64{
		prefix + "insert":  float64(mongodb.AsIntExported(opcounters["insert"])),
		prefix + "query":   float64(mongodb.AsIntExported(opcounters["query"])),
		prefix + "update":  float64(mongodb.AsIntExported(opcounters["update"])),
		prefix + "delete":  float64(mongodb.AsIntExported(opcounters["delete"])),
		prefix + "getmore": float64(mongodb.AsIntExported(opcounters["getmore"])),
		prefix + "command": float64(mongodb.AsIntExported(opcounters["command"])),
	}

	if metrics[prefix+"insert"] != 100 {
		t.Errorf("insert = %v, want 100", metrics[prefix+"insert"])
	}
	if metrics[prefix+"query"] != 200 {
		t.Errorf("query = %v, want 200", metrics[prefix+"query"])
	}
	if metrics[prefix+"command"] != 500 {
		t.Errorf("command = %v, want 500", metrics[prefix+"command"])
	}
}

func TestCollectServerStatus_MissingFields(t *testing.T) {
	result := bson.M{
		"connections": bson.M{
			"current": int32(50),
		},
	}

	connections, ok := result["connections"].(bson.M)
	if !ok {
		t.Fatal("connections not found")
	}

	val := mongodb.AsIntExported(connections["available"])
	if val != 0 {
		t.Errorf("missing field should return 0, got %d", val)
	}

	val = mongodb.AsIntExported(connections["current"])
	if val != 50 {
		t.Errorf("current = %d, want 50", val)
	}
}

func TestCollectServerStatus_Memory(t *testing.T) {
	result := bson.M{
		"mem": bson.M{
			"resident": int32(512),
			"virtual":  int32(2048),
		},
	}

	mem, ok := result["mem"].(bson.M)
	if !ok {
		t.Fatal("mem not found")
	}

	resident := mongodb.AsIntExported(mem["resident"])
	virtual := mongodb.AsIntExported(mem["virtual"])

	if resident != 512 {
		t.Errorf("resident = %d, want 512", resident)
	}
	if virtual != 2048 {
		t.Errorf("virtual = %d, want 2048", virtual)
	}
}

func TestCollectServerStatus_Asserts(t *testing.T) {
	result := bson.M{
		"asserts": bson.M{
			"regular":   int32(5),
			"warning":   int32(10),
			"msg":       int32(2),
			"user":      int32(100),
			"rollovers": int32(0),
		},
	}

	asserts, ok := result["asserts"].(bson.M)
	if !ok {
		t.Fatal("asserts not found")
	}

	if mongodb.AsIntExported(asserts["regular"]) != 5 {
		t.Errorf("asserts.regular = %d, want 5", mongodb.AsIntExported(asserts["regular"]))
	}
	if mongodb.AsIntExported(asserts["user"]) != 100 {
		t.Errorf("asserts.user = %d, want 100", mongodb.AsIntExported(asserts["user"]))
	}
}

func TestCollectServerStatus_GlobalLock(t *testing.T) {
	result := bson.M{
		"globalLock": bson.M{
			"currentQueue": bson.M{
				"total":   int32(15),
				"readers": int32(10),
				"writers": int32(5),
			},
			"activeClients": bson.M{
				"total":   int32(20),
				"readers": int32(12),
				"writers": int32(8),
			},
		},
	}

	globalLock, ok := result["globalLock"].(bson.M)
	if !ok {
		t.Fatal("globalLock not found")
	}

	queue, ok := globalLock["currentQueue"].(bson.M)
	if !ok {
		t.Fatal("currentQueue not found")
	}
	if mongodb.AsIntExported(queue["total"]) != 15 {
		t.Errorf("queue.total = %d, want 15", mongodb.AsIntExported(queue["total"]))
	}

	active, ok := globalLock["activeClients"].(bson.M)
	if !ok {
		t.Fatal("activeClients not found")
	}
	if mongodb.AsIntExported(active["writers"]) != 8 {
		t.Errorf("active.writers = %d, want 8", mongodb.AsIntExported(active["writers"]))
	}
}
