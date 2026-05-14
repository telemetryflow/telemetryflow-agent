// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestCollStats_RegularCollection(t *testing.T) {
	result := bson.M{
		"count":          int32(100000),
		"size":           int64(52428800),
		"storageSize":    int64(26214400),
		"avgObjSize":     int32(524),
		"totalIndexSize": int64(10485760),
		"nindexes":       int32(3),
		"capped":         false,
	}

	if mongodb.AsFloatExported(result["count"]) != 100000 {
		t.Errorf("count = %v, want 100000", mongodb.AsFloatExported(result["count"]))
	}
	if mongodb.AsFloatExported(result["size"]) != 52428800 {
		t.Errorf("size = %v, want 52428800", mongodb.AsFloatExported(result["size"]))
	}
	if mongodb.AsFloatExported(result["avgObjSize"]) != 524 {
		t.Errorf("avgObjSize = %v, want 524", mongodb.AsFloatExported(result["avgObjSize"]))
	}

	if capped, ok := result["capped"].(bool); ok && capped {
		t.Error("regular collection should not be capped")
	}
}

func TestCollStats_CappedCollection(t *testing.T) {
	result := bson.M{
		"count":   int32(5000),
		"size":    int64(1048576),
		"capped":  true,
		"max":     int64(10000),
		"maxSize": int64(5242880),
	}

	capped, ok := result["capped"].(bool)
	if !ok || !capped {
		t.Error("expected capped collection")
	}
	if mongodb.AsFloatExported(result["max"]) != 10000 {
		t.Errorf("max = %v, want 10000", mongodb.AsFloatExported(result["max"]))
	}
	if mongodb.AsFloatExported(result["maxSize"]) != 5242880 {
		t.Errorf("maxSize = %v, want 5242880", mongodb.AsFloatExported(result["maxSize"]))
	}
}

func TestCollStats_IndexSizes(t *testing.T) {
	result := bson.M{
		"indexSizes": bson.M{
			"_id_":            int64(1048576),
			"name_1":          int64(524288),
			"status_1_date_1": int64(262144),
		},
	}

	indexSizes, ok := result["indexSizes"].(bson.M)
	if !ok {
		t.Fatal("indexSizes not found")
	}
	if len(indexSizes) != 3 {
		t.Fatalf("expected 3 indexes, got %d", len(indexSizes))
	}

	if mongodb.AsFloatExported(indexSizes["_id_"]) != 1048576 {
		t.Errorf("_id_ size = %v, want 1048576", mongodb.AsFloatExported(indexSizes["_id_"]))
	}
}

func TestCollStats_DatabaseDiscovery(t *testing.T) {
	result := bson.M{
		"databases": bson.A{
			bson.M{"name": "admin", "sizeOnDisk": int64(8192)},
			bson.M{"name": "myapp", "sizeOnDisk": int64(104857600)},
			bson.M{"name": "analytics", "sizeOnDisk": int64(524288000)},
			bson.M{"name": "local", "sizeOnDisk": int64(4096)},
			bson.M{"name": "config", "sizeOnDisk": int64(4096)},
		},
	}

	databases, ok := result["databases"].(bson.A)
	if !ok {
		t.Fatal("databases not found")
	}

	var userDBs []string
	for _, d := range databases {
		db, ok := d.(bson.M)
		if !ok {
			continue
		}
		name := mongodb.AsStringExported(db["name"])
		if name == "admin" || name == "local" || name == "config" {
			continue
		}
		userDBs = append(userDBs, name)
	}

	if len(userDBs) != 2 {
		t.Fatalf("expected 2 user databases, got %d: %v", len(userDBs), userDBs)
	}
	if userDBs[0] != "myapp" {
		t.Errorf("userDBs[0] = %q, want myapp", userDBs[0])
	}
}
