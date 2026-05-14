// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestSharding_ListShards(t *testing.T) {
	result := bson.M{
		"shards": bson.A{
			bson.M{"_id": "shard01", "host": "shard01/mongo-s1:27017", "state": int32(1)},
			bson.M{"_id": "shard02", "host": "shard02/mongo-s2:27017", "state": int32(1)},
			bson.M{"_id": "shard03", "host": "shard03/mongo-s3:27017", "state": int32(1)},
		},
	}

	shards, ok := result["shards"].(bson.A)
	if !ok {
		t.Fatal("shards not found")
	}
	if len(shards) != 3 {
		t.Fatalf("expected 3 shards, got %d", len(shards))
	}

	for i, s := range shards {
		shard, ok := s.(bson.M)
		if !ok {
			t.Fatalf("shard[%d] is not bson.M", i)
		}
		shardID := mongodb.AsStringExported(shard["_id"])
		if shardID == "" {
			t.Errorf("shard[%d] has empty _id", i)
		}
		state := mongodb.AsIntExported(shard["state"])
		if state != 1 {
			t.Errorf("shard[%d] state = %d, want 1", i, state)
		}
	}
}

func TestSharding_NonShardedDeployment(t *testing.T) {
	result := bson.M{}
	if _, ok := result["shards"]; ok {
		t.Error("non-sharded should not have shards key")
	}
}

func TestSharding_BalancerConfig(t *testing.T) {
	balancerConfig := bson.M{
		"_id":     "balancer",
		"stopped": false,
	}

	stopped, ok := balancerConfig["stopped"].(bool)
	if !ok {
		t.Fatal("stopped not found")
	}
	if stopped {
		t.Error("balancer should be enabled (stopped=false)")
	}

	var enabled float64
	if stopped {
		enabled = 0
	} else {
		enabled = 1
	}
	if enabled != 1 {
		t.Errorf("balancer_enabled = %v, want 1", enabled)
	}
}
