// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestReplication_MemberMetrics(t *testing.T) {
	rsStatus := bson.M{
		"myState": int32(1),
		"members": bson.A{
			bson.M{
				"name":     "mongo-0:27017",
				"state":    int32(1),
				"health":   int32(1),
				"stateStr": "PRIMARY",
			},
			bson.M{
				"name":     "mongo-1:27017",
				"state":    int32(2),
				"health":   int32(1),
				"stateStr": "SECONDARY",
			},
			bson.M{
				"name":     "mongo-2:27017",
				"state":    int32(2),
				"health":   int32(1),
				"stateStr": "SECONDARY",
			},
		},
	}

	myState, ok := rsStatus["myState"].(int32)
	if !ok || myState != 1 {
		t.Errorf("myState = %v, want 1", myState)
	}

	members, ok := rsStatus["members"].(bson.A)
	if !ok {
		t.Fatal("members not found")
	}
	if len(members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(members))
	}

	for i, m := range members {
		member, ok := m.(bson.M)
		if !ok {
			t.Fatalf("member[%d] is not bson.M", i)
		}

		name := mongodb.AsStringExported(member["name"])
		if name == "" {
			t.Errorf("member[%d] has empty name", i)
		}

		state := mongodb.AsIntExported(member["state"])
		health := mongodb.AsIntExported(member["health"])

		if i == 0 {
			if state != 1 {
				t.Errorf("member[0] state = %d, want 1 (PRIMARY)", state)
			}
		} else {
			if state != 2 {
				t.Errorf("member[%d] state = %d, want 2 (SECONDARY)", i, state)
			}
		}
		if health != 1 {
			t.Errorf("member[%d] health = %d, want 1", i, health)
		}
	}
}

func TestReplication_StandaloneSkip(t *testing.T) {
	result := bson.M{}
	if _, ok := result["members"]; ok {
		t.Error("standalone should not have members key")
	}
}

func TestOplog_WindowCalculation(t *testing.T) {
	first := bson.M{"ts": bson.Timestamp{T: 1700000000, I: 1}}
	last := bson.M{"ts": bson.Timestamp{T: 1700036000, I: 1}}

	firstTs, ok1 := first["ts"].(bson.Timestamp)
	lastTs, ok2 := last["ts"].(bson.Timestamp)
	if !ok1 || !ok2 {
		t.Fatal("timestamps not found")
	}

	window := int64(lastTs.T) - int64(firstTs.T)
	if window != 36000 {
		t.Errorf("oplog window = %d, want 36000 seconds (10h)", window)
	}
}
