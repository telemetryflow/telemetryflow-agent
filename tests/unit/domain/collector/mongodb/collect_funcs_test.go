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
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

var errBoom = errors.New("boom")

// ---------- serverStatus ----------

func TestCollectServerStatus_FullDocument(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{doc: bson.M{
		"connections": bson.M{
			"current": int32(100), "available": int32(900),
			"totalCreated": int32(5000), "active": int32(50),
		},
		"opcounters": bson.M{
			"insert": int32(1), "query": int32(2), "update": int32(3),
			"delete": int32(4), "getmore": int32(5), "command": int32(6),
		},
		"opcountersRepl": bson.M{
			"insert": int32(10), "query": int32(20), "update": int32(30),
			"delete": int32(40), "getmore": int32(50), "command": int32(60),
		},
		"mem": bson.M{"resident": int32(512), "virtual": int32(2048), "mapped": int32(256)},
		"metrics": bson.M{
			"document": bson.M{"inserted": int32(7), "returned": int32(8), "updated": int32(9), "deleted": int32(11)},
			"cursor": bson.M{
				"open":     bson.M{"total": int32(3), "noTimeout": int32(1), "pinned": int32(2)},
				"timedOut": int32(12),
			},
		},
		"network": bson.M{"bytesIn": int64(1000), "bytesOut": int64(2000), "numRequests": int32(30)},
		"asserts": bson.M{"regular": int32(1), "warning": int32(2), "msg": int32(3), "user": int32(4), "rollovers": int32(5)},
		"globalLock": bson.M{
			"currentQueue":  bson.M{"total": int32(15), "readers": int32(10), "writers": int32(5)},
			"activeClients": bson.M{"total": int32(20), "readers": int32(12), "writers": int32(8)},
		},
		"extra_info": bson.M{"page_faults": int64(99)},
	}}

	labels := map[string]string{"db.system": "mongodb"}
	metrics, err := mongodb.CollectServerStatusExported(context.Background(), f, labels)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValue(t, metrics, "db.mongodb.connections.current", 100)
	requireValue(t, metrics, "db.mongodb.connections.total_created", 5000)
	requireValue(t, metrics, "db.mongodb.opcounters.insert", 1)
	requireValue(t, metrics, "db.mongodb.opcounters.repl.command", 60)
	requireValue(t, metrics, "db.mongodb.memory.resident_mb", 512)
	requireValue(t, metrics, "db.mongodb.memory.mapped_mb", 256)
	requireValue(t, metrics, "db.mongodb.document.inserted", 7)
	requireValue(t, metrics, "db.mongodb.cursors.open.total", 3)
	requireValue(t, metrics, "db.mongodb.cursors.timed_out", 12)
	requireValue(t, metrics, "db.mongodb.network.bytes_in", 1000)
	requireValue(t, metrics, "db.mongodb.asserts.user", 4)
	requireValue(t, metrics, "db.mongodb.global_lock.current_queue.total", 15)
	requireValue(t, metrics, "db.mongodb.global_lock.active_clients.writers", 8)
	requireValue(t, metrics, "db.mongodb.extra_info.page_faults", 99)
}

func TestCollectServerStatus_MissingSections(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{doc: bson.M{}}

	metrics, err := mongodb.CollectServerStatusExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty serverStatus, got %d", len(metrics))
	}
}

func TestCollectServerStatus_CommandError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{err: errBoom}

	if _, err := mongodb.CollectServerStatusExported(context.Background(), f, nil); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------- WiredTiger ----------

func TestCollectWiredTiger_Full(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{doc: bson.M{
		"wiredTiger": bson.M{
			"cache": bson.M{
				"bytes currently in the cache":     int64(500),
				"tracked dirty bytes in the cache": int64(50),
				"maximum bytes configured":         int64(1000),
				"bytes read into cache":            int64(100),
				"bytes written from cache":         int64(200),
				"unmodified pages evicted":         int64(3),
				"modified pages evicted":           int64(4),
				"eviction calls":                   int64(5),
			},
			"concurrentTransactions": bson.M{
				"read":  bson.M{"available": int32(120), "out": int32(8), "totalTickets": int32(128)},
				"write": bson.M{"available": int32(125), "out": int32(3), "totalTickets": int32(128)},
			},
			"checkpoint": bson.M{
				"latest checkpoint duration":      int64(10),
				"total checkpoints":               int64(20),
				"latest checkpoint pages written": int64(30),
				"min checkpoint duration":         int64(5),
				"max checkpoint duration":         int64(15),
			},
			"log": bson.M{
				"log bytes written": int64(1000), "log records written": int64(40),
				"log syncs": int64(50), "log sync directory": int64(60),
				"log flushes": int64(70), "log max file size": int64(80),
			},
			"block-manager": bson.M{
				"bytes read": int64(11), "bytes written": int64(22),
				"blocks read": int64(33), "blocks written": int64(44),
			},
		},
	}}

	metrics, err := mongodb.CollectWiredTigerExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.wiredtiger.cache.bytes_in_cache", 500)
	requireValue(t, metrics, "db.mongodb.wiredtiger.cache.max_bytes", 1000)
	requireValue(t, metrics, "db.mongodb.wiredtiger.cache.utilization_percent", 50)
	requireValue(t, metrics, "db.mongodb.wiredtiger.tickets.read.available", 120)
	requireValue(t, metrics, "db.mongodb.wiredtiger.tickets.write.out", 3)
	requireValue(t, metrics, "db.mongodb.wiredtiger.checkpoint.total", 20)
	requireValue(t, metrics, "db.mongodb.wiredtiger.log.records_written", 40)
	requireValue(t, metrics, "db.mongodb.wiredtiger.block_manager.blocks_written", 44)
}

func TestCollectWiredTiger_NotPresent(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{doc: bson.M{"foo": int32(1)}}

	metrics, err := mongodb.CollectWiredTigerExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics when wiredTiger absent, got %d", len(metrics))
	}
}

func TestCollectWiredTiger_CommandError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|serverStatus"] = cannedResult{err: errBoom}
	if _, err := mongodb.CollectWiredTigerExported(context.Background(), f, nil); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- Replication ----------

func TestCollectReplication_MembersAndOplog(t *testing.T) {
	now := bson.DateTime(time.Now().UnixMilli())
	optime := bson.DateTime(time.Now().Add(-5 * time.Second).UnixMilli())

	f := newFakeAPI()
	f.runCommand["admin|replSetGetStatus"] = cannedResult{doc: bson.M{
		"myState": int32(1),
		"members": bson.A{
			bson.M{
				"name": "mongo-0:27017", "state": int32(1), "health": int32(1),
				"optimeDate": optime, "date": now, "pingMs": int32(3), "uptime": int64(3600),
			},
			bson.M{
				"name": "mongo-1:27017", "state": int32(2), "health": int32(1),
			},
			"not-a-doc",
		},
	}}
	f.runCommand["local|collStats"] = cannedResult{doc: bson.M{"size": int64(1024), "maxSize": int64(4096)}}
	f.aggregate["local.oplog.rs"] = cannedSlice{docs: []bson.M{{"ts": bson.Timestamp{T: 100}}}}
	// second aggregate call reuses same key; override with last after first read is not possible,
	// so provide a single doc that serves both first and last (window = 0).

	metrics, err := mongodb.CollectReplicationExported(context.Background(), f, map[string]string{"db.instance": "rs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.replication.my_state", 1)
	requireValue(t, metrics, "db.mongodb.oplog.size_bytes", 1024)
	requireValue(t, metrics, "db.mongodb.oplog.max_size_bytes", 4096)

	// member lag should be present and non-negative (~5s)
	if m, ok := metricByName(metrics, "db.mongodb.replication.lag_seconds"); ok {
		if m.Value < 0 {
			t.Errorf("lag_seconds negative: %v", m.Value)
		}
	} else {
		t.Error("expected lag_seconds metric")
	}
	requireValue(t, metrics, "db.mongodb.replication.uptime_seconds", 3600)
}

func TestCollectReplication_StandaloneError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|replSetGetStatus"] = cannedResult{err: errBoom}
	if _, err := mongodb.CollectReplicationExported(context.Background(), f, nil); err == nil {
		t.Fatal("expected error for standalone")
	}
}

func TestCollectReplication_OplogStatsError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|replSetGetStatus"] = cannedResult{doc: bson.M{"myState": int32(1)}}
	f.runCommand["local|collStats"] = cannedResult{err: errBoom}
	metrics, err := mongodb.CollectReplicationExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.replication.my_state", 1)
}

// ---------- Sharding ----------

func TestCollectSharding_ShardsAndBalancer(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listShards"] = cannedResult{doc: bson.M{
		"shards": bson.A{
			bson.M{"_id": "shard0", "state": int32(1)},
			bson.M{"_id": "shard1", "state": int32(1)},
		},
	}}
	f.findOne["config.settings"] = cannedResult{doc: bson.M{"stopped": false}}

	metrics, err := mongodb.CollectShardingExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.sharding.total_shards", 2)
	requireValue(t, metrics, "db.mongodb.sharding.balancer_enabled", 1)
}

func TestCollectSharding_BalancerStopped(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listShards"] = cannedResult{doc: bson.M{"shards": bson.A{}}}
	f.findOne["config.settings"] = cannedResult{doc: bson.M{"stopped": true}}
	metrics, err := mongodb.CollectShardingExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.sharding.total_shards", 0)
	requireValue(t, metrics, "db.mongodb.sharding.balancer_enabled", 0)
}

func TestCollectSharding_CommandError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listShards"] = cannedResult{err: errBoom}
	if _, err := mongodb.CollectShardingExported(context.Background(), f, nil); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- CurrentOp ----------

func TestCollectCurrentOp_Operations(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|currentOp"] = cannedResult{doc: bson.M{
		"inprog": bson.A{
			bson.M{"active": true, "op": "query", "microsecs_running": int64(2_000_000), "waitingForLock": true},
			bson.M{"active": true, "op": "update", "microsecs_running": int64(15_000_000)},
			bson.M{"active": true, "op": "insert", "microsecs_running": int64(70_000_000)},
			bson.M{"active": false, "op": "query"},
			"not-a-doc",
		},
	}}

	metrics, err := mongodb.CollectCurrentOpExported(context.Background(), f, map[string]string{"db.instance": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.operations.active", 3)
	requireValue(t, metrics, "db.mongodb.operations.waiting_for_lock", 1)
	requireValue(t, metrics, "db.mongodb.operations.running_longer_than_1s", 3)
	requireValue(t, metrics, "db.mongodb.operations.running_longer_than_10s", 2)
	requireValue(t, metrics, "db.mongodb.operations.running_longer_than_60s", 1)

	// active_by_type present for query
	found := false
	for _, m := range metrics {
		if m.Name == "db.mongodb.operations.active_by_type" && m.Labels["operation"] == "query" {
			found = true
			if m.Value != 1 {
				t.Errorf("query active_by_type = %v, want 1", m.Value)
			}
		}
	}
	if !found {
		t.Error("expected active_by_type for query")
	}
}

func TestCollectCurrentOp_NoInprog(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|currentOp"] = cannedResult{doc: bson.M{}}
	metrics, err := mongodb.CollectCurrentOpExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics, got %d", len(metrics))
	}
}

func TestCollectCurrentOp_CommandError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|currentOp"] = cannedResult{err: errBoom}
	if _, err := mongodb.CollectCurrentOpExported(context.Background(), f, nil); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- discoverDatabases ----------

func TestDiscoverDatabases_FiltersSystem(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{
		"databases": bson.A{
			bson.M{"name": "admin"}, bson.M{"name": "local"}, bson.M{"name": "config"},
			bson.M{"name": "app"}, bson.M{"name": "orders"},
		},
	}}
	ti := mongodb.NewTestInstance("x")
	dbs, err := mongodb.DiscoverDatabasesExported(context.Background(), f, ti)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dbs) != 2 {
		t.Fatalf("expected 2 dbs, got %v", dbs)
	}
}

func TestDiscoverDatabases_Error(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	if _, err := mongodb.DiscoverDatabasesExported(context.Background(), f, ti); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- CollStats ----------

func TestCollectCollStats_Full(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{
		"databases": bson.A{bson.M{"name": "app"}},
	}}
	f.runCommand["app|dbStats"] = cannedResult{doc: bson.M{
		"objects": int64(100), "dataSize": int64(2000), "storageSize": int64(1000),
		"indexSize": int64(500), "collections": int32(3), "indexes": int32(5),
	}}
	f.listCollections["app"] = cannedNames{names: []string{"users"}}
	f.runCommand["app|collStats"] = cannedResult{doc: bson.M{
		"count": int32(100), "size": int64(2000), "storageSize": int64(1000),
		"avgObjSize": int32(20), "totalIndexSize": int64(500), "nindexes": int32(2),
		"capped": true, "max": int32(1000), "maxSize": int64(4096),
	}}
	f.aggregate["app.users"] = cannedSlice{docs: []bson.M{
		{"name": "_id_", "accesses": bson.M{"ops": int64(42)}, "size": int64(128)},
	}}

	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectCollStatsExported(context.Background(), f, ti, map[string]string{"db.instance": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.database.document_count", 100)
	requireValue(t, metrics, "db.mongodb.database.index_count", 5)
	requireValue(t, metrics, "db.mongodb.collection.document_count", 100)
	requireValue(t, metrics, "db.mongodb.collection.index_count", 2)
	requireValue(t, metrics, "db.mongodb.collection.capped", 1)
	requireValue(t, metrics, "db.mongodb.collection.capped_max_documents", 1000)
	requireValue(t, metrics, "db.mongodb.index.accesses", 42)
	requireValue(t, metrics, "db.mongodb.index.size_bytes", 128)
}

func TestCollectCollStats_DiscoverError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	if _, err := mongodb.CollectCollStatsExported(context.Background(), f, ti, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectCollStats_ListCollectionsError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|dbStats"] = cannedResult{doc: bson.M{"objects": int64(1)}}
	f.listCollections["app"] = cannedNames{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectCollStatsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// dbStats still emitted despite listCollections failure
	requireValue(t, metrics, "db.mongodb.database.document_count", 1)
}

// ---------- QueryMetrics ----------

func TestCollectQueryMetrics_Aggregation(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{docs: []bson.M{
		{"query": map[string]interface{}{"find": "users", "filter": map[string]interface{}{"x": 1}},
			"ns": "app.users", "op": "query", "millis": int64(50), "docsExamined": int64(10), "nreturned": int64(2)},
		{"command": map[string]interface{}{"find": "users", "filter": map[string]interface{}{"x": 2}},
			"ns": "app.users", "op": "query", "millis": int64(150), "docsExamined": int64(20), "nreturned": int64(1)},
		{"no-query-here": true},
	}}

	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, map[string]string{"db.instance": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// both docs normalize to same {find:?} fingerprint -> aggregated
	if m, ok := metricByName(metrics, "db.mongodb.query.max_duration_ms"); ok {
		if m.Value != 150 {
			t.Errorf("max_duration_ms = %v, want 150", m.Value)
		}
	} else {
		t.Error("expected max_duration_ms")
	}
	requireValue(t, metrics, "db.mongodb.query.docs_scanned", 30)
	requireValue(t, metrics, "db.mongodb.query.docs_returned", 3)
}

func TestCollectQueryMetrics_ProfilerDisabled(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(0)}}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics when profiler disabled, got %d", len(metrics))
	}
}

func TestCollectQueryMetrics_DiscoverError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	if _, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, nil); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- SlowQueries ----------

func TestCollectSlowQueries_Aggregation(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{docs: []bson.M{
		{"query": map[string]interface{}{"find": "users"}, "ns": "app.users", "op": "query",
			"millis": int64(120), "docsExamined": int64(10), "nreturned": int64(2)},
		{"query": map[string]interface{}{"find": "users"}, "ns": "app.users", "op": "query",
			"millis": int64(300), "docsExamined": int64(40), "nreturned": int64(1)},
	}}

	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectSlowQueriesExported(context.Background(), f, ti, map[string]string{"db.instance": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.query.slow_count", 2)
	requireValue(t, metrics, "db.mongodb.query.slow_max_ms", 300)
	requireValue(t, metrics, "db.mongodb.query.slow_total_docs_examined", 50)
	requireValue(t, metrics, "db.mongodb.query.slow_avg_ms", 210)
}

func TestCollectSlowQueries_ProfilerDisabled(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(0)}}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectSlowQueriesExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

// ---------- helpers ----------

func TestInstanceLabels(t *testing.T) {
	labels := mongodb.InstanceLabelsExported("inst-1", map[string]string{"env": "prod"})
	if labels["db.system"] != "mongodb" {
		t.Errorf("db.system = %q", labels["db.system"])
	}
	if labels["db.instance"] != "inst-1" {
		t.Errorf("db.instance = %q", labels["db.instance"])
	}
	if labels["env"] != "prod" {
		t.Errorf("env tag = %q", labels["env"])
	}
}

func TestCopyLabels(t *testing.T) {
	if got := mongodb.CopyLabelsExported(nil); got == nil || len(got) != 0 {
		t.Errorf("copyLabels(nil) = %v", got)
	}
	src := map[string]string{"a": "1"}
	dst := mongodb.CopyLabelsExported(src)
	dst["b"] = "2"
	if _, ok := src["b"]; ok {
		t.Error("copyLabels did not isolate source map")
	}
}

func TestNormalizeQueryShape(t *testing.T) {
	got := mongodb.NormalizeQueryShapeExported(map[string]interface{}{"find": "users", "filter": map[string]interface{}{"a": 1}})
	if v, ok := got["find"]; !ok || v != "?" {
		t.Errorf("normalizeQueryShape find = %v", got)
	}

	// fallback path: no known op
	fb := mongodb.NormalizeQueryShapeExported(map[string]interface{}{"custom": "x"})
	if fb["custom"] != "?" {
		t.Errorf("fallback normalize = %v", fb)
	}
}

func TestFingerprintMongo(t *testing.T) {
	a := mongodb.FingerprintMongoExported("query", "app.users")
	b := mongodb.FingerprintMongoExported("query", "app.users")
	c := mongodb.FingerprintMongoExported("update", "app.users")
	if a != b {
		t.Error("fingerprint not deterministic")
	}
	if a == c {
		t.Error("different inputs produced same fingerprint")
	}
}
