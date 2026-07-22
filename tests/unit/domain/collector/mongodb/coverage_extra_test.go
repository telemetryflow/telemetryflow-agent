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

	"go.mongodb.org/mongo-driver/v2/bson"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

// ---------- CollStats edge branches ----------

// collStats RunCommand error for a collection must skip that collection while
// still emitting the database-level dbStats metrics.
func TestCollectCollStats_CollStatsError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|dbStats"] = cannedResult{doc: bson.M{"objects": int64(7)}}
	f.listCollections["app"] = cannedNames{names: []string{"users"}}
	f.runCommand["app|collStats"] = cannedResult{err: errBoom}

	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectCollStatsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.database.document_count", 7)
	if _, ok := metricByName(metrics, "db.mongodb.collection.document_count"); ok {
		t.Error("expected no collection metrics when collStats errors")
	}
}

// $indexStats Aggregate error must skip index stats but keep collection metrics.
func TestCollectCollStats_IndexStatsError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|dbStats"] = cannedResult{doc: bson.M{"objects": int64(1)}}
	f.listCollections["app"] = cannedNames{names: []string{"users"}}
	f.runCommand["app|collStats"] = cannedResult{doc: bson.M{"count": int32(3)}}
	f.aggregate["app.users"] = cannedSlice{err: errBoom}

	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectCollStatsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.collection.document_count", 3)
	if _, ok := metricByName(metrics, "db.mongodb.index.accesses"); ok {
		t.Error("expected no index metrics when $indexStats errors")
	}
}

// An index accesses.since bson.DateTime must be recorded as an index_since label.
func TestCollectCollStats_IndexSinceLabel(t *testing.T) {
	since := bson.DateTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli())
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|dbStats"] = cannedResult{doc: bson.M{"objects": int64(1)}}
	f.listCollections["app"] = cannedNames{names: []string{"users"}}
	f.runCommand["app|collStats"] = cannedResult{doc: bson.M{"count": int32(1)}}
	f.aggregate["app.users"] = cannedSlice{docs: []bson.M{
		{"name": "_id_", "accesses": bson.M{"ops": int64(9), "since": since}, "size": int64(64)},
	}}

	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectCollStatsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := metricByName(metrics, "db.mongodb.index.size_bytes")
	if !ok {
		t.Fatal("expected index size metric")
	}
	if m.Labels["index_since"] != "2026-01-02T03:04:05Z" {
		t.Errorf("index_since = %q, want 2026-01-02T03:04:05Z", m.Labels["index_since"])
	}
}

// discoverDatabases must return the cached slice without issuing a listDatabases
// command when the discovery cache is warm.
func TestDiscoverDatabases_CachedHit(t *testing.T) {
	f := newFakeAPI() // no canned listDatabases: a cache miss would error
	ti := mongodb.NewTestInstance("x")
	ti.SetDiscovered([]string{"cached_db"}, time.Now())

	dbs, err := mongodb.DiscoverDatabasesExported(context.Background(), f, ti)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dbs) != 1 || dbs[0] != "cached_db" {
		t.Fatalf("expected cached [cached_db], got %v", dbs)
	}
}

// ---------- fingerprint default branches ----------

func TestNormalizeValue_DefaultType(t *testing.T) {
	// A []string value is not one of the enumerated types, hitting the default
	// branch of normalizeValue which collapses it to "?".
	got := mongodb.NormalizeQuery(map[string]interface{}{"tags": []string{"a", "b"}})
	if got["tags"] != "?" {
		t.Errorf("default normalize = %v, want ?", got["tags"])
	}
}

func TestCanonicalize_DefaultType(t *testing.T) {
	if got := mongodb.CanonicalizeExported(42); got != "?" {
		t.Errorf("canonicalize(42) = %q, want ?", got)
	}
}

// ---------- SlowQueries edge branches ----------

func TestCollectSlowQueries_DiscoverError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	if _, err := mongodb.CollectSlowQueriesExported(context.Background(), f, ti, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectSlowQueries_ProfileCommandError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectSlowQueriesExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

func TestCollectSlowQueries_FindError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectSlowQueriesExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

// A profile doc lacking a "query" field must be skipped. prevTime is seeded so
// the non-zero "since" computation branch is also exercised.
func TestCollectSlowQueries_NoQueryDoc(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{docs: []bson.M{
		{"no-query": true},
		{"query": map[string]interface{}{"find": "users"}, "ns": "app.users", "op": "query", "millis": int64(120)},
	}}
	ti := mongodb.NewTestInstance("x")
	ti.SetPrevTime(time.Now().Add(-30 * time.Second))

	metrics, err := mongodb.CollectSlowQueriesExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.query.slow_count", 1)
}

// ---------- QueryMetrics edge branches ----------

func TestCollectQueryMetrics_ProfileCommandError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

func TestCollectQueryMetrics_FindError(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{err: errBoom}
	ti := mongodb.NewTestInstance("x")
	metrics, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

// With a prior snapshot, "since" and the elapsed rate use inst.prevTime.
func TestCollectQueryMetrics_WithPrevTime(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{docs: []bson.M{
		{"command": map[string]interface{}{"find": "users"}, "ns": "app.users", "op": "query",
			"millis": int64(20), "docsExamined": int64(4), "nreturned": int64(1)},
	}}
	ti := mongodb.NewTestInstance("x")
	ti.SetPrevTime(time.Now().Add(-10 * time.Second))

	metrics, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.query.docs_scanned", 4)
	if _, ok := metricByName(metrics, "db.mongodb.query.calls_rate"); !ok {
		t.Error("expected calls_rate metric")
	}
}

// A prevTime in the future produces a non-positive elapsed, exercising the
// elapsed<=0 clamp.
func TestCollectQueryMetrics_NonPositiveElapsed(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listDatabases"] = cannedResult{doc: bson.M{"databases": bson.A{bson.M{"name": "app"}}}}
	f.runCommand["app|profile"] = cannedResult{doc: bson.M{"was": int32(1)}}
	f.find["app.system.profile"] = cannedSlice{docs: []bson.M{
		{"command": map[string]interface{}{"find": "users"}, "ns": "app.users", "op": "query", "millis": int64(5)},
	}}
	ti := mongodb.NewTestInstance("x")
	ti.SetPrevTime(time.Now().Add(1 * time.Hour))

	metrics, err := mongodb.CollectQueryMetricsExported(context.Background(), f, ti, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := metricByName(metrics, "db.mongodb.query.calls_rate")
	if !ok {
		t.Fatal("expected calls_rate metric")
	}
	// elapsed clamped to 1s, count = 1 -> rate = 1
	if m.Value != 1 {
		t.Errorf("calls_rate = %v, want 1 (elapsed clamped)", m.Value)
	}
}

// ---------- Replication edge branches ----------

// optimeDate ahead of date yields a negative raw lag that must be clamped to 0.
func TestCollectReplication_NegativeLagClamped(t *testing.T) {
	date := bson.DateTime(time.Now().Add(-10 * time.Second).UnixMilli())
	optime := bson.DateTime(time.Now().UnixMilli()) // ahead of date -> negative lag
	f := newFakeAPI()
	f.runCommand["admin|replSetGetStatus"] = cannedResult{doc: bson.M{
		"myState": int32(1),
		"members": bson.A{
			bson.M{"name": "m0", "state": int32(2), "health": int32(1), "optimeDate": optime, "date": date},
		},
	}}
	f.runCommand["local|collStats"] = cannedResult{err: errBoom}

	metrics, err := mongodb.CollectReplicationExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.replication.lag_seconds", 0)
}

// Empty first-oplog aggregate must short-circuit oplog window computation while
// still returning the size metrics.
func TestCollectReplication_OplogFirstEmpty(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|replSetGetStatus"] = cannedResult{doc: bson.M{"myState": int32(1)}}
	f.runCommand["local|collStats"] = cannedResult{doc: bson.M{"size": int64(2048), "maxSize": int64(8192)}}
	f.aggregate["local.oplog.rs"] = cannedSlice{docs: []bson.M{}}

	metrics, err := mongodb.CollectReplicationExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.oplog.size_bytes", 2048)
	if _, ok := metricByName(metrics, "db.mongodb.oplog.window_seconds"); ok {
		t.Error("expected no window metric when first oplog entry is empty")
	}
}

// A non-empty first aggregate followed by an empty last aggregate must
// short-circuit the window computation.
func TestCollectReplication_OplogLastEmpty(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|replSetGetStatus"] = cannedResult{doc: bson.M{"myState": int32(1)}}
	f.runCommand["local|collStats"] = cannedResult{doc: bson.M{"size": int64(2048)}}
	f.aggregateSeq["local.oplog.rs"] = []cannedSlice{
		{docs: []bson.M{{"ts": bson.Timestamp{T: 100}}}}, // first
		{docs: []bson.M{}},                               // last (empty)
	}

	metrics, err := mongodb.CollectReplicationExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.oplog.size_bytes", 2048)
	if _, ok := metricByName(metrics, "db.mongodb.oplog.window_seconds"); ok {
		t.Error("expected no window metric when last oplog entry is empty")
	}
}

// ---------- Sharding edge branch ----------

// A non-document entry in the shards array must be skipped.
func TestCollectSharding_NonDocShard(t *testing.T) {
	f := newFakeAPI()
	f.runCommand["admin|listShards"] = cannedResult{doc: bson.M{
		"shards": bson.A{
			bson.M{"_id": "shard0", "state": int32(1)},
			"not-a-doc",
		},
	}}
	f.findOne["config.settings"] = cannedResult{err: errBoom}

	metrics, err := mongodb.CollectShardingExported(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValue(t, metrics, "db.mongodb.sharding.total_shards", 2)
	// Only the valid shard produces a member_state metric.
	count := 0
	for _, m := range metrics {
		if m.Name == "db.mongodb.sharding.member_state" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("member_state metrics = %d, want 1", count)
	}
}
