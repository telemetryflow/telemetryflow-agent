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

package mongodb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func testLogger() *zap.Logger { return zap.NewNop() }

// This file exposes internal collect functions and the driver abstraction to
// the external (black-box) test package so the collectors can be exercised
// through a hand-written fake without a real MongoDB instance.

// MongoAPI is the exported alias of the internal driver abstraction so tests
// can supply a fake implementation.
type MongoAPI = mongoAPI

// TestInstance is a lightweight, test-constructable handle around the internal
// per-instance collector state.
type TestInstance struct {
	inst *mongoInstance
}

// NewTestInstance builds a *mongoInstance for tests with the given name.
func NewTestInstance(name string) *TestInstance {
	return &TestInstance{
		inst: &mongoInstance{
			config:       config.MongoDBCommunityInstanceConfig{Name: name},
			prevCounters: make(map[string]float64),
		},
	}
}

// SetPrevTime seeds the per-instance prevTime so rate/window branches that
// depend on a prior snapshot can be exercised without a network connection.
func (ti *TestInstance) SetPrevTime(t time.Time) { ti.inst.prevTime = t }

// SetDiscovered seeds the database discovery cache so the cached-hit branch of
// discoverDatabases can be exercised.
func (ti *TestInstance) SetDiscovered(dbs []string, at time.Time) {
	ti.inst.discoveredDBs = dbs
	ti.inst.discoveredAt = at
}

// CanonicalizeExported exposes the internal canonicalize helper so its default
// (non-string/map/slice) branch can be exercised directly.
func CanonicalizeExported(v interface{}) string { return canonicalize(v) }

// CollectServerStatusExported drives collectServerStatus through the fake API.
func CollectServerStatusExported(ctx context.Context, api MongoAPI, labels map[string]string) ([]collector.Metric, error) {
	return collectServerStatus(ctx, api, labels, testLogger())
}

// CollectWiredTigerExported drives collectWiredTiger through the fake API.
func CollectWiredTigerExported(ctx context.Context, api MongoAPI, labels map[string]string) ([]collector.Metric, error) {
	return collectWiredTiger(ctx, api, labels, testLogger())
}

// CollectReplicationExported drives collectReplication through the fake API.
func CollectReplicationExported(ctx context.Context, api MongoAPI, labels map[string]string) ([]collector.Metric, error) {
	return collectReplication(ctx, api, labels, testLogger())
}

// CollectShardingExported drives collectSharding through the fake API.
func CollectShardingExported(ctx context.Context, api MongoAPI, labels map[string]string) ([]collector.Metric, error) {
	return collectSharding(ctx, api, labels, testLogger())
}

// CollectCurrentOpExported drives collectCurrentOp through the fake API.
func CollectCurrentOpExported(ctx context.Context, api MongoAPI, labels map[string]string) ([]collector.Metric, error) {
	return collectCurrentOp(ctx, api, labels, testLogger())
}

// CollectCollStatsExported drives collectCollStats through the fake API.
func CollectCollStatsExported(ctx context.Context, api MongoAPI, ti *TestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectCollStats(ctx, api, ti.inst, labels, testLogger())
}

// CollectQueryMetricsExported drives collectQueryMetrics through the fake API.
func CollectQueryMetricsExported(ctx context.Context, api MongoAPI, ti *TestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectQueryMetrics(ctx, api, ti.inst, labels, testLogger())
}

// CollectSlowQueriesExported drives collectSlowQueries through the fake API.
func CollectSlowQueriesExported(ctx context.Context, api MongoAPI, ti *TestInstance, labels map[string]string) ([]collector.Metric, error) {
	return collectSlowQueries(ctx, api, ti.inst, labels, testLogger())
}

// DiscoverDatabasesExported drives discoverDatabases through the fake API.
func DiscoverDatabasesExported(ctx context.Context, api MongoAPI, ti *TestInstance) ([]string, error) {
	return discoverDatabases(ctx, api, ti.inst)
}

// InstanceLabelsExported exposes instanceLabels for tests.
func InstanceLabelsExported(name string, tags map[string]string) map[string]string {
	return instanceLabels(&mongoInstance{
		config: config.MongoDBCommunityInstanceConfig{Name: name, Tags: tags},
	})
}

// CopyLabelsExported exposes copyLabels for tests.
func CopyLabelsExported(src map[string]string) map[string]string { return copyLabels(src) }

// NormalizeQueryShapeExported exposes normalizeQueryShape for tests.
func NormalizeQueryShapeExported(doc map[string]interface{}) map[string]interface{} {
	return normalizeQueryShape(doc)
}

// FingerprintMongoExported exposes fingerprintMongo for tests.
func FingerprintMongoExported(op, ns string) string { return fingerprintMongo(op, ns) }

// ComputeRatesExported exposes computeRates for tests. It seeds prevCounters so
// the rate loop executes over known counter names.
func ComputeRatesExported(prev map[string]float64, elapsed float64, labels map[string]string) []collector.Metric {
	inst := &mongoInstance{prevCounters: prev}
	return computeRates(inst, elapsed, labels)
}

// AdvanceBackoffExported runs advanceBackoff n times against a fresh instance
// and returns the resulting backoff durations in seconds. Exercises the pure
// exponential back-off logic without a network connection.
func AdvanceBackoffExported(n int) []float64 {
	c := &MongoDBCollector{}
	inst := &mongoInstance{}
	out := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		c.advanceBackoff(inst)
		out = append(out, inst.backoff.Seconds())
	}
	return out
}

// CloseConnectionNilExported exercises closeConnection with a nil client
// (no network involved) to confirm it is a safe no-op.
func CloseConnectionNilExported() {
	c := &MongoDBCollector{}
	c.closeConnection(&mongoInstance{})
}

// DetectTopologyNilExported exercises detectTopology early-return with a nil
// client (no network involved).
func DetectTopologyNilExported() {
	c := &MongoDBCollector{logger: testLogger()}
	c.detectTopology(context.Background(), &mongoInstance{})
}

// QANInstanceLabelsExported exposes the QAN collector's instanceLabels helper.
func QANInstanceLabelsExported(name string, cfgLabels map[string]string) map[string]string {
	c := &QANMongoDBCollector{cfg: QANMongoDBConfig{Labels: cfgLabels}}
	return c.instanceLabels(&qanMongoInstance{
		config: config.MongoDBCommunityInstanceConfig{Name: name},
	})
}
