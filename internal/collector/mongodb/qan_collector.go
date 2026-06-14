// Package mongodb implements the MongoDB QAN collector using the profiler
// (system.profile) with delta calculation from previous snapshot.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// QANMongoDBCollector collects query analytics from the MongoDB profiler
// (system.profile) with delta calculation. It implements qan.QANCollector.
type QANMongoDBCollector struct {
	cfg    QANMongoDBConfig
	logger *zap.Logger

	mu        sync.RWMutex
	running   bool
	instances []*qanMongoInstance
}

// QANMongoDBConfig holds configuration for the MongoDB QAN collector.
type QANMongoDBConfig struct {
	Instances       []config.MongoDBCommunityInstanceConfig
	TopQueriesLimit int
	Labels          map[string]string
	Logger          *zap.Logger
}

// qanMongoInstance holds per-instance state including delta cache.
type qanMongoInstance struct {
	config       config.MongoDBCommunityInstanceConfig
	client       *mongo.Client
	mu           sync.Mutex
	prevSnapshot map[string]*mongoProfileSnapshot // keyed by fingerprint
	prevTime     time.Time
}

// mongoProfileSnapshot captures aggregated profiler stats per query shape.
type mongoProfileSnapshot struct {
	fingerprint   string
	count         uint64
	millisTotal   uint64
	docsReturned  uint64
	docsScanned   uint64
	keysExamined  uint64
	responseBytes uint64
}

// NewQANMongoDBCollector creates a new MongoDB QAN collector.
func NewQANMongoDBCollector(cfg QANMongoDBConfig, logger *zap.Logger) *QANMongoDBCollector {
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 200
	}
	instances := make([]*qanMongoInstance, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instances[i] = &qanMongoInstance{
			config:       inst,
			prevSnapshot: make(map[string]*mongoProfileSnapshot),
		}
	}

	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &QANMongoDBCollector{
		cfg:       cfg,
		logger:    logger.Named("qan-mongodb-profiler"),
		instances: instances,
	}
}

// Name returns the collector name.
func (c *QANMongoDBCollector) Name() string { return "qan-mongodb-profiler" }

// AgentType returns the PMM-compatible agent type.
func (c *QANMongoDBCollector) AgentType() qan.AgentType {
	return qan.AgentTypeMongoDBProfiler
}

// IsRunning returns whether the collector is active.
func (c *QANMongoDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start initializes database connections.
func (c *QANMongoDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("qan-mongodb collector already running")
	}
	c.running = true
	c.mu.Unlock()

	c.logger.Info("QAN MongoDB collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
	)
	return nil
}

// Stop closes database connections.
func (c *QANMongoDBCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	for _, inst := range c.instances {
		if inst.client != nil {
			_ = inst.client.Disconnect(context.Background())
			inst.client = nil
		}
	}
	return nil
}

// CollectQAN queries the profiler, aggregates by query shape, computes
// deltas, and returns buckets.
func (c *QANMongoDBCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
	if len(c.instances) == 0 {
		return nil, nil
	}

	var allBuckets []qan.QANMetricsBucket
	for _, inst := range c.instances {
		buckets, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("QAN collection failed for instance",
				zap.String("instance", inst.config.Name),
				zap.Error(err),
			)
			continue
		}
		allBuckets = append(allBuckets, buckets...)
	}
	return allBuckets, nil
}

func (c *QANMongoDBCollector) collectInstance(ctx context.Context, inst *qanMongoInstance) ([]qan.QANMetricsBucket, error) {
	client, err := c.ensureConnection(ctx, inst)
	if err != nil {
		return nil, err
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	now := time.Now()
	sinceTS := bson.NewDateTimeFromTime(inst.prevTime.Add(-5 * time.Second))
	if inst.prevTime.IsZero() {
		sinceTS = bson.NewDateTimeFromTime(now.Add(-60 * time.Second))
	}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{
			{Key: "ts", Value: bson.D{{Key: "$gt", Value: sinceTS}}},
			{Key: "op", Value: bson.D{{Key: "$in", Value: []string{"query", "command", "getmore"}}}},
		}}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{
				{Key: "op", Value: "$op"},
				{Key: "ns", Value: "$ns"},
			}},
			{Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "millisTotal", Value: bson.D{{Key: "$sum", Value: "$millis"}}},
			{Key: "millisMax", Value: bson.D{{Key: "$max", Value: "$millis"}}},
			{Key: "millisMin", Value: bson.D{{Key: "$min", Value: "$millis"}}},
			{Key: "docsReturned", Value: bson.D{{Key: "$sum", Value: "$nreturned"}}},
			{Key: "docsScanned", Value: bson.D{{Key: "$sum", Value: "$docsExamined"}}},
			{Key: "keysExamined", Value: bson.D{{Key: "$sum", Value: "$keysExamined"}}},
			{Key: "responseBytes", Value: bson.D{{Key: "$sum", Value: "$responseLength"}}},
			{Key: "planSummary", Value: bson.D{{Key: "$first", Value: "$planSummary"}}},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "millisTotal", Value: -1}}}},
		{{Key: "$limit", Value: c.cfg.TopQueriesLimit}},
	}

	// system.profile lives in each DB that has profiling enabled.
	// Use the instance name or "admin" as a fallback; the URI itself
	// determines the default database in the connection string.
	dbName := "admin"

	cursor, err := client.Database(dbName).Collection("system.profile").Aggregate(ctx2, pipeline)
	if err != nil {
		return nil, fmt.Errorf("aggregate system.profile: %w", err)
	}
	defer func() { _ = cursor.Close(ctx2) }()

	var periodLength time.Duration
	if inst.prevTime.IsZero() {
		periodLength = 60 * time.Second
	} else {
		periodLength = now.Sub(inst.prevTime)
		if periodLength <= 0 {
			periodLength = 60 * time.Second
		}
	}

	currentSnapshot := make(map[string]*mongoProfileSnapshot)
	var buckets []qan.QANMetricsBucket
	labels := c.instanceLabels(inst)

	for cursor.Next(ctx2) {
		var result struct {
			ID struct {
				Op string `bson:"op"`
				Ns string `bson:"ns"`
			} `bson:"_id"`
			Count         uint64 `bson:"count"`
			MillisTotal   uint64 `bson:"millisTotal"`
			MillisMax     uint64 `bson:"millisMax"`
			MillisMin     uint64 `bson:"millisMin"`
			DocsReturned  uint64 `bson:"docsReturned"`
			DocsScanned   uint64 `bson:"docsScanned"`
			KeysExamined  uint64 `bson:"keysExamined"`
			ResponseBytes uint64 `bson:"responseBytes"`
			PlanSummary   string `bson:"planSummary"`
		}
		if err := cursor.Decode(&result); err != nil {
			continue
		}

		fp := fingerprintMongo(result.ID.Op, result.ID.Ns)
		snap := &mongoProfileSnapshot{
			fingerprint:   fp,
			count:         result.Count,
			millisTotal:   result.MillisTotal,
			docsReturned:  result.DocsReturned,
			docsScanned:   result.DocsScanned,
			keysExamined:  result.KeysExamined,
			responseBytes: result.ResponseBytes,
		}
		currentSnapshot[fp] = snap

		prev, hasPrev := inst.prevSnapshot[fp]
		if !hasPrev {
			continue
		}

		deltaCount := int64(result.Count) - int64(prev.count)
		if deltaCount <= 0 {
			continue
		}

		deltaMillis := int64(result.MillisTotal) - int64(prev.millisTotal)
		deltaDocsReturned := int64(result.DocsReturned) - int64(prev.docsReturned)
		deltaDocsScanned := int64(result.DocsScanned) - int64(prev.docsScanned)
		deltaKeysExamined := int64(result.KeysExamined) - int64(prev.keysExamined)
		deltaResponseBytes := int64(result.ResponseBytes) - int64(prev.responseBytes)

		bucket := qan.QANMetricsBucket{
			AgentType:       qan.AgentTypeMongoDBProfiler,
			QueryID:         fp,
			Fingerprint:     fp,
			Example:         fmt.Sprintf("%s on %s", result.ID.Op, result.ID.Ns),
			PeriodStartSec:  inst.prevTime.Unix(),
			PeriodLengthSec: int64(periodLength.Seconds()),
			Database:        result.ID.Ns,
			Labels:          labels,
			NumQueries:      float64(deltaCount),
			QueryTimeCnt:    float64(deltaCount),
			QueryTimeSum:    float64(deltaMillis) / 1000.0,
			QueryTimeMin:    float64(result.MillisMin) / 1000.0,
			QueryTimeMax:    float64(result.MillisMax) / 1000.0,
			MongoDB: &qan.MongoDBQANMetrics{
				DocsReturnedCnt: float64(deltaCount),
				DocsReturnedSum: float64(deltaDocsReturned),
				DocsScannedCnt:  float64(deltaCount),
				DocsScannedSum:  float64(deltaDocsScanned),
				KeysExaminedCnt: float64(deltaCount),
				KeysExaminedSum: float64(deltaKeysExamined),

				ResponseLengthCnt: float64(deltaCount),
				ResponseLengthSum: float64(deltaResponseBytes),

				PlanSummary: result.PlanSummary,
			},
		}

		buckets = append(buckets, bucket)
	}

	inst.prevSnapshot = currentSnapshot
	inst.prevTime = now

	return buckets, nil
}

func (c *QANMongoDBCollector) ensureConnection(ctx context.Context, inst *qanMongoInstance) (*mongo.Client, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.client != nil {
		if err := inst.client.Ping(ctx, readpref.SecondaryPreferred()); err == nil {
			return inst.client, nil
		}
		_ = inst.client.Disconnect(ctx)
		inst.client = nil
	}

	opts := options.Client().ApplyURI(inst.config.URI).
		SetReadPreference(readpref.SecondaryPreferred()).
		SetServerSelectionTimeout(10 * time.Second).
		SetConnectTimeout(10 * time.Second)

	if inst.config.Username != "" {
		opts.SetAuth(options.Credential{
			Username: inst.config.Username,
			Password: inst.config.Password,
		})
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("mongodb %s: connect: %w", inst.config.Name, err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx2, readpref.SecondaryPreferred()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("mongodb %s: ping: %w", inst.config.Name, err)
	}

	inst.client = client
	return client, nil
}

func (c *QANMongoDBCollector) instanceLabels(inst *qanMongoInstance) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Labels {
		labels[k] = v
	}
	labels["mongodb_instance"] = inst.config.Name
	labels["db_system"] = "mongodb"
	return labels
}

func fingerprintMongo(op, ns string) string {
	normalised := strings.ToLower(fmt.Sprintf("%s|%s", op, ns))
	h := sha256.Sum256([]byte(normalised))
	return fmt.Sprintf("%x", h[:16])
}
