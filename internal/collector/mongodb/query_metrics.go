package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectQueryMetrics queries system.profile for all queries (not just slow),
// aggregates by fingerprint, computes rates from previous snapshot,
// and emits per-fingerprint metrics for QAN consumption.
func collectQueryMetrics(ctx context.Context, api mongoAPI, inst *mongoInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	prefix := "db.mongodb.query."
	var all []collector.Metric

	dbs, err := discoverDatabases(ctx, api, inst)
	if err != nil {
		return nil, err
	}

	type fpAggEntry struct {
		fingerprint   string
		database      string
		collection    string
		operation     string
		count         int
		totalDuration float64
		maxDuration   float64
		docsScanned   float64
		docsReturned  float64
	}

	fingerprintAgg := map[string]*fpAggEntry{}

	for _, dbName := range dbs {
		// Check if profiler is enabled (level >= 1)
		var profileResult bson.M
		if err := api.RunCommand(ctx, dbName, bson.D{{Key: "profile", Value: -1}}, &profileResult); err != nil {
			logger.Debug("Cannot read profiler status",
				zap.String("instance", inst.config.Name),
				zap.String("database", dbName),
				zap.Error(err),
			)
			continue
		}
		if was, ok := profileResult["was"].(int32); !ok || was < 1 {
			logger.Debug("Profiler disabled, skipping query metrics",
				zap.String("instance", inst.config.Name),
				zap.String("database", dbName),
			)
			continue
		}

		// Query recent entries since last collection
		since := time.Now().Add(-60 * time.Second)
		if !inst.prevTime.IsZero() {
			since = inst.prevTime
		}

		var profileDocs []bson.M
		if err := api.Find(ctx, dbName, "system.profile", bson.D{
			{Key: "ts", Value: bson.D{{Key: "$gte", Value: since}}},
		}, &profileDocs); err != nil {
			logger.Debug("Cannot query system.profile",
				zap.String("instance", inst.config.Name),
				zap.String("database", dbName),
				zap.Error(err),
			)
			continue
		}

		for _, doc := range profileDocs {
			queryDoc, _ := doc["query"].(map[string]interface{})
			if queryDoc == nil {
				// Try "command" field for modern MongoDB versions
				queryDoc, _ = doc["command"].(map[string]interface{})
			}
			if queryDoc == nil {
				continue
			}

			// Normalize: keep only the operation type key
			normalized := normalizeQueryShape(queryDoc)
			fp := FingerprintQuery(normalized)

			ns := asString(doc["ns"])
			op := asString(doc["op"])
			millis := asFloat(doc["millis"])
			docsExamined := asFloat(doc["docsExamined"])
			docsReturned := asFloat(doc["nreturned"])

			key := fmt.Sprintf("%s.%s.%s", dbName, ns, fp)
			if _, exists := fingerprintAgg[key]; !exists {
				fingerprintAgg[key] = &fpAggEntry{
					fingerprint: fp,
					database:    dbName,
					collection:  ns,
					operation:   op,
				}
			}
			a := fingerprintAgg[key]
			a.count++
			a.totalDuration += millis
			if millis > a.maxDuration {
				a.maxDuration = millis
			}
			a.docsScanned += docsExamined
			a.docsReturned += docsReturned
		}
	}

	// Compute elapsed time for rate calculation
	now := time.Now()
	elapsed := 60.0 // default 60s
	if !inst.prevTime.IsZero() {
		elapsed = now.Sub(inst.prevTime).Seconds()
	}
	if elapsed <= 0 {
		elapsed = 1
	}

	// Emit aggregated fingerprint metrics
	for _, a := range fingerprintAgg {
		fpLabels := copyLabels(labels)
		fpLabels["fingerprint"] = a.fingerprint
		fpLabels["database"] = a.database
		fpLabels["collection"] = a.collection
		fpLabels["operation"] = a.operation

		all = append(all,
			gauge(prefix+"calls_rate", float64(a.count)/elapsed, fpLabels),
			gauge(prefix+"avg_duration_ms", safeDiv(a.totalDuration, float64(a.count)), fpLabels),
			gauge(prefix+"max_duration_ms", a.maxDuration, fpLabels),
			gauge(prefix+"docs_scanned", a.docsScanned, fpLabels),
			gauge(prefix+"docs_returned", a.docsReturned, fpLabels),
		)
	}

	return all, nil
}

// normalizeQueryShape keeps only the top-level operation type for fingerprinting.
func normalizeQueryShape(doc map[string]interface{}) map[string]interface{} {
	// Common MongoDB operations to preserve
	ops := []string{"find", "aggregate", "count", "distinct", "update", "delete", "insert", "findAndModify"}
	for _, op := range ops {
		if _, ok := doc[op]; ok {
			return map[string]interface{}{op: "?"}
		}
	}
	// Fallback: normalize the full document
	return NormalizeQuery(doc)
}
