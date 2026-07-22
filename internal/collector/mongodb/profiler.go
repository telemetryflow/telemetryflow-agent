package mongodb

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectSlowQueries reads system.profile for slow queries and emits fingerprint metrics.
func collectSlowQueries(ctx context.Context, api mongoAPI, inst *mongoInstance, labels map[string]string, _ *zap.Logger) ([]collector.Metric, error) {
	prefix := "db.mongodb.query."
	var all []collector.Metric

	dbs, err := discoverDatabases(ctx, api, inst)
	if err != nil {
		return nil, err
	}

	fingerprintAgg := map[string]*fpAgg{}

	for _, dbName := range dbs {
		// Check if profiler is enabled (level >= 1)
		var profileResult bson.M
		if err := api.RunCommand(ctx, dbName, bson.D{{Key: "profile", Value: -1}}, &profileResult); err != nil {
			continue
		}
		if was, ok := profileResult["was"].(int32); !ok || was < 1 {
			continue
		}

		// Query recent slow queries (last profile_interval)
		since := time.Now().Add(-inst.prevTime.Sub(time.Time{}))
		if inst.prevTime.IsZero() {
			since = time.Now().Add(-60 * time.Second)
		}

		var profileDocs []bson.M
		if err := api.Find(ctx, dbName, "system.profile", bson.D{
			{Key: "ts", Value: bson.D{{Key: "$gte", Value: since}}},
			{Key: "millis", Value: bson.D{{Key: "$gte", Value: 100}}},
		}, &profileDocs); err != nil {
			continue
		}

		for _, doc := range profileDocs {
			queryDoc, _ := doc["query"].(map[string]interface{})
			if queryDoc == nil {
				continue
			}

			// Strip command wrapper
			if cmd, ok := queryDoc["find"].(string); ok {
				queryDoc = map[string]interface{}{"find": cmd}
			}

			fp := FingerprintQuery(queryDoc)
			collection := asString(doc["ns"])
			op := asString(doc["op"])
			millis := asFloat(doc["millis"])
			docsExamined := asFloat(doc["docsExamined"])
			docsReturned := asFloat(doc["nreturned"])

			key := dbName + "." + collection + "." + fp
			if _, exists := fingerprintAgg[key]; !exists {
				fingerprintAgg[key] = &fpAgg{
					fingerprint:   fp,
					database:      dbName,
					collection:    collection,
					operation:     op,
					totalCount:    0,
					totalMillis:   0,
					maxMillis:     0,
					totalDocsExam: 0,
				}
			}
			a := fingerprintAgg[key]
			a.totalCount++
			a.totalMillis += millis
			if millis > a.maxMillis {
				a.maxMillis = millis
			}
			a.totalDocsExam += docsExamined
			_ = docsReturned
		}
	}

	// Emit aggregated fingerprint metrics
	for _, a := range fingerprintAgg {
		fpLabels := copyLabels(labels)
		fpLabels["fingerprint"] = a.fingerprint
		fpLabels["database"] = a.database
		fpLabels["collection"] = a.collection
		fpLabels["operation"] = a.operation

		all = append(all,
			counter(prefix+"slow_count", float64(a.totalCount), fpLabels),
			gauge(prefix+"slow_avg_ms", safeDiv(a.totalMillis, float64(a.totalCount)), fpLabels),
			gauge(prefix+"slow_max_ms", a.maxMillis, fpLabels),
			counter(prefix+"slow_total_docs_examined", a.totalDocsExam, fpLabels),
		)
	}

	return all, nil
}

type fpAgg struct {
	fingerprint   string
	database      string
	collection    string
	operation     string
	totalCount    int
	totalMillis   float64
	maxMillis     float64
	totalDocsExam float64
}
