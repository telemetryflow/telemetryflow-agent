package mongodb

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectReplication(ctx context.Context, client *mongo.Client, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	admin := client.Database("admin")

	var rsStatus bson.M
	if err := admin.RunCommand(ctx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&rsStatus); err != nil {
		// Error code 76 = Not running with --replSet (standalone)
		return nil, err
	}

	var all []collector.Metric
	prefix := "db.mongodb.replication."

	// Replica set state
	if myState, ok := rsStatus["myState"].(int32); ok {
		all = append(all, gauge(prefix+"my_state", float64(myState), labels))
	}

	// Per-member metrics
	if members, ok := rsStatus["members"].(bson.A); ok {
		for _, m := range members {
			member, ok := m.(bson.M)
			if !ok {
				continue
			}
			name := asString(member["name"])
			memberLabels := copyLabels(labels)
			memberLabels["member"] = name

			all = append(all,
				gauge(prefix+"member_state", float64(asInt(member["state"])), memberLabels),
				gauge(prefix+"member_health", float64(asInt(member["health"])), memberLabels),
			)

			// Replication lag (only for secondaries)
			if optimeDate, ok := member["optimeDate"].(bson.DateTime); ok {
				if date, ok := member["date"].(bson.DateTime); ok {
					lag := time.UnixMilli(date.Time().UnixMilli()).Sub(time.UnixMilli(optimeDate.Time().UnixMilli()))
					lagSeconds := lag.Seconds()
					if lagSeconds < 0 {
						lagSeconds = 0
					}
					all = append(all, gauge(prefix+"lag_seconds", lagSeconds, memberLabels))
				}
			}

			// Heartbeat latency
			if pingMs, ok := member["pingMs"]; ok {
				all = append(all, gauge(prefix+"heartbeat_latency_ms", float64(asInt(pingMs)), memberLabels))
			}

			// Uptime
			if uptime, ok := member["uptime"]; ok {
				all = append(all, gauge(prefix+"uptime_seconds", float64(asInt64(uptime)), memberLabels))
			}
		}
	}

	// Oplog metrics
	oplogMetrics, err := collectOplogMetrics(ctx, client, labels)
	if err != nil {
		logger.Debug("Oplog metrics collection skipped", zap.Error(err))
	} else {
		all = append(all, oplogMetrics...)
	}

	return all, nil
}

func collectOplogMetrics(ctx context.Context, client *mongo.Client, labels map[string]string) ([]collector.Metric, error) {
	localDB := client.Database("local")

	// Get oplog stats
	var stats bson.M
	if err := localDB.RunCommand(ctx, bson.D{
		{Key: "collStats", Value: "oplog.rs"},
	}).Decode(&stats); err != nil {
		// Try alternative approach
		return nil, err
	}

	prefix := "db.mongodb.oplog."
	var all []collector.Metric

	if size, ok := stats["size"]; ok {
		all = append(all, gauge(prefix+"size_bytes", asFloat(size), labels))
	}
	if maxSize, ok := stats["maxSize"]; ok {
		all = append(all, gauge(prefix+"max_size_bytes", asFloat(maxSize), labels))
	}

	// Calculate oplog window from first/last entries
	firstPipeline := bson.A{
		bson.D{{Key: "$sort", Value: bson.D{{Key: "ts", Value: 1}}}},
		bson.D{{Key: "$limit", Value: 1}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "ts", Value: 1}}}},
	}
	lastPipeline := bson.A{
		bson.D{{Key: "$sort", Value: bson.D{{Key: "ts", Value: -1}}}},
		bson.D{{Key: "$limit", Value: 1}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "ts", Value: 1}}}},
	}

	oplogCol := localDB.Collection("oplog.rs")

	cursor, err := oplogCol.Aggregate(ctx, firstPipeline)
	if err != nil {
		return all, nil
	}
	var first []bson.M
	if err := cursor.All(ctx, &first); err != nil || len(first) == 0 {
		return all, nil
	}

	cursor2, err := oplogCol.Aggregate(ctx, lastPipeline)
	if err != nil {
		return all, nil
	}
	var last []bson.M
	if err := cursor2.All(ctx, &last); err != nil || len(last) == 0 {
		return all, nil
	}

	firstTs, ok1 := first[0]["ts"].(bson.Timestamp)
	lastTs, ok2 := last[0]["ts"].(bson.Timestamp)
	if ok1 && ok2 {
		window := int64(lastTs.T) - int64(firstTs.T)
		all = append(all, gauge(prefix+"window_seconds", float64(window), labels))
	}

	return all, nil
}
