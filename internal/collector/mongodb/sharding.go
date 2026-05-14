package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectSharding(ctx context.Context, client *mongo.Client, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	admin := client.Database("admin")
	var all []collector.Metric
	prefix := "db.mongodb.sharding."

	// List shards
	var listShards bson.M
	if err := admin.RunCommand(ctx, bson.D{{Key: "listShards", Value: 1}}).Decode(&listShards); err != nil {
		return nil, err
	}

	if shards, ok := listShards["shards"].(bson.A); ok {
		all = append(all, gauge(prefix+"total_shards", float64(len(shards)), labels))

		// Per-shard chunk counts (requires config.chunks aggregation)
		for _, s := range shards {
			shard, ok := s.(bson.M)
			if !ok {
				continue
			}
			shardID := asString(shard["_id"])
			shardLabels := copyLabels(labels)
			shardLabels["shard"] = shardID
			all = append(all, gauge(prefix+"member_state", float64(asInt(shard["state"])), shardLabels))
		}
	}

	// Balancer status
	var balancerConfig bson.M
	configDB := client.Database("config")
	if err := configDB.Collection("settings").FindOne(ctx, bson.D{{Key: "_id", Value: "balancer"}}).Decode(&balancerConfig); err == nil {
		if stopped, ok := balancerConfig["stopped"].(bool); ok {
			if stopped {
				all = append(all, gauge(prefix+"balancer_enabled", 0, labels))
			} else {
				all = append(all, gauge(prefix+"balancer_enabled", 1, labels))
			}
		}
	}

	return all, nil
}
