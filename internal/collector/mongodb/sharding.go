package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectSharding(ctx context.Context, api mongoAPI, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric
	prefix := "db.mongodb.sharding."

	// List shards
	var listShards bson.M
	if err := api.RunCommand(ctx, "admin", bson.D{{Key: "listShards", Value: 1}}, &listShards); err != nil {
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
	if err := api.FindOne(ctx, "config", "settings", bson.D{{Key: "_id", Value: "balancer"}}, &balancerConfig); err == nil {
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
