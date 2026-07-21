package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectWiredTiger(ctx context.Context, api mongoAPI, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var result bson.M
	if err := api.RunCommand(ctx, "admin", bson.D{{Key: "serverStatus", Value: 1}}, &result); err != nil {
		return nil, err
	}

	wt, ok := result["wiredTiger"].(bson.M)
	if !ok {
		return nil, nil // WiredTiger not present (e.g., MMAPv1)
	}

	var all []collector.Metric
	prefix := "db.mongodb.wiredtiger."

	// Cache metrics
	if cache, ok := wt["cache"].(bson.M); ok {
		all = append(all,
			gauge(prefix+"cache.bytes_in_cache", asFloat(cache["bytes currently in the cache"]), labels),
			gauge(prefix+"cache.bytes_dirty", asFloat(cache["tracked dirty bytes in the cache"]), labels),
			gauge(prefix+"cache.max_bytes", asFloat(cache["maximum bytes configured"]), labels),
			counter(prefix+"cache.bytes_read_into", asFloat(cache["bytes read into cache"]), labels),
			counter(prefix+"cache.bytes_written_from", asFloat(cache["bytes written from cache"]), labels),
			counter(prefix+"cache.pages_evicted_unmodified", asFloat(cache["unmodified pages evicted"]), labels),
			counter(prefix+"cache.pages_evicted_modified", asFloat(cache["modified pages evicted"]), labels),
			counter(prefix+"cache.eviction_calls", asFloat(cache["eviction calls"]), labels),
		)

		maxBytes := asFloat(cache["maximum bytes configured"])
		inCache := asFloat(cache["bytes currently in the cache"])
		if maxBytes > 0 {
			utilization := safeDiv(inCache, maxBytes) * 100
			all = append(all, gauge(prefix+"cache.utilization_percent", utilization, labels))
		}
	}

	// Concurrency ticket metrics
	if concurrency, ok := wt["concurrentTransactions"].(bson.M); ok {
		if read, ok := concurrency["read"].(bson.M); ok {
			all = append(all,
				gauge(prefix+"tickets.read.available", float64(asInt(read["available"])), labels),
				gauge(prefix+"tickets.read.out", float64(asInt(read["out"])), labels),
				gauge(prefix+"tickets.read.total", float64(asInt(read["totalTickets"])), labels),
			)
		}
		if write, ok := concurrency["write"].(bson.M); ok {
			all = append(all,
				gauge(prefix+"tickets.write.available", float64(asInt(write["available"])), labels),
				gauge(prefix+"tickets.write.out", float64(asInt(write["out"])), labels),
				gauge(prefix+"tickets.write.total", float64(asInt(write["totalTickets"])), labels),
			)
		}
	}

	// Checkpoint metrics
	if ckpt, ok := wt["checkpoint"].(bson.M); ok {
		all = append(all,
			gauge(prefix+"checkpoint.duration_ms", asFloat(ckpt["latest checkpoint duration"]), labels),
			counter(prefix+"checkpoint.total", asFloat(ckpt["total checkpoints"]), labels),
			counter(prefix+"checkpoint.pages_written", asFloat(ckpt["latest checkpoint pages written"]), labels),
			gauge(prefix+"checkpoint.min_duration_ms", asFloat(ckpt["min checkpoint duration"]), labels),
			gauge(prefix+"checkpoint.max_duration_ms", asFloat(ckpt["max checkpoint duration"]), labels),
		)
	}

	// Log metrics
	if log, ok := wt["log"].(bson.M); ok {
		all = append(all,
			gauge(prefix+"log.size_bytes", asFloat(log["log bytes written"]), labels),
			counter(prefix+"log.bytes_written", asFloat(log["log bytes written"]), labels),
			counter(prefix+"log.records_written", asFloat(log["log records written"]), labels),
			counter(prefix+"log.syncs", asFloat(log["log syncs"]), labels),
			counter(prefix+"log.sync_dir", asFloat(log["log sync directory"]), labels),
			counter(prefix+"log.flushes", asFloat(log["log flushes"]), labels),
			gauge(prefix+"log.max_size_bytes", asFloat(log["log max file size"]), labels),
		)
	}

	// Block manager metrics
	if bm, ok := wt["block-manager"].(bson.M); ok {
		all = append(all,
			counter(prefix+"block_manager.bytes_read", asFloat(bm["bytes read"]), labels),
			counter(prefix+"block_manager.bytes_written", asFloat(bm["bytes written"]), labels),
			counter(prefix+"block_manager.blocks_read", asFloat(bm["blocks read"]), labels),
			counter(prefix+"block_manager.blocks_written", asFloat(bm["blocks written"]), labels),
		)
	}

	return all, nil
}
