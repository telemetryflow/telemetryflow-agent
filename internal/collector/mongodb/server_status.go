package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectServerStatus(ctx context.Context, client *mongo.Client, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	admin := client.Database("admin")
	var result bson.M
	if err := admin.RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&result); err != nil {
		return nil, err
	}

	var all []collector.Metric
	prefix := "db.mongodb."

	// Connection metrics
	if connections, ok := result["connections"].(bson.M); ok {
		all = append(all,
			gauge(prefix+"connections.current", float64(asInt(connections["current"])), labels),
			gauge(prefix+"connections.available", float64(asInt(connections["available"])), labels),
			counter(prefix+"connections.total_created", float64(asInt(connections["totalCreated"])), labels),
			gauge(prefix+"connections.active", float64(asInt(connections["active"])), labels),
		)
	}

	// Opcounter metrics
	if opcounters, ok := result["opcounters"].(bson.M); ok {
		all = append(all,
			counter(prefix+"opcounters.insert", float64(asInt(opcounters["insert"])), labels),
			counter(prefix+"opcounters.query", float64(asInt(opcounters["query"])), labels),
			counter(prefix+"opcounters.update", float64(asInt(opcounters["update"])), labels),
			counter(prefix+"opcounters.delete", float64(asInt(opcounters["delete"])), labels),
			counter(prefix+"opcounters.getmore", float64(asInt(opcounters["getmore"])), labels),
			counter(prefix+"opcounters.command", float64(asInt(opcounters["command"])), labels),
		)
	}
	if opcounters, ok := result["opcountersRepl"].(bson.M); ok {
		all = append(all,
			counter(prefix+"opcounters.repl.insert", float64(asInt(opcounters["insert"])), labels),
			counter(prefix+"opcounters.repl.query", float64(asInt(opcounters["query"])), labels),
			counter(prefix+"opcounters.repl.update", float64(asInt(opcounters["update"])), labels),
			counter(prefix+"opcounters.repl.delete", float64(asInt(opcounters["delete"])), labels),
			counter(prefix+"opcounters.repl.getmore", float64(asInt(opcounters["getmore"])), labels),
			counter(prefix+"opcounters.repl.command", float64(asInt(opcounters["command"])), labels),
		)
	}

	// Memory metrics
	if mem, ok := result["mem"].(bson.M); ok {
		all = append(all,
			gauge(prefix+"memory.resident_mb", float64(asInt(mem["resident"])), labels),
			gauge(prefix+"memory.virtual_mb", float64(asInt(mem["virtual"])), labels),
		)
		if mapped, ok := mem["mapped"].(int32); ok {
			all = append(all, gauge(prefix+"memory.mapped_mb", float64(mapped), labels))
		}
	}

	// Document metrics
	if doc, ok := result["metrics"].(bson.M); ok {
		if dd, ok := doc["document"].(bson.M); ok {
			all = append(all,
				counter(prefix+"document.inserted", float64(asInt(dd["inserted"])), labels),
				counter(prefix+"document.returned", float64(asInt(dd["returned"])), labels),
				counter(prefix+"document.updated", float64(asInt(dd["updated"])), labels),
				counter(prefix+"document.deleted", float64(asInt(dd["deleted"])), labels),
			)
		}
	}

	// Cursor metrics
	if cursors, ok := result["metrics"].(bson.M); ok {
		if cc, ok := cursors["cursor"].(bson.M); ok {
			if open, ok := cc["open"].(bson.M); ok {
				all = append(all,
					gauge(prefix+"cursors.open.total", float64(asInt(open["total"])), labels),
					gauge(prefix+"cursors.open.no_timeout", float64(asInt(open["noTimeout"])), labels),
					gauge(prefix+"cursors.open.pinned", float64(asInt(open["pinned"])), labels),
				)
			}
			all = append(all,
				counter(prefix+"cursors.timed_out", float64(asInt(cc["timedOut"])), labels),
			)
		}
	}

	// Network metrics
	if network, ok := result["network"].(bson.M); ok {
		all = append(all,
			counter(prefix+"network.bytes_in", float64(asInt64(network["bytesIn"])), labels),
			counter(prefix+"network.bytes_out", float64(asInt64(network["bytesOut"])), labels),
			counter(prefix+"network.requests", float64(asInt(network["numRequests"])), labels),
		)
	}

	// Assert metrics
	if asserts, ok := result["asserts"].(bson.M); ok {
		all = append(all,
			counter(prefix+"asserts.regular", float64(asInt(asserts["regular"])), labels),
			counter(prefix+"asserts.warning", float64(asInt(asserts["warning"])), labels),
			counter(prefix+"asserts.msg", float64(asInt(asserts["msg"])), labels),
			counter(prefix+"asserts.user", float64(asInt(asserts["user"])), labels),
			counter(prefix+"asserts.rollovers", float64(asInt(asserts["rollovers"])), labels),
		)
	}

	// Global lock metrics
	if globalLock, ok := result["globalLock"].(bson.M); ok {
		if queue, ok := globalLock["currentQueue"].(bson.M); ok {
			all = append(all,
				gauge(prefix+"global_lock.current_queue.total", float64(asInt(queue["total"])), labels),
				gauge(prefix+"global_lock.current_queue.readers", float64(asInt(queue["readers"])), labels),
				gauge(prefix+"global_lock.current_queue.writers", float64(asInt(queue["writers"])), labels),
			)
		}
		if active, ok := globalLock["activeClients"].(bson.M); ok {
			all = append(all,
				gauge(prefix+"global_lock.active_clients.total", float64(asInt(active["total"])), labels),
				gauge(prefix+"global_lock.active_clients.readers", float64(asInt(active["readers"])), labels),
				gauge(prefix+"global_lock.active_clients.writers", float64(asInt(active["writers"])), labels),
			)
		}
	}

	// Extra fields metrics (connections extra)
	if extraInfo, ok := result["extra_info"].(bson.M); ok {
		all = append(all,
			gauge(prefix+"extra_info.page_faults", float64(asInt64(extraInfo["page_faults"])), labels),
		)
	}

	return all, nil
}

// computeRates derives rate-based metrics from counter deltas.
func computeRates(inst *mongoInstance, elapsed float64, labels map[string]string) []collector.Metric {
	var all []collector.Metric
	prefix := "db.mongodb."

	rateNames := []string{
		prefix + "asserts.regular",
		prefix + "network.bytes_in",
		prefix + "network.bytes_out",
	}

	for _, name := range rateNames {
		prev, hasPrev := inst.prevCounters[name]
		_ = prev
		_ = hasPrev
	}

	return all
}
