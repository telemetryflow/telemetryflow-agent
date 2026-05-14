package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectCollStats(ctx context.Context, client *mongo.Client, inst *mongoInstance, baseLabels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric
	prefix := "db.mongodb."

	// Discover databases
	dbs, err := discoverDatabases(ctx, client, inst)
	if err != nil {
		return nil, err
	}

	for _, dbName := range dbs {
		db := client.Database(dbName)
		dbLabels := copyLabels(baseLabels)
		dbLabels["database"] = dbName

		// dbStats
		var dbStats bson.M
		if err := db.RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&dbStats); err == nil {
			all = append(all,
				gauge(prefix+"database.document_count", asFloat(dbStats["objects"]), dbLabels),
				gauge(prefix+"database.data_size_bytes", asFloat(dbStats["dataSize"]), dbLabels),
				gauge(prefix+"database.storage_size_bytes", asFloat(dbStats["storageSize"]), dbLabels),
				gauge(prefix+"database.index_size_bytes", asFloat(dbStats["indexSize"]), dbLabels),
				gauge(prefix+"database.collection_count", asFloat(dbStats["collections"]), dbLabels),
				gauge(prefix+"database.index_count", asFloat(dbStats["indexes"]), dbLabels),
			)
		}

		// List collections
		collections, err := db.ListCollectionNames(ctx, bson.D{})
		if err != nil {
			continue
		}

		for _, collName := range collections {
			collLabels := copyLabels(dbLabels)
			collLabels["collection"] = collName

			var collStats bson.M
			if err := db.RunCommand(ctx, bson.D{
				{Key: "collStats", Value: collName},
			}).Decode(&collStats); err != nil {
				continue
			}

			all = append(all,
				gauge(prefix+"collection.document_count", asFloat(collStats["count"]), collLabels),
				gauge(prefix+"collection.size_bytes", asFloat(collStats["size"]), collLabels),
				gauge(prefix+"collection.storage_size_bytes", asFloat(collStats["storageSize"]), collLabels),
				gauge(prefix+"collection.avg_document_size_bytes", asFloat(collStats["avgObjSize"]), collLabels),
				gauge(prefix+"collection.total_index_size_bytes", asFloat(collStats["totalIndexSize"]), collLabels),
			)

			if indexCount, ok := collStats["nindexes"].(int32); ok {
				all = append(all, gauge(prefix+"collection.index_count", float64(indexCount), collLabels))
			}

			// Capped collection info
			if capped, ok := collStats["capped"].(bool); ok && capped {
				all = append(all, gauge(prefix+"collection.capped", 1, collLabels))
				if maxDocs, ok := collStats["max"]; ok {
					all = append(all, gauge(prefix+"collection.capped_max_documents", asFloat(maxDocs), collLabels))
				}
				if maxSize, ok := collStats["maxSize"]; ok {
					all = append(all, gauge(prefix+"collection.capped_max_size_bytes", asFloat(maxSize), collLabels))
				}
			}

			// Per-index stats via $indexStats
			coll := db.Collection(collName)
			cursor, err := coll.Aggregate(ctx, bson.A{
				bson.D{{Key: "$indexStats", Value: bson.M{}}},
			})
			if err != nil {
				continue
			}
			var indexStats []bson.M
			if err := cursor.All(ctx, &indexStats); err != nil {
				continue
			}
			for _, idx := range indexStats {
				idxName := asString(idx["name"])
				idxLabels := copyLabels(collLabels)
				idxLabels["index"] = idxName

				if accesses, ok := idx["accesses"].(bson.M); ok {
					all = append(all,
						counter(prefix+"index.accesses", asFloat(accesses["ops"]), idxLabels),
					)
					if since, ok := accesses["since"].(bson.DateTime); ok {
						idxLabels["index_since"] = since.Time().Format("2006-01-02T15:04:05Z")
					}
				}
				if size, ok := idx["size"]; ok {
					all = append(all, gauge(prefix+"index.size_bytes", asFloat(size), idxLabels))
				}
			}
		}
	}

	return all, nil
}

func discoverDatabases(ctx context.Context, client *mongo.Client, inst *mongoInstance) ([]string, error) {
	// Use cached discovery if fresh (< collstats_interval)
	if len(inst.discoveredDBs) > 0 && !inst.discoveredAt.IsZero() {
		return inst.discoveredDBs, nil
	}

	var result bson.M
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "listDatabases", Value: 1}}).Decode(&result); err != nil {
		return nil, err
	}

	var dbs []string
	if databases, ok := result["databases"].(bson.A); ok {
		for _, d := range databases {
			if db, ok := d.(bson.M); ok {
				name := asString(db["name"])
				// Skip system databases
				if name == "admin" || name == "local" || name == "config" {
					continue
				}
				dbs = append(dbs, name)
			}
		}
	}

	inst.discoveredDBs = dbs
	inst.discoveredAt = inst.prevTime
	return dbs, nil
}
