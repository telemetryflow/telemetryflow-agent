package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectCurrentOp executes db.currentOp({$all: true}) and emits operation metrics.
func collectCurrentOp(ctx context.Context, client *mongo.Client, labels map[string]string, _ *zap.Logger) ([]collector.Metric, error) {
	admin := client.Database("admin")
	var result bson.M
	if err := admin.RunCommand(ctx, bson.D{
		{Key: "currentOp", Value: true},
		{Key: "$all", Value: true},
	}).Decode(&result); err != nil {
		return nil, err
	}

	prefix := "db.mongodb.operations."
	var all []collector.Metric

	inProg, ok := result["inprog"].(bson.A)
	if !ok {
		return nil, nil
	}

	var activeCount, waitingForLock int
	var long1s, long10s, long60s int
	activeByType := map[string]int{}

	for _, op := range inProg {
		o, ok := op.(bson.M)
		if !ok {
			continue
		}

		active, _ := o["active"].(bool)
		if !active {
			continue
		}
		activeCount++

		if opType := asString(o["op"]); opType != "" {
			activeByType[opType]++
		}

		if wl, _ := o["waitingForLock"].(bool); wl {
			waitingForLock++
		}

		if micros, ok := o["microsecs_running"]; ok {
			secs := asFloat(micros) / 1e6
			if secs >= 1 {
				long1s++
			}
			if secs >= 10 {
				long10s++
			}
			if secs >= 60 {
				long60s++
			}
		}
	}

	all = append(all,
		gauge(prefix+"active", float64(activeCount), labels),
		gauge(prefix+"waiting_for_lock", float64(waitingForLock), labels),
		gauge(prefix+"running_longer_than_1s", float64(long1s), labels),
		gauge(prefix+"running_longer_than_10s", float64(long10s), labels),
		gauge(prefix+"running_longer_than_60s", float64(long60s), labels),
	)

	for opType, count := range activeByType {
		typeLabels := copyLabels(labels)
		typeLabels["operation"] = opType
		all = append(all, gauge(prefix+"active_by_type", float64(count), typeLabels))
	}

	return all, nil
}
