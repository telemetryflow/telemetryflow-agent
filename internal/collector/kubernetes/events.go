package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectEvents gathers Kubernetes events and aggregates event count metrics.
func collectEvents(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []EventState, error) {
	eventList, err := cs.CoreV1().Events("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []EventState

	// Aggregate event counts: namespace → type(Normal/Warning) → count
	eventCounts := make(map[string]map[string]int)

	for i := range eventList.Items {
		ev := &eventList.Items[i]

		if !cfg.shouldCollectNamespace(ev.Namespace) {
			continue
		}

		var firstTS, lastTS int64
		if !ev.FirstTimestamp.IsZero() {
			firstTS = ev.FirstTimestamp.UnixMilli()
		}
		if !ev.LastTimestamp.IsZero() {
			lastTS = ev.LastTimestamp.UnixMilli()
		}

		source := ""
		if ev.Source.Component != "" {
			source = ev.Source.Component
		}

		states = append(states, EventState{
			Type:           ev.Type,
			Reason:         ev.Reason,
			Message:        ev.Message,
			Source:         source,
			InvolvedKind:   ev.InvolvedObject.Kind,
			InvolvedName:   ev.InvolvedObject.Name,
			Namespace:      ev.Namespace,
			Count:          ev.Count,
			FirstTimestamp: firstTS,
			LastTimestamp:  lastTS,
		})

		// Aggregate counts by namespace and type
		if eventCounts[ev.Namespace] == nil {
			eventCounts[ev.Namespace] = make(map[string]int)
		}
		eventCounts[ev.Namespace][ev.Type]++
	}

	// Emit aggregate event count metrics
	for ns, types := range eventCounts {
		for evType, count := range types {
			metrics = append(metrics,
				collector.NewMetric("k8s.event.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithLabel("type", evType).
					WithDescription("Kubernetes event count by namespace and type"),
			)
		}
	}

	return metrics, states, nil
}
