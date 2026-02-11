package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectNamespaces gathers namespace metrics and state.
func collectNamespaces(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []NamespaceState, error) {
	nsList, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []NamespaceState

	for i := range nsList.Items {
		ns := &nsList.Items[i]

		if !cfg.shouldCollectNamespace(ns.Name) {
			continue
		}

		phase := string(ns.Status.Phase)
		labels := map[string]string{
			"cluster":   cluster,
			"namespace": ns.Name,
			"phase":     phase,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.namespace.phase", boolToFloat(phase == "Active"), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Namespace phase (1=Active, 0=Terminating)"),
		)

		states = append(states, NamespaceState{
			Name:   ns.Name,
			Phase:  phase,
			Labels: ns.Labels,
		})
	}

	return metrics, states, nil
}
