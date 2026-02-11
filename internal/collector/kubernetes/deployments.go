package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectDeployments gathers deployment metrics and state.
func collectDeployments(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []DeploymentState, error) {
	depList, err := cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []DeploymentState

	for i := range depList.Items {
		dep := &depList.Items[i]

		if !cfg.shouldCollectNamespace(dep.Namespace) {
			continue
		}

		labels := map[string]string{
			"cluster":    cluster,
			"namespace":  dep.Namespace,
			"deployment": dep.Name,
		}

		replicas := int32(0)
		if dep.Spec.Replicas != nil {
			replicas = *dep.Spec.Replicas
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.deployment.replicas", float64(replicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Desired replica count"),
			collector.NewMetric("k8s.deployment.replicas.ready", float64(dep.Status.ReadyReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Ready replica count"),
			collector.NewMetric("k8s.deployment.replicas.available", float64(dep.Status.AvailableReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Available replica count"),
			collector.NewMetric("k8s.deployment.replicas.unavailable", float64(dep.Status.UnavailableReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Unavailable replica count"),
		)

		// Condition metrics
		conditions := make(map[string]bool)
		for _, cond := range dep.Status.Conditions {
			condName := string(cond.Type)
			isTrue := cond.Status == "True"
			conditions[condName] = isTrue

			condLabels := map[string]string{
				"cluster":    cluster,
				"namespace":  dep.Namespace,
				"deployment": dep.Name,
				"condition":  condName,
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.deployment.condition", boolToFloat(isTrue), collector.MetricTypeGauge).
					WithLabels(condLabels).
					WithDescription("Deployment condition status"),
			)
		}

		states = append(states, DeploymentState{
			Name:                dep.Name,
			Namespace:           dep.Namespace,
			Replicas:            replicas,
			ReadyReplicas:       dep.Status.ReadyReplicas,
			AvailableReplicas:   dep.Status.AvailableReplicas,
			UnavailableReplicas: dep.Status.UnavailableReplicas,
			Labels:              dep.Labels,
			Conditions:          conditions,
		})
	}

	return metrics, states, nil
}
