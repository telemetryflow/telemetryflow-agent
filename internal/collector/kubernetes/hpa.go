package kubernetes

import (
	"context"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectHPAs gathers HorizontalPodAutoscaler state and metrics.
// Covers: current/desired replicas, min/max bounds, scaling conditions.
func collectHPAs(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []HPAState, error) {
	hpaList, err := cs.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []HPAState

	for i := range hpaList.Items {
		hpa := &hpaList.Items[i]

		if !cfg.shouldCollectNamespace(hpa.Namespace) {
			continue
		}

		labels := map[string]string{
			"cluster":     cluster,
			"namespace":   hpa.Namespace,
			"hpa":         hpa.Name,
			"target_kind": hpa.Spec.ScaleTargetRef.Kind,
			"target_name": hpa.Spec.ScaleTargetRef.Name,
		}

		minReplicas := int32(1)
		if hpa.Spec.MinReplicas != nil {
			minReplicas = *hpa.Spec.MinReplicas
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.hpa.replicas.min", float64(minReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("HPA minimum replica count"),
			collector.NewMetric("k8s.hpa.replicas.max", float64(hpa.Spec.MaxReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("HPA maximum replica count"),
			collector.NewMetric("k8s.hpa.replicas.current", float64(hpa.Status.CurrentReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("HPA current replica count"),
			collector.NewMetric("k8s.hpa.replicas.desired", float64(hpa.Status.DesiredReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("HPA desired replica count"),
		)

		// Condition metrics (AbleToScale, ScalingActive, ScalingLimited)
		conditions := make(map[string]bool)
		for _, cond := range hpa.Status.Conditions {
			val := cond.Status == "True"
			conditions[string(cond.Type)] = val
			condLabels := map[string]string{
				"cluster":   cluster,
				"namespace": hpa.Namespace,
				"hpa":       hpa.Name,
				"condition": string(cond.Type),
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.hpa.condition", boolToFloat(val), collector.MetricTypeGauge).
					WithLabels(condLabels).
					WithDescription("HPA condition status"),
			)
		}

		states = append(states, HPAState{
			Name:            hpa.Name,
			Namespace:       hpa.Namespace,
			ScaleTargetKind: hpa.Spec.ScaleTargetRef.Kind,
			ScaleTargetName: hpa.Spec.ScaleTargetRef.Name,
			MinReplicas:     minReplicas,
			MaxReplicas:     hpa.Spec.MaxReplicas,
			CurrentReplicas: hpa.Status.CurrentReplicas,
			DesiredReplicas: hpa.Status.DesiredReplicas,
			Conditions:      conditions,
			Labels:          hpa.Labels,
		})
	}

	return metrics, states, nil
}

// hpaConditionStatus converts autoscalingv2 condition status to bool.
// kept as a compile-time reference to ensure the import is used.
var _ = autoscalingv2.HorizontalPodAutoscalerConditionType("")
