package kubernetes

import (
	"context"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectPDBs gathers PodDisruptionBudget state and metrics.
// Covers: current healthy pods, desired healthy pods, disruptions allowed.
func collectPDBs(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []PDBState, error) {
	pdbList, err := cs.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []PDBState

	for i := range pdbList.Items {
		pdb := &pdbList.Items[i]

		if !cfg.shouldCollectNamespace(pdb.Namespace) {
			continue
		}

		labels := map[string]string{
			"cluster":   cluster,
			"namespace": pdb.Namespace,
			"pdb":       pdb.Name,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.pdb.pods.current_healthy", float64(pdb.Status.CurrentHealthy), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Number of pods that are currently healthy"),
			collector.NewMetric("k8s.pdb.pods.desired_healthy", float64(pdb.Status.DesiredHealthy), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Minimum desired number of healthy pods"),
			collector.NewMetric("k8s.pdb.pods.expected", float64(pdb.Status.ExpectedPods), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Total number of pods counted by this PDB"),
			collector.NewMetric("k8s.pdb.disruptions_allowed", float64(pdb.Status.DisruptionsAllowed), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Number of pod disruptions currently allowed"),
		)

		states = append(states, PDBState{
			Name:               pdb.Name,
			Namespace:          pdb.Namespace,
			CurrentHealthy:     pdb.Status.CurrentHealthy,
			DesiredHealthy:     pdb.Status.DesiredHealthy,
			ExpectedPods:       pdb.Status.ExpectedPods,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
			Labels:             pdb.Labels,
		})
	}

	return metrics, states, nil
}

// compile-time import anchor
var _ = policyv1.PodDisruptionBudget{}
