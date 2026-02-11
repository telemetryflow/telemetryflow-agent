package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectStorage gathers PersistentVolume and PersistentVolumeClaim metrics.
func collectStorage(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []PVState, []PVCState, error) {
	var metrics []collector.Metric
	var pvStates []PVState
	var pvcStates []PVCState

	// --- PersistentVolumes (cluster-scoped) ---
	pvList, err := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, err
	}

	for i := range pvList.Items {
		pv := &pvList.Items[i]

		storageClass := pv.Spec.StorageClassName
		capacity := parseMemory(*pv.Spec.Capacity.Storage())
		phase := string(pv.Status.Phase)

		labels := map[string]string{
			"cluster":       cluster,
			"pv":            pv.Name,
			"storage_class": storageClass,
			"phase":         phase,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.pv.capacity_bytes", float64(capacity), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("PersistentVolume capacity in bytes"),
		)

		pvStates = append(pvStates, PVState{
			Name:         pv.Name,
			StorageClass: storageClass,
			Capacity:     capacity,
			Phase:        phase,
		})
	}

	// --- PersistentVolumeClaims (namespaced) ---
	pvcList, err := cs.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return metrics, pvStates, nil, err
	}

	for i := range pvcList.Items {
		pvc := &pvcList.Items[i]

		if !cfg.shouldCollectNamespace(pvc.Namespace) {
			continue
		}

		storageClass := ""
		if pvc.Spec.StorageClassName != nil {
			storageClass = *pvc.Spec.StorageClassName
		}
		phase := string(pvc.Status.Phase)

		// Use actual allocated capacity from status, fallback to requested
		var capacity int64
		if storage, ok := pvc.Status.Capacity["storage"]; ok {
			capacity = parseMemory(storage)
		} else if req, ok := pvc.Spec.Resources.Requests["storage"]; ok {
			capacity = parseMemory(req)
		}

		labels := map[string]string{
			"cluster":       cluster,
			"namespace":     pvc.Namespace,
			"pvc":           pvc.Name,
			"storage_class": storageClass,
			"phase":         phase,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.pvc.capacity_bytes", float64(capacity), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("PersistentVolumeClaim capacity in bytes"),
		)

		pvcStates = append(pvcStates, PVCState{
			Name:         pvc.Name,
			Namespace:    pvc.Namespace,
			StorageClass: storageClass,
			Capacity:     capacity,
			Phase:        phase,
		})
	}

	return metrics, pvStates, pvcStates, nil
}
