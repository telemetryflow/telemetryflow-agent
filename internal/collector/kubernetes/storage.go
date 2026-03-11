// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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

		// Access modes
		var accessModes []string
		for _, m := range pv.Spec.AccessModes {
			accessModes = append(accessModes, string(m))
		}

		// Reclaim policy
		reclaimPolicy := string(pv.Spec.PersistentVolumeReclaimPolicy)

		// Volume mode
		volumeMode := "Filesystem"
		if pv.Spec.VolumeMode != nil {
			volumeMode = string(*pv.Spec.VolumeMode)
		}

		// Claim ref
		var claimRef *PVClaimRef
		if pv.Spec.ClaimRef != nil {
			claimRef = &PVClaimRef{
				Name:      pv.Spec.ClaimRef.Name,
				Namespace: pv.Spec.ClaimRef.Namespace,
			}
		}

		pvStates = append(pvStates, PVState{
			Name:          pv.Name,
			StorageClass:  storageClass,
			Capacity:      capacity,
			Phase:         phase,
			AccessModes:   accessModes,
			ReclaimPolicy: reclaimPolicy,
			VolumeMode:    volumeMode,
			ClaimRef:      claimRef,
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

		// Access modes
		var pvcAccessModes []string
		for _, m := range pvc.Spec.AccessModes {
			pvcAccessModes = append(pvcAccessModes, string(m))
		}

		// Volume mode
		pvcVolumeMode := "Filesystem"
		if pvc.Spec.VolumeMode != nil {
			pvcVolumeMode = string(*pvc.Spec.VolumeMode)
		}

		// Resources
		var pvcResources *PVCResources
		if len(pvc.Spec.Resources.Requests) > 0 || len(pvc.Spec.Resources.Limits) > 0 {
			pvcResources = &PVCResources{}
			if len(pvc.Spec.Resources.Requests) > 0 {
				pvcResources.Requests = make(map[string]string)
				for k, v := range pvc.Spec.Resources.Requests {
					pvcResources.Requests[string(k)] = v.String()
				}
			}
			if len(pvc.Spec.Resources.Limits) > 0 {
				pvcResources.Limits = make(map[string]string)
				for k, v := range pvc.Spec.Resources.Limits {
					pvcResources.Limits[string(k)] = v.String()
				}
			}
		}

		pvcStates = append(pvcStates, PVCState{
			Name:         pvc.Name,
			Namespace:    pvc.Namespace,
			StorageClass: storageClass,
			Capacity:     capacity,
			Phase:        phase,
			AccessModes:  pvcAccessModes,
			VolumeName:   pvc.Spec.VolumeName,
			VolumeMode:   pvcVolumeMode,
			Resources:    pvcResources,
		})
	}

	return metrics, pvStates, pvcStates, nil
}
