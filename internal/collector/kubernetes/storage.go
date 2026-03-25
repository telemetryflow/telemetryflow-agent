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

	"go.uber.org/zap"

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

		// Reclaim policy
		reclaimPolicy := string(pv.Spec.PersistentVolumeReclaimPolicy)

		// Volume mode
		volumeMode := "Filesystem"
		if pv.Spec.VolumeMode != nil {
			volumeMode = string(*pv.Spec.VolumeMode)
		}

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
			collector.NewMetric("k8s.pv.phase", 1, collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("PersistentVolume phase (label carries phase: Available, Bound, Released, Failed)"),
			collector.NewMetric("k8s.pv.info", 1, collector.MetricTypeGauge).
				WithLabels(labels).
				WithLabel("reclaim_policy", reclaimPolicy).
				WithLabel("volume_mode", volumeMode).
				WithDescription("PersistentVolume info gauge (labels carry metadata)"),
		)

		// Access modes
		var accessModes []string
		for _, m := range pv.Spec.AccessModes {
			accessModes = append(accessModes, string(m))
		}

		// Claim ref
		var claimRef *PVClaimRef
		if pv.Spec.ClaimRef != nil {
			claimRef = &PVClaimRef{
				Name:      pv.Spec.ClaimRef.Name,
				Namespace: pv.Spec.ClaimRef.Namespace,
			}
		}

		pvs := PVState{
			Name:          pv.Name,
			StorageClass:  storageClass,
			Capacity:      capacity,
			Phase:         phase,
			AccessModes:   accessModes,
			ReclaimPolicy: reclaimPolicy,
			VolumeMode:    volumeMode,
			ClaimRef:      claimRef,
			// Describe-level fields
			Labels:       pv.Labels,
			Annotations:  pv.Annotations,
			MountOptions: pv.Spec.MountOptions,
		}
		if pv.CreationTimestamp.Unix() > 0 {
			pvs.CreatedAt = pv.CreationTimestamp.UnixMilli()
		}
		pvStates = append(pvStates, pvs)
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

		pvcs := PVCState{
			Name:         pvc.Name,
			Namespace:    pvc.Namespace,
			StorageClass: storageClass,
			Capacity:     capacity,
			Phase:        phase,
			AccessModes:  pvcAccessModes,
			VolumeName:   pvc.Spec.VolumeName,
			VolumeMode:   pvcVolumeMode,
			Resources:    pvcResources,
			// Describe-level fields
			Labels:      pvc.Labels,
			Annotations: pvc.Annotations,
		}
		// PVC conditions
		for _, cond := range pvc.Status.Conditions {
			pvcs.Conditions = append(pvcs.Conditions, PVCConditionState{
				Type:    string(cond.Type),
				Status:  string(cond.Status),
				Reason:  cond.Reason,
				Message: cond.Message,
			})
		}
		if pvc.CreationTimestamp.Unix() > 0 {
			pvcs.CreatedAt = pvc.CreationTimestamp.UnixMilli()
		}
		pvcStates = append(pvcStates, pvcs)
	}

	return metrics, pvStates, pvcStates, nil
}

// pvcVolumeData holds per-PVC volume usage collected from Kubelet /stats/summary.
type pvcVolumeData struct {
	namespace      string
	pvcName        string
	usedBytes      *int64
	capacityBytes  *int64
	availableBytes *int64
	inodesUsed     *int64
	inodes         *int64
}

// collectVolumeStats gathers per-PVC volume usage metrics from Kubelet /stats/summary.
// This is the only source for live volume usage (used bytes, inodes) — the K8s API
// only provides capacity via PV/PVC specs, not actual usage.
// It also returns raw per-PVC data for building PV I/O stats via PVC→PV mapping.
func collectVolumeStats(
	ctx context.Context,
	fetcher KubeletProxyFunc,
	nodeNames []string,
	cfg Config,
	cluster string,
	logger *zap.Logger,
) ([]collector.Metric, []pvcVolumeData, error) {
	if fetcher == nil {
		return nil, nil, nil
	}

	var metrics []collector.Metric
	var pvcData []pvcVolumeData

	for _, nodeName := range nodeNames {
		summary, err := fetcher(ctx, nodeName)
		if err != nil {
			logger.Debug("Failed to fetch kubelet stats for volume stats",
				zap.String("node", nodeName), zap.Error(err))
			continue
		}

		for _, pod := range summary.Pods {
			ns := pod.PodRef.Namespace
			if !cfg.shouldCollectNamespace(ns) {
				continue
			}
			for _, vol := range pod.Volumes {
				if vol.PvcRef == nil {
					continue
				}
				labels := map[string]string{
					"cluster":   cluster,
					"namespace": ns,
					"pod":       pod.PodRef.Name,
					"pvc":       vol.PvcRef.Name,
					"volume":    vol.Name,
				}

				var pd pvcVolumeData
				pd.namespace = vol.PvcRef.Namespace
				if pd.namespace == "" {
					pd.namespace = ns
				}
				pd.pvcName = vol.PvcRef.Name

				if vol.UsedBytes != nil {
					v := int64(*vol.UsedBytes)
					pd.usedBytes = &v
					metrics = append(metrics,
						collector.NewMetric("k8s.volume.used_bytes", float64(*vol.UsedBytes), collector.MetricTypeGauge).
							WithLabels(labels).WithUnit("bytes").
							WithDescription("Volume used bytes from Kubelet summary"),
					)
				}
				if vol.InodesUsed != nil {
					v := int64(*vol.InodesUsed)
					pd.inodesUsed = &v
					metrics = append(metrics,
						collector.NewMetric("k8s.volume.inodes_used", float64(*vol.InodesUsed), collector.MetricTypeGauge).
							WithLabels(labels).
							WithDescription("Volume inodes used from Kubelet summary"),
					)
				}
				if vol.CapacityBytes != nil {
					v := int64(*vol.CapacityBytes)
					pd.capacityBytes = &v
					metrics = append(metrics,
						collector.NewMetric("k8s.volume.capacity_bytes", float64(*vol.CapacityBytes), collector.MetricTypeGauge).
							WithLabels(labels).WithUnit("bytes").
							WithDescription("Volume capacity bytes from Kubelet summary"),
					)
				}
				if vol.AvailableBytes != nil {
					v := int64(*vol.AvailableBytes)
					pd.availableBytes = &v
				}
				if vol.Inodes != nil {
					v := int64(*vol.Inodes)
					pd.inodes = &v
				}

				pvcData = append(pvcData, pd)
			}
		}
	}

	return metrics, pvcData, nil
}

// buildPVIOStats maps PVC volume usage data to PV names using PVState.ClaimRef.
// This bridges the gap between Kubelet (which reports by PVC) and the platform
// (which queries by PV name).
func buildPVIOStats(pvStates []PVState, pvcData []pvcVolumeData) []PVIOStats {
	// Build PVC key (namespace/name) → pvcVolumeData lookup.
	// If multiple pods mount the same PVC, take the first non-nil values.
	pvcMap := make(map[string]*pvcVolumeData)
	for i := range pvcData {
		key := pvcData[i].namespace + "/" + pvcData[i].pvcName
		if existing, ok := pvcMap[key]; ok {
			// Merge: prefer non-nil
			if existing.usedBytes == nil && pvcData[i].usedBytes != nil {
				existing.usedBytes = pvcData[i].usedBytes
			}
			if existing.capacityBytes == nil && pvcData[i].capacityBytes != nil {
				existing.capacityBytes = pvcData[i].capacityBytes
			}
			if existing.availableBytes == nil && pvcData[i].availableBytes != nil {
				existing.availableBytes = pvcData[i].availableBytes
			}
			if existing.inodesUsed == nil && pvcData[i].inodesUsed != nil {
				existing.inodesUsed = pvcData[i].inodesUsed
			}
			if existing.inodes == nil && pvcData[i].inodes != nil {
				existing.inodes = pvcData[i].inodes
			}
		} else {
			copy := pvcData[i]
			pvcMap[key] = &copy
		}
	}

	var result []PVIOStats
	for _, pv := range pvStates {
		if pv.ClaimRef == nil {
			continue
		}
		key := pv.ClaimRef.Namespace + "/" + pv.ClaimRef.Name
		pd, ok := pvcMap[key]
		if !ok {
			continue
		}
		stat := PVIOStats{PVName: pv.Name, Namespace: pv.ClaimRef.Namespace}
		stat.UsedBytes = pd.usedBytes
		stat.CapacityBytes = pd.capacityBytes
		stat.AvailableBytes = pd.availableBytes
		stat.InodesUsed = pd.inodesUsed
		stat.Inodes = pd.inodes
		result = append(result, stat)
	}
	return result
}
