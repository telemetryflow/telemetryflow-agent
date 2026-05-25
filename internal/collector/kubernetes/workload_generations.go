// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectWorkloadGenerations emits metadata_generation and observed_generation
// metrics for Deployments and StatefulSets.
//
// Deployments are sourced from lastState (already fetched by collectDeployments).
// StatefulSets are queried directly from the API because WorkloadState does not
// carry generation fields.
//
// Metrics emitted:
//
//	k8s.deployment.metadata_generation{cluster, namespace, deployment}   = metadata.generation
//	k8s.deployment.observed_generation{cluster, namespace, deployment}   = status.observedGeneration
//	k8s.statefulset.metadata_generation{cluster, namespace, statefulset} = metadata.generation
//	k8s.statefulset.observed_generation{cluster, namespace, statefulset} = status.observedGeneration
func (k *KubernetesCollector) collectWorkloadGenerations(ctx context.Context) ([]collector.Metric, error) {
	k.mu.RLock()
	state := k.lastState
	k.mu.RUnlock()

	var metrics []collector.Metric

	// --- Deployments (reuse lastState) ---
	if state != nil {
		for i := range state.Deployments {
			dep := &state.Deployments[i]

			labels := map[string]string{
				"cluster":    k.cfg.ClusterName,
				"namespace":  dep.Namespace,
				"deployment": dep.Name,
			}

			metrics = append(metrics,
				collector.NewMetric("k8s.deployment.metadata_generation", float64(dep.Generation), collector.MetricTypeGauge).
					WithLabels(labels).
					WithDescription("Deployment metadata generation"),
				collector.NewMetric("k8s.deployment.observed_generation", float64(dep.ObservedGeneration), collector.MetricTypeGauge).
					WithLabels(labels).
					WithDescription("Deployment observed generation"),
			)
		}
	}

	// --- StatefulSets (query API — WorkloadState lacks generation fields) ---
	stsList, err := k.clientset.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: k.cfg.LabelSelector,
	})
	if err != nil {
		return metrics, err
	}

	for i := range stsList.Items {
		sts := &stsList.Items[i]

		if !k.cfg.shouldCollectNamespace(sts.Namespace) {
			continue
		}

		labels := map[string]string{
			"cluster":     k.cfg.ClusterName,
			"namespace":   sts.Namespace,
			"statefulset": sts.Name,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.statefulset.metadata_generation", float64(sts.Generation), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("StatefulSet metadata generation"),
			collector.NewMetric("k8s.statefulset.observed_generation", float64(sts.Status.ObservedGeneration), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("StatefulSet observed generation"),
		)
	}

	return metrics, nil
}
