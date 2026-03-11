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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// standardPodConditions are the four standard Kubernetes pod condition types.
var standardPodConditions = []string{
	"Ready",
	"Initialized",
	"ContainersReady",
	"PodScheduled",
}

// collectPodConditions emits k8s.pod.condition metrics for all four standard
// pod conditions. It reuses the pod list from k.lastState (populated by
// collectPods) to avoid an extra API call. If lastState is nil or has no pods,
// it returns empty metrics without error.
//
// Metric: k8s.pod.condition{cluster, namespace, pod, condition} = 1|0
//   - 1 when condition status is True
//   - 0 when condition status is False, Unknown, or absent
func (k *KubernetesCollector) collectPodConditions(_ context.Context) ([]collector.Metric, error) {
	k.mu.RLock()
	state := k.lastState
	k.mu.RUnlock()

	if state == nil || len(state.Pods) == 0 {
		return nil, nil
	}

	var metrics []collector.Metric

	for i := range state.Pods {
		pod := &state.Pods[i]

		for _, condition := range standardPodConditions {
			value := 0.0
			if pod.Conditions[condition] {
				value = 1.0
			}

			metrics = append(metrics,
				collector.NewMetric("k8s.pod.condition", value, collector.MetricTypeGauge).
					WithLabel("cluster", k.cfg.ClusterName).
					WithLabel("namespace", pod.Namespace).
					WithLabel("pod", pod.Name).
					WithLabel("condition", condition).
					WithDescription("Pod condition status (1=True, 0=False/Unknown/absent)"),
			)
		}
	}

	return metrics, nil
}
