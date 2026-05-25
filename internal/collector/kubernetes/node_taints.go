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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectNodeTaints emits k8s.node.taint metrics for every taint on every node.
// It reuses the node list from k.lastState (populated by collectNodes) to avoid
// an extra API call. Nodes with no taints emit no metrics.
//
// Metric: k8s.node.taint{cluster, node, key, value, effect} = 1
//   - One metric per taint; value label is the taint value string or "" if unset.
//   - Untainted nodes produce no output (no zero-value placeholder).
func (k *KubernetesCollector) collectNodeTaints(_ context.Context) ([]collector.Metric, error) {
	k.mu.RLock()
	state := k.lastState
	k.mu.RUnlock()

	if state == nil || len(state.Nodes) == 0 {
		return nil, nil
	}

	var metrics []collector.Metric

	for i := range state.Nodes {
		node := &state.Nodes[i]

		for _, taint := range node.Taints {
			metrics = append(metrics,
				collector.NewMetric("k8s.node.taint", 1.0, collector.MetricTypeGauge).
					WithLabel("cluster", k.cfg.ClusterName).
					WithLabel("node", node.Name).
					WithLabel("key", taint.Key).
					WithLabel("value", taint.Value).
					WithLabel("effect", taint.Effect).
					WithDescription("Node taint (1 = taint present)"),
			)
		}
	}

	return metrics, nil
}
