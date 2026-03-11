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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// parseCPU converts a resource.Quantity to millicores (int64).
func parseCPU(q resource.Quantity) int64 {
	return q.MilliValue()
}

// parseMemory converts a resource.Quantity to bytes (int64).
func parseMemory(q resource.Quantity) int64 {
	return q.Value()
}

// cpuToFloat converts millicores to cores as float64.
func cpuToFloat(millicores int64) float64 {
	return float64(millicores) / 1000.0
}

// nodeRoles extracts roles from a node's labels.
// Roles are defined by labels: node-role.kubernetes.io/<role>
func nodeRoles(node *corev1.Node) []string {
	var roles []string
	for key := range node.Labels {
		if strings.HasPrefix(key, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(key, "node-role.kubernetes.io/")
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		roles = append(roles, "worker")
	}
	return roles
}

// nodeReady returns whether the node is in Ready condition.
func nodeReady(node *corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// nodeConditions returns a map of condition name → bool for all node conditions.
func nodeConditions(node *corev1.Node) map[string]bool {
	conds := make(map[string]bool, len(node.Status.Conditions))
	for _, c := range node.Status.Conditions {
		conds[string(c.Type)] = c.Status == corev1.ConditionTrue
	}
	return conds
}

// containerStatus returns a human-readable status string for a container.
func containerStatus(cs corev1.ContainerStatus) string {
	if cs.State.Running != nil {
		return "running"
	}
	if cs.State.Waiting != nil {
		return "waiting"
	}
	if cs.State.Terminated != nil {
		return "terminated"
	}
	return "unknown"
}

// ownerRef returns the first owner reference kind and name.
func ownerRef(pod *corev1.Pod) (kind, name string) {
	if len(pod.OwnerReferences) > 0 {
		return pod.OwnerReferences[0].Kind, pod.OwnerReferences[0].Name
	}
	return "", ""
}

// boolToFloat converts a bool to 0.0 or 1.0 for gauge metrics.
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// phaseToFloat maps a pod phase to a numeric gauge value:
// Running=1, Succeeded=2, Pending=3, Failed=4, Unknown=5
func phaseToFloat(phase corev1.PodPhase) float64 {
	switch phase {
	case corev1.PodRunning:
		return 1
	case corev1.PodSucceeded:
		return 2
	case corev1.PodPending:
		return 3
	case corev1.PodFailed:
		return 4
	default:
		return 5
	}
}

// parseResourceQuantity parses a Kubernetes quantity string (e.g. "500m", "2Gi").
func parseResourceQuantity(s string) (resource.Quantity, error) {
	return resource.ParseQuantity(s)
}
