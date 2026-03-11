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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectNamespaces gathers namespace metrics and state.
func collectNamespaces(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []NamespaceState, error) {
	nsList, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	// Pre-fetch ResourceQuotas for all namespaces
	rqMap := fetchResourceQuotas(ctx, cs, cfg)

	var metrics []collector.Metric
	var states []NamespaceState

	for i := range nsList.Items {
		ns := &nsList.Items[i]

		if !cfg.shouldCollectNamespace(ns.Name) {
			continue
		}

		phase := string(ns.Status.Phase)
		labels := map[string]string{
			"cluster":   cluster,
			"namespace": ns.Name,
			"phase":     phase,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.namespace.phase", boolToFloat(phase == "Active"), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Namespace phase (1=Active, 0=Terminating)"),
		)

		state := NamespaceState{
			Name:          ns.Name,
			Phase:         phase,
			Labels:        ns.Labels,
			ResourceQuota: rqMap[ns.Name],
		}

		states = append(states, state)
	}

	// Emit resource quota metrics
	for ns, rq := range rqMap {
		quotaLabels := map[string]string{
			"cluster":   cluster,
			"namespace": ns,
		}

		if rq.CPU != nil {
			cpuUsed := parseQuantityString(rq.CPU.Used)
			cpuHard := parseQuantityString(rq.CPU.Hard)
			metrics = append(metrics,
				collector.NewMetric("k8s.namespace.quota.cpu.used", cpuUsed, collector.MetricTypeGauge).
					WithLabels(quotaLabels).WithUnit("cores").
					WithDescription("CPU quota usage"),
				collector.NewMetric("k8s.namespace.quota.cpu.hard", cpuHard, collector.MetricTypeGauge).
					WithLabels(quotaLabels).WithUnit("cores").
					WithDescription("CPU quota hard limit"),
			)
		}

		if rq.Memory != nil {
			memUsed := parseQuantityStringBytes(rq.Memory.Used)
			memHard := parseQuantityStringBytes(rq.Memory.Hard)
			metrics = append(metrics,
				collector.NewMetric("k8s.namespace.quota.memory.used", memUsed, collector.MetricTypeGauge).
					WithLabels(quotaLabels).WithUnit("bytes").
					WithDescription("Memory quota usage"),
				collector.NewMetric("k8s.namespace.quota.memory.hard", memHard, collector.MetricTypeGauge).
					WithLabels(quotaLabels).WithUnit("bytes").
					WithDescription("Memory quota hard limit"),
			)
		}

		if rq.Pods != nil {
			podsUsed := parseQuantityStringValue(rq.Pods.Used)
			podsHard := parseQuantityStringValue(rq.Pods.Hard)
			metrics = append(metrics,
				collector.NewMetric("k8s.namespace.quota.pods.used", podsUsed, collector.MetricTypeGauge).
					WithLabels(quotaLabels).
					WithDescription("Pods quota usage"),
				collector.NewMetric("k8s.namespace.quota.pods.hard", podsHard, collector.MetricTypeGauge).
					WithLabels(quotaLabels).
					WithDescription("Pods quota hard limit"),
			)
		}
	}

	return metrics, states, nil
}

// fetchResourceQuotas retrieves ResourceQuotas and aggregates them by namespace.
func fetchResourceQuotas(ctx context.Context, cs kubernetes.Interface, cfg Config) map[string]*NamespaceResourceQuota {
	result := make(map[string]*NamespaceResourceQuota)

	rqList, err := cs.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result
	}

	for i := range rqList.Items {
		rq := &rqList.Items[i]
		if !cfg.shouldCollectNamespace(rq.Namespace) {
			continue
		}
		if result[rq.Namespace] == nil {
			result[rq.Namespace] = &NamespaceResourceQuota{}
		}
		nrq := result[rq.Namespace]

		// CPU (requests.cpu)
		if hard, ok := rq.Status.Hard[corev1.ResourceRequestsCPU]; ok {
			used := rq.Status.Used[corev1.ResourceRequestsCPU]
			nrq.CPU = &ResourceQuotaUsage{Used: used.String(), Hard: hard.String()}
		}

		// Memory (requests.memory)
		if hard, ok := rq.Status.Hard[corev1.ResourceRequestsMemory]; ok {
			used := rq.Status.Used[corev1.ResourceRequestsMemory]
			nrq.Memory = &ResourceQuotaUsage{Used: used.String(), Hard: hard.String()}
		}

		// Pods
		if hard, ok := rq.Status.Hard[corev1.ResourcePods]; ok {
			used := rq.Status.Used[corev1.ResourcePods]
			nrq.Pods = &ResourceQuotaUsage{Used: used.String(), Hard: hard.String()}
		}
	}

	return result
}

// parseQuantityString parses a Kubernetes quantity string to CPU cores as float64.
func parseQuantityString(s string) float64 {
	q, err := parseResourceQuantity(s)
	if err != nil {
		return 0
	}
	return float64(q.MilliValue()) / 1000.0
}

// parseQuantityStringBytes parses a Kubernetes quantity string to bytes as float64.
func parseQuantityStringBytes(s string) float64 {
	q, err := parseResourceQuantity(s)
	if err != nil {
		return 0
	}
	return float64(q.Value())
}

// parseQuantityStringValue parses a Kubernetes quantity string to a plain value as float64.
func parseQuantityStringValue(s string) float64 {
	q, err := parseResourceQuantity(s)
	if err != nil {
		return 0
	}
	return float64(q.Value())
}
