// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectLimitRanges lists all LimitRange objects and emits metrics for each
// constraint type (default, defaultRequest, max, min) per limit entry.
// Only emits a metric if the constraint map is non-nil and has an entry for the resource.
func (k *KubernetesCollector) collectLimitRanges(ctx context.Context) ([]collector.Metric, error) {
	limitRangeList, err := k.clientset.CoreV1().LimitRanges(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var metrics []collector.Metric

	for i := range limitRangeList.Items {
		lr := &limitRangeList.Items[i]

		for j := range lr.Spec.Limits {
			item := &lr.Spec.Limits[j]
			limitType := string(item.Type)

			type constraintEntry struct {
				metricName string
				constraint string
				list       corev1.ResourceList
			}

			constraints := []constraintEntry{
				{"k8s.limitrange.default", "default", item.Default},
				{"k8s.limitrange.default_request", "defaultRequest", item.DefaultRequest},
				{"k8s.limitrange.max", "max", item.Max},
				{"k8s.limitrange.min", "min", item.Min},
			}

			for _, c := range constraints {
				if c.list == nil {
					continue
				}
				for resourceName, qty := range c.list {
					labels := map[string]string{
						"cluster":    k.cfg.ClusterName,
						"namespace":  lr.Namespace,
						"limitrange": lr.Name,
						"resource":   string(resourceName),
						"type":       limitType,
						"constraint": c.constraint,
					}
					metrics = append(metrics,
						collector.NewMetric(c.metricName, qty.AsApproximateFloat64(), collector.MetricTypeGauge).
							WithLabels(labels).
							WithDescription("LimitRange constraint value"),
					)
				}
			}
		}
	}

	return metrics, nil
}
