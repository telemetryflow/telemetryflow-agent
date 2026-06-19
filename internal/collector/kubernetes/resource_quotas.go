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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectResourceQuotas lists all ResourceQuota objects and emits hard/used metrics
// for each resource entry. If a resource appears in spec.hard but not in status.used,
// the used value is emitted as 0.
func (k *KubernetesCollector) collectResourceQuotas(ctx context.Context) ([]collector.Metric, error) {
	quotaList, err := k.clientset.CoreV1().ResourceQuotas(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var metrics []collector.Metric

	for i := range quotaList.Items {
		quota := &quotaList.Items[i]

		for resourceName, hardQty := range quota.Spec.Hard {
			resource := string(resourceName)

			hardLabels := map[string]string{
				"cluster":       k.cfg.ClusterName,
				"namespace":     quota.Namespace,
				"resourcequota": quota.Name,
				"resource":      resource,
				"type":          "hard",
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.resourcequota.hard", hardQty.AsApproximateFloat64(), collector.MetricTypeGauge).
					WithLabels(hardLabels).
					WithDescription("ResourceQuota hard limit"),
			)

			// Emit used value; default to 0 if absent from status.used
			usedValue := 0.0
			if usedQty, ok := quota.Status.Used[resourceName]; ok {
				usedValue = usedQty.AsApproximateFloat64()
			}

			usedLabels := map[string]string{
				"cluster":       k.cfg.ClusterName,
				"namespace":     quota.Namespace,
				"resourcequota": quota.Name,
				"resource":      resource,
				"type":          "used",
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.resourcequota.used", usedValue, collector.MetricTypeGauge).
					WithLabels(usedLabels).
					WithDescription("ResourceQuota used amount"),
			)
		}
	}

	return metrics, nil
}
