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

// collectServices gathers Service and Endpoints metrics.
func collectServices(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []ServiceState, error) {
	svcList, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	// Pre-fetch endpoints
	epList, _ := cs.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	epMap := make(map[string]int) // namespace/name → address count
	if epList != nil {
		for i := range epList.Items {
			ep := &epList.Items[i]
			key := ep.Namespace + "/" + ep.Name
			count := 0
			for _, subset := range ep.Subsets {
				count += len(subset.Addresses)
			}
			epMap[key] = count
		}
	}

	// Aggregate service counts per namespace+type
	svcCounts := make(map[string]map[string]int) // namespace → type → count

	var metrics []collector.Metric
	var states []ServiceState

	for i := range svcList.Items {
		svc := &svcList.Items[i]

		if !cfg.shouldCollectNamespace(svc.Namespace) {
			continue
		}

		svcType := string(svc.Spec.Type)
		key := svc.Namespace + "/" + svc.Name
		endpointCount := epMap[key]

		// Aggregate
		if svcCounts[svc.Namespace] == nil {
			svcCounts[svc.Namespace] = make(map[string]int)
		}
		svcCounts[svc.Namespace][svcType]++

		// Per-service endpoint count
		epLabels := map[string]string{
			"cluster":   cluster,
			"namespace": svc.Namespace,
			"service":   svc.Name,
		}
		metrics = append(metrics,
			collector.NewMetric("k8s.endpoint.count", float64(endpointCount), collector.MetricTypeGauge).
				WithLabels(epLabels).
				WithDescription("Number of ready endpoints for this service"),
		)

		states = append(states, ServiceState{
			Name:          svc.Name,
			Namespace:     svc.Namespace,
			Type:          svcType,
			ClusterIP:     svc.Spec.ClusterIP,
			EndpointCount: endpointCount,
		})
	}

	// Aggregate service count metrics
	for ns, types := range svcCounts {
		for svcType, count := range types {
			metrics = append(metrics,
				collector.NewMetric("k8s.service.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithLabel("type", svcType).
					WithDescription("Service count by namespace and type"),
			)
		}
	}

	return metrics, states, nil
}
