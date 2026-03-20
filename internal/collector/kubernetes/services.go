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

// collectServices gathers Service and Endpoints metrics and state.
func collectServices(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []ServiceState, []EndpointState, error) {
	svcList, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Pre-fetch endpoints
	epList, _ := cs.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	epCountMap := make(map[string]int)              // namespace/name → address count
	epStateMap := make(map[string][]EndpointSubset) // namespace/name → subsets
	var endpointStates []EndpointState

	if epList != nil {
		for i := range epList.Items {
			ep := &epList.Items[i]
			if !cfg.shouldCollectNamespace(ep.Namespace) {
				continue
			}
			key := ep.Namespace + "/" + ep.Name
			count := 0
			var subsets []EndpointSubset
			for _, subset := range ep.Subsets {
				count += len(subset.Addresses)

				var addresses []EndpointAddress
				for _, addr := range subset.Addresses {
					ea := EndpointAddress{IP: addr.IP}
					if addr.NodeName != nil {
						ea.NodeName = *addr.NodeName
					}
					if addr.TargetRef != nil {
						ea.TargetRef = addr.TargetRef.Name
					}
					addresses = append(addresses, ea)
				}

				var notReady []EndpointAddress
				for _, addr := range subset.NotReadyAddresses {
					ea := EndpointAddress{IP: addr.IP}
					if addr.NodeName != nil {
						ea.NodeName = *addr.NodeName
					}
					if addr.TargetRef != nil {
						ea.TargetRef = addr.TargetRef.Name
					}
					notReady = append(notReady, ea)
				}

				var ports []EndpointPort
				for _, p := range subset.Ports {
					ports = append(ports, EndpointPort{
						Name:     p.Name,
						Port:     p.Port,
						Protocol: string(p.Protocol),
					})
				}

				subsets = append(subsets, EndpointSubset{
					Addresses:         addresses,
					NotReadyAddresses: notReady,
					Ports:             ports,
				})
			}
			epCountMap[key] = count
			epStateMap[key] = subsets

			endpointStates = append(endpointStates, EndpointState{
				Name:      ep.Name,
				Namespace: ep.Namespace,
				Subsets:   subsets,
				CreatedAt: ep.CreationTimestamp.UnixMilli(),
			})
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
		endpointCount := epCountMap[key]

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

		// Build ports
		var ports []ServicePort
		for _, p := range svc.Spec.Ports {
			ports = append(ports, ServicePort{
				Name:       p.Name,
				Protocol:   string(p.Protocol),
				Port:       p.Port,
				TargetPort: p.TargetPort.String(),
				NodePort:   p.NodePort,
			})
		}

		// External IPs
		externalIPs := svc.Spec.ExternalIPs
		// Also check LoadBalancer ingress
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ing.IP != "" {
				externalIPs = append(externalIPs, ing.IP)
			} else if ing.Hostname != "" {
				externalIPs = append(externalIPs, ing.Hostname)
			}
		}

		states = append(states, ServiceState{
			Name:          svc.Name,
			Namespace:     svc.Namespace,
			Type:          svcType,
			ClusterIP:     svc.Spec.ClusterIP,
			ExternalIPs:   externalIPs,
			Ports:         ports,
			Selector:      svc.Spec.Selector,
			Labels:        svc.Labels,
			EndpointCount: endpointCount,
			CreatedAt:     svc.CreationTimestamp.UnixMilli(),
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

	// Endpoint count metric per namespace (total)
	nsEpCounts := make(map[string]int)
	for _, epState := range endpointStates {
		for _, sub := range epState.Subsets {
			nsEpCounts[epState.Namespace] += len(sub.Addresses)
		}
	}
	for ns, count := range nsEpCounts {
		metrics = append(metrics,
			collector.NewMetric("k8s.endpoint.total", float64(count), collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", ns).
				WithDescription("Total endpoint addresses per namespace"),
		)
	}

	return metrics, states, endpointStates, nil
}
