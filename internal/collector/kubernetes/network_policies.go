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
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectNetworkPolicies gathers Kubernetes NetworkPolicy resources.
func collectNetworkPolicies(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []NetworkPolicyState, error) {
	npList, err := cs.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []NetworkPolicyState
	nsCounts := make(map[string]int)

	for i := range npList.Items {
		np := &npList.Items[i]

		if !cfg.shouldCollectNamespace(np.Namespace) {
			continue
		}

		nsCounts[np.Namespace]++

		// Policy types
		var policyTypes []string
		for _, pt := range np.Spec.PolicyTypes {
			policyTypes = append(policyTypes, string(pt))
		}

		// Pod selector (which pods this policy applies to)
		podSelector := make(map[string]string)
		for k, v := range np.Spec.PodSelector.MatchLabels {
			podSelector[k] = v
		}

		// Ingress rules count
		ingressRuleCount := len(np.Spec.Ingress)

		// Egress rules count
		egressRuleCount := len(np.Spec.Egress)

		// Build ingress rules detail
		var ingressRules []NetworkPolicyRule
		for _, rule := range np.Spec.Ingress {
			var ports []NetworkPolicyPort
			for _, p := range rule.Ports {
				npp := NetworkPolicyPort{
					Protocol: "TCP",
				}
				if p.Protocol != nil {
					npp.Protocol = string(*p.Protocol)
				}
				if p.Port != nil {
					npp.Port = p.Port.String()
				}
				ports = append(ports, npp)
			}
			var fromPeers []NetworkPolicyPeer
			for _, from := range rule.From {
				peer := NetworkPolicyPeer{}
				if from.PodSelector != nil {
					peer.PodSelector = from.PodSelector.MatchLabels
				}
				if from.NamespaceSelector != nil {
					peer.NamespaceSelector = from.NamespaceSelector.MatchLabels
				}
				if from.IPBlock != nil {
					peer.IPBlock = &NetworkPolicyIPBlock{
						CIDR:   from.IPBlock.CIDR,
						Except: from.IPBlock.Except,
					}
				}
				fromPeers = append(fromPeers, peer)
			}
			ingressRules = append(ingressRules, NetworkPolicyRule{
				Ports: ports,
				Peers: fromPeers,
			})
		}

		// Build egress rules detail
		var egressRules []NetworkPolicyRule
		for _, rule := range np.Spec.Egress {
			var ports []NetworkPolicyPort
			for _, p := range rule.Ports {
				npp := NetworkPolicyPort{
					Protocol: "TCP",
				}
				if p.Protocol != nil {
					npp.Protocol = string(*p.Protocol)
				}
				if p.Port != nil {
					npp.Port = p.Port.String()
				}
				ports = append(ports, npp)
			}
			var toPeers []NetworkPolicyPeer
			for _, to := range rule.To {
				peer := NetworkPolicyPeer{}
				if to.PodSelector != nil {
					peer.PodSelector = to.PodSelector.MatchLabels
				}
				if to.NamespaceSelector != nil {
					peer.NamespaceSelector = to.NamespaceSelector.MatchLabels
				}
				if to.IPBlock != nil {
					peer.IPBlock = &NetworkPolicyIPBlock{
						CIDR:   to.IPBlock.CIDR,
						Except: to.IPBlock.Except,
					}
				}
				toPeers = append(toPeers, peer)
			}
			egressRules = append(egressRules, NetworkPolicyRule{
				Ports: ports,
				Peers: toPeers,
			})
		}

		states = append(states, NetworkPolicyState{
			Name:             np.Name,
			Namespace:        np.Namespace,
			PolicyTypes:      policyTypes,
			PodSelector:      podSelector,
			IngressRuleCount: ingressRuleCount,
			EgressRuleCount:  egressRuleCount,
			IngressRules:     ingressRules,
			EgressRules:      egressRules,
			Labels:           np.Labels,
			CreatedAt:        np.CreationTimestamp.UnixMilli(),
		})
	}

	// Metrics: network policy count per namespace
	for ns, count := range nsCounts {
		metrics = append(metrics,
			collector.NewMetric("k8s.networkpolicy.count", float64(count), collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", ns).
				WithDescription("NetworkPolicy count per namespace"),
		)
	}

	return metrics, states, nil
}
