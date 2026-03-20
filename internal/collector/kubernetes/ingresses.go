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
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectIngresses gathers Ingress resources state and metrics.
func collectIngresses(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []IngressState, error) {
	ingList, err := cs.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []IngressState
	nsCounts := make(map[string]int)

	for i := range ingList.Items {
		ing := &ingList.Items[i]

		if !cfg.shouldCollectNamespace(ing.Namespace) {
			continue
		}

		nsCounts[ing.Namespace]++

		// Ingress class
		ingressClass := ""
		if ing.Spec.IngressClassName != nil {
			ingressClass = *ing.Spec.IngressClassName
		}
		// Fallback to annotation
		if ingressClass == "" {
			ingressClass = ing.Annotations["kubernetes.io/ingress.class"]
		}

		// Rules
		var rules []IngressRule
		for _, rule := range ing.Spec.Rules {
			var paths []IngressPath
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					ip := IngressPath{
						Path:     path.Path,
						PathType: string(*path.PathType),
					}
					if path.Backend.Service != nil {
						ip.ServiceName = path.Backend.Service.Name
						if path.Backend.Service.Port.Name != "" {
							ip.ServicePort = path.Backend.Service.Port.Name
						} else {
							ip.ServicePort = fmt.Sprintf("%d", path.Backend.Service.Port.Number)
						}
					}
					paths = append(paths, ip)
				}
			}
			rules = append(rules, IngressRule{
				Host:  rule.Host,
				Paths: paths,
			})
		}

		// TLS
		var tls []IngressTLS
		for _, t := range ing.Spec.TLS {
			tls = append(tls, IngressTLS{
				Hosts:      t.Hosts,
				SecretName: t.SecretName,
			})
		}

		// Load Balancer IPs
		var lbs []string
		for _, lbIng := range ing.Status.LoadBalancer.Ingress {
			if lbIng.IP != "" {
				lbs = append(lbs, lbIng.IP)
			} else if lbIng.Hostname != "" {
				lbs = append(lbs, lbIng.Hostname)
			}
		}

		// Per-ingress metrics
		ruleCount := len(rules)
		metrics = append(metrics,
			collector.NewMetric("k8s.ingress.rule_count", float64(ruleCount), collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", ing.Namespace).
				WithLabel("ingress", ing.Name).
				WithDescription("Number of rules in this ingress"),
		)

		if len(tls) > 0 {
			metrics = append(metrics,
				collector.NewMetric("k8s.ingress.tls_enabled", 1, collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ing.Namespace).
					WithLabel("ingress", ing.Name).
					WithDescription("Whether this ingress has TLS configured"),
			)
		}

		states = append(states, IngressState{
			Name:          ing.Name,
			Namespace:     ing.Namespace,
			IngressClass:  ingressClass,
			Rules:         rules,
			TLS:           tls,
			LoadBalancers: lbs,
			Labels:        ing.Labels,
			Annotations:   ing.Annotations,
			CreatedAt:     ing.CreationTimestamp.UnixMilli(),
		})
	}

	// Aggregate ingress count per namespace (already in resource_counts.go but we add here too for completeness)
	for ns, count := range nsCounts {
		metrics = append(metrics,
			collector.NewMetric("k8s.ingress.count", float64(count), collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", ns).
				WithDescription("Ingress count per namespace"),
		)
	}

	return metrics, states, nil
}
