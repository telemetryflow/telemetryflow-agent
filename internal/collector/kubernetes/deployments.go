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
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectDeployments gathers deployment metrics and state.
func collectDeployments(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []DeploymentState, error) {
	depList, err := cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []DeploymentState

	for i := range depList.Items {
		dep := &depList.Items[i]

		if !cfg.shouldCollectNamespace(dep.Namespace) {
			continue
		}

		labels := map[string]string{
			"cluster":    cluster,
			"namespace":  dep.Namespace,
			"deployment": dep.Name,
		}

		replicas := int32(0)
		if dep.Spec.Replicas != nil {
			replicas = *dep.Spec.Replicas
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.deployment.replicas", float64(replicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Desired replica count"),
			collector.NewMetric("k8s.deployment.replicas.ready", float64(dep.Status.ReadyReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Ready replica count"),
			collector.NewMetric("k8s.deployment.replicas.available", float64(dep.Status.AvailableReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Available replica count"),
			collector.NewMetric("k8s.deployment.replicas.unavailable", float64(dep.Status.UnavailableReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Unavailable replica count"),
			collector.NewMetric("k8s.deployment.replicas.updated", float64(dep.Status.UpdatedReplicas), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Updated replica count"),
		)

		// Condition metrics
		conditions := make(map[string]bool)
		for _, cond := range dep.Status.Conditions {
			condName := string(cond.Type)
			isTrue := cond.Status == "True"
			conditions[condName] = isTrue

			condLabels := map[string]string{
				"cluster":    cluster,
				"namespace":  dep.Namespace,
				"deployment": dep.Name,
				"condition":  condName,
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.deployment.condition", boolToFloat(isTrue), collector.MetricTypeGauge).
					WithLabels(condLabels).
					WithDescription("Deployment condition status"),
			)
		}

		// Strategy
		var strategy *DeploymentStrategy
		if dep.Spec.Strategy.Type != "" {
			strategy = &DeploymentStrategy{
				Type: string(dep.Spec.Strategy.Type),
			}
			if dep.Spec.Strategy.RollingUpdate != nil {
				if dep.Spec.Strategy.RollingUpdate.MaxUnavailable != nil {
					strategy.MaxUnavailable = dep.Spec.Strategy.RollingUpdate.MaxUnavailable.String()
				}
				if dep.Spec.Strategy.RollingUpdate.MaxSurge != nil {
					strategy.MaxSurge = dep.Spec.Strategy.RollingUpdate.MaxSurge.String()
				}
			}
		}

		// Container summaries from pod template
		var containers []DeploymentContainer
		for _, c := range dep.Spec.Template.Spec.Containers {
			containers = append(containers, DeploymentContainer{
				Name:  c.Name,
				Image: c.Image,
			})
		}

		// Selector
		var selector map[string]string
		if dep.Spec.Selector != nil {
			selector = dep.Spec.Selector.MatchLabels
		}

		ds := DeploymentState{
			Name:                    dep.Name,
			Namespace:               dep.Namespace,
			Replicas:                replicas,
			ReadyReplicas:           dep.Status.ReadyReplicas,
			AvailableReplicas:       dep.Status.AvailableReplicas,
			UnavailableReplicas:     dep.Status.UnavailableReplicas,
			UpdatedReplicas:         dep.Status.UpdatedReplicas,
			Labels:                  dep.Labels,
			Annotations:             dep.Annotations,
			Conditions:              conditions,
			Strategy:                strategy,
			Containers:              containers,
			Selector:                selector,
			Generation:              dep.Generation,
			ObservedGeneration:      dep.Status.ObservedGeneration,
			MinReadySeconds:         dep.Spec.MinReadySeconds,
			RevisionHistoryLimit:    dep.Spec.RevisionHistoryLimit,
			ProgressDeadlineSeconds: dep.Spec.ProgressDeadlineSeconds,
		}
		if dep.CreationTimestamp.Unix() > 0 {
			ds.CreatedAt = dep.CreationTimestamp.UnixMilli()
		}
		states = append(states, ds)
	}

	return metrics, states, nil
}
