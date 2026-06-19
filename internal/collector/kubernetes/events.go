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

// collectEvents gathers Kubernetes events and aggregates event count metrics.
func collectEvents(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []EventState, error) {
	eventList, err := cs.CoreV1().Events("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []EventState

	// Aggregate event counts: namespace → type(Normal/Warning) → count
	eventCounts := make(map[string]map[string]int)

	for i := range eventList.Items {
		ev := &eventList.Items[i]

		if !cfg.shouldCollectNamespace(ev.Namespace) {
			continue
		}

		var firstTS, lastTS int64
		if !ev.FirstTimestamp.IsZero() {
			firstTS = ev.FirstTimestamp.UnixMilli()
		}
		if !ev.LastTimestamp.IsZero() {
			lastTS = ev.LastTimestamp.UnixMilli()
		}

		source := ""
		if ev.Source.Component != "" {
			source = ev.Source.Component
		}

		states = append(states, EventState{
			Type:           ev.Type,
			Reason:         ev.Reason,
			Message:        ev.Message,
			Source:         source,
			InvolvedKind:   ev.InvolvedObject.Kind,
			InvolvedName:   ev.InvolvedObject.Name,
			Namespace:      ev.Namespace,
			Count:          ev.Count,
			FirstTimestamp: firstTS,
			LastTimestamp:  lastTS,
		})

		// Aggregate counts by namespace and type
		if eventCounts[ev.Namespace] == nil {
			eventCounts[ev.Namespace] = make(map[string]int)
		}
		eventCounts[ev.Namespace][ev.Type]++
	}

	// Emit aggregate event count metrics
	for ns, types := range eventCounts {
		for evType, count := range types {
			metrics = append(metrics,
				collector.NewMetric("k8s.event.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithLabel("type", evType).
					WithDescription("Kubernetes event count by namespace and type"),
			)
		}
	}

	return metrics, states, nil
}
