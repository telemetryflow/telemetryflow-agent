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
	"encoding/json"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// KubeletProxyFunc retrieves the Kubelet /stats/summary via the API server proxy for a given node name.
type KubeletProxyFunc func(ctx context.Context, nodeName string) (*KubeletSummary, error)

// collectNetwork fetches per-pod network stats from each node's Kubelet Summary
// API and aggregates them by namespace.
func collectNetwork(
	ctx context.Context,
	fetcher KubeletProxyFunc,
	nodeNames []string,
	cfg Config,
	cluster string,
	logger *zap.Logger,
) ([]collector.Metric, []NamespaceNetworkStats, error) {
	if fetcher == nil {
		return nil, nil, nil
	}

	nsRx := make(map[string]uint64)
	nsTx := make(map[string]uint64)
	nsRxErr := make(map[string]uint64)
	nsTxErr := make(map[string]uint64)

	for _, nodeName := range nodeNames {
		summary, err := fetcher(ctx, nodeName)
		if err != nil {
			logger.Debug("Failed to fetch kubelet stats",
				zap.String("node", nodeName), zap.Error(err))
			continue
		}

		for _, pod := range summary.Pods {
			ns := pod.PodRef.Namespace
			if !cfg.shouldCollectNamespace(ns) {
				continue
			}
			if pod.Network == nil {
				continue
			}
			for _, iface := range pod.Network.Interfaces {
				if iface.RxBytes != nil {
					nsRx[ns] += *iface.RxBytes
				}
				if iface.TxBytes != nil {
					nsTx[ns] += *iface.TxBytes
				}
				if iface.RxErrors != nil {
					nsRxErr[ns] += *iface.RxErrors
				}
				if iface.TxErrors != nil {
					nsTxErr[ns] += *iface.TxErrors
				}
			}
		}
	}

	var metrics []collector.Metric
	var states []NamespaceNetworkStats

	for ns := range nsRx {
		labels := map[string]string{
			"cluster":   cluster,
			"namespace": ns,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.namespace.network.receive_bytes", float64(nsRx[ns]), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("Network bytes received aggregated by namespace"),
			collector.NewMetric("k8s.namespace.network.transmit_bytes", float64(nsTx[ns]), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("Network bytes transmitted aggregated by namespace"),
		)

		states = append(states, NamespaceNetworkStats{
			Namespace: ns,
			RxBytes:   nsRx[ns],
			TxBytes:   nsTx[ns],
			RxErrors:  nsRxErr[ns],
			TxErrors:  nsTxErr[ns],
		})
	}

	return metrics, states, nil
}

// newKubeletStatsFetcher creates a real KubeletProxyFunc using the
// Kubernetes API server proxy to reach each node's kubelet /stats/summary.
func newKubeletStatsFetcher(cs kubernetes.Interface) KubeletProxyFunc {
	return func(ctx context.Context, nodeName string) (*KubeletSummary, error) {
		data, err := cs.CoreV1().RESTClient().Get().
			Resource("nodes").
			Name(nodeName).
			SubResource("proxy", "stats", "summary").
			DoRaw(ctx)
		if err != nil {
			return nil, err
		}

		var summary KubeletSummary
		if err := json.Unmarshal(data, &summary); err != nil {
			return nil, err
		}
		return &summary, nil
	}
}
