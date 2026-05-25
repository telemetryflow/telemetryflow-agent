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
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// errMetricsServerUnavailable is returned when the metrics.k8s.io API returns
// no data, signalling that the kubelet fallback path should be used.
var errMetricsServerUnavailable = errors.New("metrics-server returned no data")

const (
	// metricK8sMetricsSource is the self-observability gauge name indicating
	// which data source is currently providing usage metrics.
	metricK8sMetricsSource = "tfo_k8s_metrics_source"

	// sourceMetricsAPI indicates metrics were fetched from metrics.k8s.io.
	sourceMetricsAPI = "metrics_api"

	// sourceKubeletFallback indicates metrics were fetched directly from Kubelet.
	sourceKubeletFallback = "kubelet_fallback"

	// sourceUnavailable indicates no usage metrics source is available.
	sourceUnavailable = "unavailable"
)

// k8sMetricsSourceGauge tracks which data source is providing usage metrics.
// Labels: source (metrics_api | kubelet_fallback | unavailable)
var k8sMetricsSourceGauge = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: metricK8sMetricsSource,
		Help: "Indicates the current data source for Kubernetes usage metrics (1 = active source).",
	},
	[]string{"source"},
)

func init() {
	prometheus.MustRegister(k8sMetricsSourceGauge)
}

// collectUsageMetricsWithFallback tries the metrics.k8s.io API first when
// cfg.MetricsAPI is true. On failure (or when MetricsAPI is false) it falls
// back to querying each node's Kubelet /stats/summary endpoint directly.
//
// The function emits the tfo_k8s_metrics_source gauge to indicate which path
// was used, and adds a metrics_source="kubelet" label to all metrics produced
// via the fallback path.
func collectUsageMetricsWithFallback(ctx context.Context, k *KubernetesCollector) ([]collector.Metric, error) {
	if k.cfg.MetricsAPI && k.metricsClient != nil {
		metrics, err := tryMetricsAPI(ctx, k)
		if err == nil {
			k8sMetricsSourceGauge.WithLabelValues(sourceMetricsAPI).Set(1)
			return metrics, nil
		}
		k.logger.Warn("metrics-server unavailable, falling back to kubelet", zap.Error(err))
	}

	// Fallback: collect directly from each node's Kubelet.
	metrics, err := collectFromKubelet(ctx, k)
	if err != nil {
		k8sMetricsSourceGauge.WithLabelValues(sourceUnavailable).Set(1)
		return nil, err
	}

	k8sMetricsSourceGauge.WithLabelValues(sourceKubeletFallback).Set(1)
	return metrics, nil
}

// tryMetricsAPI fetches node and pod usage metrics from the metrics.k8s.io API.
// Returns an error if the API is unavailable or returns no data.
func tryMetricsAPI(ctx context.Context, k *KubernetesCollector) ([]collector.Metric, error) {
	cluster := k.cfg.ClusterName

	nodeMetricsMap := fetchNodeMetrics(ctx, k.metricsClient, k.logger)
	if len(nodeMetricsMap) == 0 {
		// fetchNodeMetrics swallows errors; treat empty result as unavailable.
		return nil, errMetricsServerUnavailable
	}

	var metrics []collector.Metric

	// Node-level usage metrics.
	for nodeName, nm := range nodeMetricsMap {
		labels := map[string]string{
			"cluster": cluster,
			"node":    nodeName,
		}
		metrics = append(metrics,
			collector.NewMetric("k8s.node.cpu.usage", nm.cpuCores, collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("{cores}").
				WithDescription("Node CPU usage from metrics-server"),
			collector.NewMetric("k8s.node.memory.usage", float64(nm.memoryBytes), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("By").
				WithDescription("Node memory usage from metrics-server"),
		)
	}

	// Pod/container-level usage metrics.
	podMetricsList, err := k.metricsClient.MetricsV1beta1().PodMetricses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, pm := range podMetricsList.Items {
		for _, c := range pm.Containers {
			labels := map[string]string{
				"cluster":   cluster,
				"namespace": pm.Namespace,
				"pod":       pm.Name,
				"container": c.Name,
			}
			cpuCores := float64(c.Usage.Cpu().MilliValue()) / 1000.0
			memBytes := float64(c.Usage.Memory().Value())
			metrics = append(metrics,
				collector.NewMetric("k8s.pod.container.cpu_usage", cpuCores, collector.MetricTypeGauge).
					WithLabels(labels).WithUnit("{cores}").
					WithDescription("Container CPU usage from metrics-server"),
				collector.NewMetric("k8s.pod.container.memory_usage", memBytes, collector.MetricTypeGauge).
					WithLabels(labels).WithUnit("By").
					WithDescription("Container memory usage from metrics-server"),
			)
		}
	}

	return metrics, nil
}

// collectFromKubelet fetches usage metrics directly from each node's Kubelet
// /stats/summary endpoint and converts them to collector.Metric values.
// All produced metrics carry a metrics_source="kubelet" label.
func collectFromKubelet(ctx context.Context, k *KubernetesCollector) ([]collector.Metric, error) {
	// Prefer the already-collected node list from lastState; fall back to API.
	var nodes []NodeState
	k.mu.RLock()
	if k.lastState != nil {
		nodes = k.lastState.Nodes
	}
	k.mu.RUnlock()

	if len(nodes) == 0 {
		nodeList, err := k.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, n := range nodeList.Items {
			var internalIP string
			for _, addr := range n.Status.Addresses {
				if addr.Type == "InternalIP" {
					internalIP = addr.Address
					break
				}
			}
			nodes = append(nodes, NodeState{Name: n.Name, InternalIP: internalIP})
		}
	}

	fetcher, err := NewKubeletHTTPFetcher(k.cfg.KubeletInsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	cluster := k.cfg.ClusterName
	var metrics []collector.Metric

	for _, node := range nodes {
		if node.InternalIP == "" {
			k.logger.Warn("Node has no internal IP, skipping kubelet fallback",
				zap.String("node", node.Name))
			continue
		}

		summary, err := fetcher.FetchNodeStats(ctx, node.InternalIP)
		if err != nil {
			k.logger.Warn("Kubelet /stats/summary unavailable for node",
				zap.String("node", node.Name),
				zap.Error(err))
			continue
		}

		nodeMetrics := convertKubeletSummary(summary, cluster, node.Name)
		metrics = append(metrics, nodeMetrics...)
	}

	return metrics, nil
}

// convertKubeletSummary converts a KubeletDirectSummary into collector.Metric
// values using the canonical metric names. All metrics include a
// metrics_source="kubelet" label to identify the fallback data path.
func convertKubeletSummary(summary *KubeletDirectSummary, cluster, nodeName string) []collector.Metric {
	const metricsSourceLabel = "kubelet"

	var metrics []collector.Metric

	// Node-level CPU and memory.
	nodeLabels := map[string]string{
		"cluster":        cluster,
		"node":           nodeName,
		"metrics_source": metricsSourceLabel,
	}

	if summary.Node.CPU != nil && summary.Node.CPU.UsageNanoCores != nil {
		cpuCores := float64(*summary.Node.CPU.UsageNanoCores) / 1e9
		metrics = append(metrics,
			collector.NewMetric("k8s.node.cpu.usage", cpuCores, collector.MetricTypeGauge).
				WithLabels(nodeLabels).WithUnit("{cores}").
				WithDescription("Node CPU usage from Kubelet /stats/summary"),
		)
	}

	if summary.Node.Memory != nil && summary.Node.Memory.WorkingSetBytes != nil {
		memBytes := float64(*summary.Node.Memory.WorkingSetBytes)
		metrics = append(metrics,
			collector.NewMetric("k8s.node.memory.usage", memBytes, collector.MetricTypeGauge).
				WithLabels(nodeLabels).WithUnit("By").
				WithDescription("Node memory working set from Kubelet /stats/summary"),
		)
	}

	// Per-pod container metrics.
	for _, pod := range summary.Pods {
		for _, c := range pod.Containers {
			containerLabels := map[string]string{
				"cluster":        cluster,
				"namespace":      pod.PodRef.Namespace,
				"pod":            pod.PodRef.Name,
				"container":      c.Name,
				"metrics_source": metricsSourceLabel,
			}

			if c.CPU != nil && c.CPU.UsageNanoCores != nil {
				cpuCores := float64(*c.CPU.UsageNanoCores) / 1e9
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.cpu_usage", cpuCores, collector.MetricTypeGauge).
						WithLabels(containerLabels).WithUnit("{cores}").
						WithDescription("Container CPU usage from Kubelet /stats/summary"),
				)
			}

			if c.Memory != nil && c.Memory.WorkingSetBytes != nil {
				memBytes := float64(*c.Memory.WorkingSetBytes)
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.memory_usage", memBytes, collector.MetricTypeGauge).
						WithLabels(containerLabels).WithUnit("By").
						WithDescription("Container memory working set from Kubelet /stats/summary"),
				)
			}
		}
	}

	return metrics
}
