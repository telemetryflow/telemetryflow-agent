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
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// CAdvisorProxyFunc fetches raw cAdvisor Prometheus metrics from a node via the
// API server proxy (/api/v1/nodes/{name}/proxy/metrics/cadvisor).
type CAdvisorProxyFunc func(ctx context.Context, nodeName string) ([]byte, error)

// newCAdvisorProxyFetcher creates a CAdvisorProxyFunc that reads cAdvisor
// Prometheus metrics through the Kubernetes API server node proxy.
func newCAdvisorProxyFetcher(cs kubernetes.Interface) CAdvisorProxyFunc {
	return func(ctx context.Context, nodeName string) ([]byte, error) {
		return cs.CoreV1().RESTClient().Get().
			Resource("nodes").
			Name(nodeName).
			SubResource("proxy", "metrics", "cadvisor").
			DoRaw(ctx)
	}
}

// containerThrottleKey identifies a container within a pod for throttle data.
type containerThrottleKey struct {
	namespace string
	pod       string
	container string
}

// fetchCPUThrottleMap queries each node's cAdvisor Prometheus endpoint via the
// API server proxy and extracts container_cpu_cfs_throttled_seconds_total values.
// Returns a map of namespace/pod → container → throttled seconds (cumulative counter).
func fetchCPUThrottleMap(
	ctx context.Context,
	podList *corev1.PodList,
	fetcher CAdvisorProxyFunc,
	logger *zap.Logger,
) map[string]map[string]float64 {
	result := make(map[string]map[string]float64)

	// Collect unique node names from the pod list.
	nodeSet := make(map[string]struct{})
	for i := range podList.Items {
		if n := podList.Items[i].Spec.NodeName; n != "" {
			nodeSet[n] = struct{}{}
		}
	}

	for nodeName := range nodeSet {
		data, err := fetcher(ctx, nodeName)
		if err != nil {
			logger.Debug("Failed to fetch cAdvisor metrics for CPU throttle",
				zap.String("node", nodeName), zap.Error(err))
			continue
		}

		throttles := parseCPUThrottleMetrics(data, logger)
		for key, seconds := range throttles {
			podKey := key.namespace + "/" + key.pod
			if result[podKey] == nil {
				result[podKey] = make(map[string]float64)
			}
			result[podKey][key.container] = seconds
		}
	}

	return result
}

// parseCPUThrottleMetrics parses Prometheus text-format cAdvisor metrics and
// extracts container_cpu_cfs_throttled_seconds_total values keyed by
// namespace/pod/container.
func parseCPUThrottleMetrics(data []byte, logger *zap.Logger) map[containerThrottleKey]float64 {
	result := make(map[containerThrottleKey]float64)

	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(data)))
	if err != nil {
		logger.Debug("Failed to parse cAdvisor Prometheus metrics", zap.Error(err))
		return result
	}

	family, ok := families["container_cpu_cfs_throttled_seconds_total"]
	if !ok || family == nil {
		return result
	}

	for _, m := range family.GetMetric() {
		namespace, pod, container := "", "", ""
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "namespace":
				namespace = lp.GetValue()
			case "pod":
				pod = lp.GetValue()
			case "container":
				container = lp.GetValue()
			}
		}

		// Skip infrastructure containers (POD/pause) and empty identifiers
		if namespace == "" || pod == "" || container == "" || container == "POD" {
			continue
		}

		var value float64
		switch family.GetType() {
		case dto.MetricType_COUNTER:
			if c := m.GetCounter(); c != nil {
				value = c.GetValue()
			}
		case dto.MetricType_UNTYPED:
			if u := m.GetUntyped(); u != nil {
				value = u.GetValue()
			}
		default:
			if c := m.GetCounter(); c != nil {
				value = c.GetValue()
			}
		}

		key := containerThrottleKey{
			namespace: namespace,
			pod:       pod,
			container: container,
		}
		result[key] = value
	}

	return result
}
