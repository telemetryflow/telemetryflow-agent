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

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectNodes gathers node-level metrics and state.
func collectNodes(
	ctx context.Context,
	cs kubernetes.Interface,
	mc metricsv.Interface,
	kubeletFetcher KubeletProxyFunc,
	cfg Config,
	cluster string,
	logger *zap.Logger,
) ([]collector.Metric, []NodeState, error) {
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	// Pre-fetch metrics-server node metrics if enabled
	var nodeMetricsMap map[string]nodeMetrics
	if cfg.MetricsAPI && mc != nil {
		nodeMetricsMap = fetchNodeMetrics(ctx, mc, logger)
	}

	var metrics []collector.Metric
	var states []NodeState

	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		labels := map[string]string{
			"cluster": cluster,
			"node":    node.Name,
		}

		ready := nodeReady(node)
		roles := nodeRoles(node)
		conditions := nodeConditions(node)

		cpuCap := parseCPU(*node.Status.Capacity.Cpu())
		cpuAlloc := parseCPU(*node.Status.Allocatable.Cpu())
		memCap := parseMemory(*node.Status.Capacity.Memory())
		memAlloc := parseMemory(*node.Status.Allocatable.Memory())
		ephStorCap := node.Status.Capacity.StorageEphemeral().Value()
		ephStorAlloc := node.Status.Allocatable.StorageEphemeral().Value()
		podsCap := node.Status.Capacity.Pods().Value()

		// Count pods on this node
		podsCount := countPodsOnNode(ctx, cs, node.Name)

		// --- Metrics ---
		metrics = append(metrics,
			collector.NewMetric("k8s.node.status", boolToFloat(ready), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Node readiness status (1=Ready, 0=NotReady)"),
			collector.NewMetric("k8s.node.cpu.capacity", cpuToFloat(cpuCap), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("cores").
				WithDescription("Total CPU capacity in cores"),
			collector.NewMetric("k8s.node.cpu.allocatable", cpuToFloat(cpuAlloc), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("cores").
				WithDescription("Allocatable CPU in cores"),
			collector.NewMetric("k8s.node.memory.capacity", float64(memCap), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("Total memory capacity in bytes"),
			collector.NewMetric("k8s.node.memory.allocatable", float64(memAlloc), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("Allocatable memory in bytes"),
			collector.NewMetric("k8s.node.ephemeral_storage.capacity", float64(ephStorCap), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("Node ephemeral storage capacity in bytes"),
			collector.NewMetric("k8s.node.ephemeral_storage.allocatable", float64(ephStorAlloc), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").
				WithDescription("Allocatable ephemeral storage in bytes"),
			collector.NewMetric("k8s.node.pods.capacity", float64(podsCap), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Maximum pods capacity"),
			collector.NewMetric("k8s.node.pods.count", float64(podsCount), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Current pod count on node"),
		)

		// Condition metrics
		for cond, val := range conditions {
			condLabels := map[string]string{
				"cluster":   cluster,
				"node":      node.Name,
				"condition": cond,
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.node.condition", boolToFloat(val), collector.MetricTypeGauge).
					WithLabels(condLabels).
					WithDescription("Node condition status"),
			)
		}

		// Extract node IPs from Status.Addresses
		var internalIP, externalIP string
		for _, addr := range node.Status.Addresses {
			switch addr.Type {
			case corev1.NodeInternalIP:
				internalIP = addr.Address
			case corev1.NodeExternalIP:
				externalIP = addr.Address
			}
		}

		// --- State ---
		state := NodeState{
			Name:                        node.Name,
			Status:                      readyString(ready),
			Roles:                       roles,
			Labels:                      node.Labels,
			Annotations:                 node.Annotations,
			KubeletVersion:              node.Status.NodeInfo.KubeletVersion,
			ContainerRuntime:            node.Status.NodeInfo.ContainerRuntimeVersion,
			OS:                          node.Status.NodeInfo.OSImage,
			Architecture:                node.Status.NodeInfo.Architecture,
			CPUCapacity:                 cpuCap,
			CPUAllocatable:              cpuAlloc,
			MemoryCapacity:              memCap,
			MemoryAllocatable:           memAlloc,
			EphemeralStorageCapacity:    ephStorCap,
			EphemeralStorageAllocatable: ephStorAlloc,
			PodsCapacity:                podsCap,
			PodsCount:                   int64(podsCount),
			Conditions:                  conditions,
			InternalIP:                  internalIP,
			ExternalIP:                  externalIP,
			// Describe-level fields
			Images:     extractNodeImages(node.Status.Images),
			Addresses:  extractNodeAddresses(node.Status.Addresses),
			SystemInfo: extractNodeSystemInfo(node.Status.NodeInfo),
		}
		if node.CreationTimestamp.Unix() > 0 {
			state.CreatedAt = node.CreationTimestamp.UnixMilli()
		}

		// Collect node taints
		for _, t := range node.Spec.Taints {
			state.Taints = append(state.Taints, TaintState{
				Key:    t.Key,
				Value:  t.Value,
				Effect: string(t.Effect),
			})
		}

		// Metrics-server usage
		if nm, ok := nodeMetricsMap[node.Name]; ok {
			cpuUsage := nm.cpuCores
			memUsage := nm.memoryBytes
			state.CPUUsage = &cpuUsage
			state.MemoryUsage = &memUsage

			metrics = append(metrics,
				collector.NewMetric("k8s.node.cpu.usage", cpuUsage, collector.MetricTypeGauge).
					WithLabels(labels).WithUnit("cores").
					WithDescription("Actual CPU usage from metrics-server"),
				collector.NewMetric("k8s.node.memory.usage", float64(memUsage), collector.MetricTypeGauge).
					WithLabels(labels).WithUnit("bytes").
					WithDescription("Actual memory usage from metrics-server"),
			)
		}

		// Enrich with Kubelet summary (CPU ns, memory working set, filesystem, imageFs, network)
		if kubeletFetcher != nil {
			if summary, err := kubeletFetcher(ctx, node.Name); err == nil && summary != nil {
				// CPU nanoseconds (cumulative — use for rate calculations)
				if summary.Node.CPU != nil {
					if summary.Node.CPU.UsageCoreNanoSeconds != nil {
						state.CPUUsageNanoseconds = summary.Node.CPU.UsageCoreNanoSeconds
						metrics = append(metrics,
							collector.NewMetric("k8s.node.cpu.usage_nanoseconds", float64(*summary.Node.CPU.UsageCoreNanoSeconds), collector.MetricTypeCounter).
								WithLabels(labels).WithUnit("ns").
								WithDescription("Cumulative CPU usage in nanoseconds from Kubelet summary"),
						)
					}
				}
				// Memory working set (better pressure indicator than RSS)
				if summary.Node.Memory != nil {
					if summary.Node.Memory.WorkingSetBytes != nil {
						state.MemoryWorkingSetBytes = summary.Node.Memory.WorkingSetBytes
						metrics = append(metrics,
							collector.NewMetric("k8s.node.memory.working_set", float64(*summary.Node.Memory.WorkingSetBytes), collector.MetricTypeGauge).
								WithLabels(labels).WithUnit("bytes").
								WithDescription("Node memory working set bytes from Kubelet summary (excludes reclaimable cache)"),
						)
					}
					if summary.Node.Memory.PageFaults != nil {
						state.MemoryPageFaults = summary.Node.Memory.PageFaults
					}
					if summary.Node.Memory.MajorPageFaults != nil {
						state.MemoryMajorPageFaults = summary.Node.Memory.MajorPageFaults
					}
				}
				// Root filesystem usage
				if summary.Node.Fs != nil {
					state.FSUsedBytes = summary.Node.Fs.UsedBytes
					state.FSCapacityBytes = summary.Node.Fs.CapacityBytes
					if summary.Node.Fs.UsedBytes != nil {
						metrics = append(metrics,
							collector.NewMetric("k8s.node.filesystem.usage", float64(*summary.Node.Fs.UsedBytes), collector.MetricTypeGauge).
								WithLabels(labels).WithUnit("bytes").
								WithDescription("Node filesystem used bytes from Kubelet summary"),
						)
					}
				}
				// Container image filesystem (image layer disk usage)
				if summary.Node.Runtime != nil && summary.Node.Runtime.ImageFs != nil {
					imgFs := summary.Node.Runtime.ImageFs
					state.ImageFSUsedBytes = imgFs.UsedBytes
					state.ImageFSCapacityBytes = imgFs.CapacityBytes
					if imgFs.UsedBytes != nil {
						metrics = append(metrics,
							collector.NewMetric("k8s.node.image_filesystem.usage", float64(*imgFs.UsedBytes), collector.MetricTypeGauge).
								WithLabels(labels).WithUnit("bytes").
								WithDescription("Container image layer disk usage from Kubelet summary"),
						)
					}
				}
				// Node-level network I/O (sum all interfaces)
				if summary.Node.Network != nil {
					var totalRx, totalTx uint64
					var totalRxDrop, totalTxDrop uint64
					for _, iface := range summary.Node.Network.Interfaces {
						if iface.RxBytes != nil {
							totalRx += *iface.RxBytes
						}
						if iface.TxBytes != nil {
							totalTx += *iface.TxBytes
						}
						if iface.RxErrors != nil {
							totalRxDrop += *iface.RxErrors
						}
						if iface.TxErrors != nil {
							totalTxDrop += *iface.TxErrors
						}
					}
					state.NetworkRxBytes = &totalRx
					state.NetworkTxBytes = &totalTx
					state.NetworkRxDrop = &totalRxDrop
					totalIO := totalRx + totalTx
					metrics = append(metrics,
						collector.NewMetric("k8s.node.network.io", float64(totalIO), collector.MetricTypeGauge).
							WithLabels(labels).WithUnit("bytes").
							WithDescription("Node total network I/O bytes (rx+tx cumulative) from Kubelet summary"),
						collector.NewMetric("k8s.node.network.receive_bytes", float64(totalRx), collector.MetricTypeCounter).
							WithLabels(labels).WithUnit("bytes").
							WithDescription("Node network bytes received from Kubelet summary"),
						collector.NewMetric("k8s.node.network.transmit_bytes", float64(totalTx), collector.MetricTypeCounter).
							WithLabels(labels).WithUnit("bytes").
							WithDescription("Node network bytes transmitted from Kubelet summary"),
						collector.NewMetric("k8s.node.network.receive_drop_total", float64(totalRxDrop), collector.MetricTypeCounter).
							WithLabels(labels).
							WithDescription("Node network receive errors/drops from Kubelet summary"),
					)
				}
			} else if err != nil {
				logger.Debug("Failed to fetch kubelet stats for node", zap.String("node", node.Name), zap.Error(err))
			}
		}

		states = append(states, state)
	}

	return metrics, states, nil
}

type nodeMetrics struct {
	cpuCores    float64
	memoryBytes int64
}

func fetchNodeMetrics(ctx context.Context, mc metricsv.Interface, logger *zap.Logger) map[string]nodeMetrics {
	result := make(map[string]nodeMetrics)
	nmList, err := mc.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Debug("Failed to fetch node metrics from metrics-server", zap.Error(err))
		return result
	}
	for _, nm := range nmList.Items {
		result[nm.Name] = nodeMetrics{
			cpuCores:    float64(nm.Usage.Cpu().MilliValue()) / 1000.0,
			memoryBytes: nm.Usage.Memory().Value(),
		}
	}
	return result
}

func countPodsOnNode(ctx context.Context, cs kubernetes.Interface, nodeName string) int {
	podList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName + ",status.phase=" + string(corev1.PodRunning),
	})
	if err != nil {
		return 0
	}
	return len(podList.Items)
}

func readyString(ready bool) string {
	if ready {
		return "Ready"
	}
	return "NotReady"
}
