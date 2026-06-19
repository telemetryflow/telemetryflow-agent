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

// collectPods gathers pod-level metrics and state.
func collectPods(
	ctx context.Context,
	cs kubernetes.Interface,
	mc metricsv.Interface,
	kubeletFetcher KubeletProxyFunc,
	cadvisorFetcher CAdvisorProxyFunc,
	cfg Config,
	cluster string,
	logger *zap.Logger,
) ([]collector.Metric, []PodState, error) {
	podList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, nil, err
	}

	// Pre-fetch pod metrics from metrics-server
	var podMetricsMap map[string]map[string]containerMetrics // key: namespace/pod → container → metrics
	if cfg.MetricsAPI && mc != nil {
		podMetricsMap = fetchPodMetrics(ctx, mc, logger)
	}

	// Pre-fetch ephemeral storage + memory working set from Kubelet summary per container.
	// metrics-server does not expose these — Kubelet summary is the only source.
	var ephemeralMap map[string]map[string]kubeletContainerData // key: namespace/pod → container → data
	if kubeletFetcher != nil {
		ephemeralMap = fetchEphemeralStorageMap(ctx, podList, kubeletFetcher, logger)
	}

	// Pre-fetch CPU throttle seconds from cAdvisor (container_cpu_cfs_throttled_seconds_total).
	// Neither metrics-server nor Kubelet /stats/summary provides this — cAdvisor is the only source.
	var throttleMap map[string]map[string]float64 // key: namespace/pod → container → seconds
	if cadvisorFetcher != nil {
		throttleMap = fetchCPUThrottleMap(ctx, podList, cadvisorFetcher, logger)
	}

	// Aggregate pod counts per namespace+phase
	podCounts := make(map[string]map[string]int) // namespace → phase → count

	var metrics []collector.Metric
	var states []PodState

	for i := range podList.Items {
		pod := &podList.Items[i]

		if !cfg.shouldCollectNamespace(pod.Namespace) {
			continue
		}

		labels := map[string]string{
			"cluster":   cluster,
			"namespace": pod.Namespace,
			"pod":       pod.Name,
			"node":      pod.Spec.NodeName,
		}

		phase := string(pod.Status.Phase)

		// Aggregate counts
		if podCounts[pod.Namespace] == nil {
			podCounts[pod.Namespace] = make(map[string]int)
		}
		podCounts[pod.Namespace][phase]++

		// Total restart count across all containers
		var totalRestarts int32
		for _, cs := range pod.Status.ContainerStatuses {
			totalRestarts += cs.RestartCount
		}

		qosClass := string(pod.Status.QOSClass)
		statusReason := pod.Status.Reason

		metrics = append(metrics,
			collector.NewMetric("k8s.pod.phase", phaseToFloat(pod.Status.Phase), collector.MetricTypeGauge).
				WithLabels(labels).WithLabel("phase", phase).
				WithDescription("Pod phase (1=Running, 2=Succeeded, 3=Pending, 4=Failed, 5=Unknown)"),
			collector.NewMetric("k8s.pod.restart_count", float64(totalRestarts), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Total container restart count"),
			collector.NewMetric("k8s.pod.qos_class", 1, collector.MetricTypeGauge).
				WithLabels(labels).WithLabel("qos_class", qosClass).
				WithDescription("Pod QoS class (label carries class: Guaranteed, Burstable, BestEffort)"),
		)

		if statusReason != "" {
			metrics = append(metrics,
				collector.NewMetric("k8s.pod.status_reason", 1, collector.MetricTypeGauge).
					WithLabels(labels).WithLabel("reason", statusReason).
					WithDescription("Pod status reason (label carries reason: Evicted, NodeLost, etc.)"),
			)
		}

		// Container-level metrics
		var containerStates []ContainerState
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			cLabels := map[string]string{
				"cluster":   cluster,
				"namespace": pod.Namespace,
				"pod":       pod.Name,
				"node":      pod.Spec.NodeName,
				"container": container.Name,
			}

			// Resource requests/limits
			cpuReq := parseCPU(*container.Resources.Requests.Cpu())
			cpuLim := parseCPU(*container.Resources.Limits.Cpu())
			memReq := parseMemory(*container.Resources.Requests.Memory())
			memLim := parseMemory(*container.Resources.Limits.Memory())
			ephReq := container.Resources.Requests.StorageEphemeral().Value()
			ephLim := container.Resources.Limits.StorageEphemeral().Value()

			cs := ContainerState{
				Name:                    container.Name,
				Image:                   container.Image,
				CPURequest:              cpuReq,
				CPULimit:                cpuLim,
				MemoryRequest:           memReq,
				MemoryLimit:             memLim,
				EphemeralStorageRequest: ephReq,
				EphemeralStorageLimit:   ephLim,
				// Describe-level fields
				VolumeMounts:    extractVolumeMounts(container.VolumeMounts),
				Command:         container.Command,
				Args:            container.Args,
				WorkingDir:      container.WorkingDir,
				LivenessProbe:   extractProbe(container.LivenessProbe),
				ReadinessProbe:  extractProbe(container.ReadinessProbe),
				StartupProbe:    extractProbe(container.StartupProbe),
				ImagePullPolicy: string(container.ImagePullPolicy),
			}

			// Find container status
			for _, cst := range pod.Status.ContainerStatuses {
				if cst.Name == container.Name {
					cs.Ready = cst.Ready
					cs.RestartCount = cst.RestartCount
					cs.Status = containerStatus(cst)

					// Last termination state (OOMKilled, Error, etc.)
					if cst.LastTerminationState.Terminated != nil {
						term := cst.LastTerminationState.Terminated
						cs.LastTerminationReason = term.Reason
						exitCode := term.ExitCode
						cs.LastTerminationCode = &exitCode
					}

					statusLabels := map[string]string{
						"cluster":   cluster,
						"namespace": pod.Namespace,
						"pod":       pod.Name,
						"container": container.Name,
						"status":    cs.Status,
					}
					metrics = append(metrics,
						collector.NewMetric("k8s.pod.container.status", boolToFloat(cst.Ready), collector.MetricTypeGauge).
							WithLabels(statusLabels).
							WithDescription("Container readiness status"),
					)
					if cs.LastTerminationReason != "" {
						termLabels := map[string]string{
							"cluster":   cluster,
							"namespace": pod.Namespace,
							"pod":       pod.Name,
							"container": container.Name,
							"reason":    cs.LastTerminationReason,
						}
						metrics = append(metrics,
							collector.NewMetric("k8s.pod.container.last_terminated", 1, collector.MetricTypeGauge).
								WithLabels(termLabels).
								WithDescription("Container last termination reason (1=terminated, label carries reason)"),
						)
					}
					break
				}
			}

			if cpuReq > 0 {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.cpu_request", cpuToFloat(cpuReq), collector.MetricTypeGauge).
						WithLabels(cLabels).WithUnit("cores").
						WithDescription("Container CPU request"),
				)
			}
			if cpuLim > 0 {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.cpu_limit", cpuToFloat(cpuLim), collector.MetricTypeGauge).
						WithLabels(cLabels).WithUnit("cores").
						WithDescription("Container CPU limit"),
				)
			}
			if memReq > 0 {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.memory_request", float64(memReq), collector.MetricTypeGauge).
						WithLabels(cLabels).WithUnit("bytes").
						WithDescription("Container memory request"),
				)
			}
			if memLim > 0 {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.memory_limit", float64(memLim), collector.MetricTypeGauge).
						WithLabels(cLabels).WithUnit("bytes").
						WithDescription("Container memory limit"),
				)
			}
			if ephReq > 0 {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.ephemeral_storage_request", float64(ephReq), collector.MetricTypeGauge).
						WithLabels(cLabels).WithUnit("bytes").
						WithDescription("Container ephemeral storage request"),
				)
			}
			if ephLim > 0 {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.container.ephemeral_storage_limit", float64(ephLim), collector.MetricTypeGauge).
						WithLabels(cLabels).WithUnit("bytes").
						WithDescription("Container ephemeral storage limit"),
				)
			}

			// Metrics-server usage
			podKey := pod.Namespace + "/" + pod.Name
			if pm, ok := podMetricsMap[podKey]; ok {
				if cm, ok2 := pm[container.Name]; ok2 {
					cs.CPUUsage = &cm.cpuCores
					cs.MemoryUsage = &cm.memoryBytes

					metrics = append(metrics,
						collector.NewMetric("k8s.pod.container.cpu_usage", cm.cpuCores, collector.MetricTypeGauge).
							WithLabels(cLabels).WithUnit("cores").
							WithDescription("Actual CPU usage from metrics-server"),
						collector.NewMetric("k8s.pod.container.memory_usage", float64(cm.memoryBytes), collector.MetricTypeGauge).
							WithLabels(cLabels).WithUnit("bytes").
							WithDescription("Actual memory usage from metrics-server"),
					)
				}
			}

			// Kubelet summary enrichment (ephemeral storage + memory working set).
			// metrics-server does not provide either of these.
			if ephMap, ok := ephemeralMap[podKey]; ok {
				if cStats, ok2 := ephMap[container.Name]; ok2 {
					if cStats.ephemeralBytes > 0 {
						cs.EphemeralStorageUsage = &cStats.ephemeralBytes
						metrics = append(metrics,
							collector.NewMetric("k8s.pod.container.ephemeral_storage_usage", float64(cStats.ephemeralBytes), collector.MetricTypeGauge).
								WithLabels(cLabels).WithUnit("bytes").
								WithDescription("Actual ephemeral storage usage from Kubelet summary (rootfs + logs)"),
						)
					}
					if cStats.memoryWorkingSet > 0 {
						cs.MemoryWorkingSetBytes = &cStats.memoryWorkingSet
						metrics = append(metrics,
							collector.NewMetric("k8s.pod.container.memory_working_set", float64(cStats.memoryWorkingSet), collector.MetricTypeGauge).
								WithLabels(cLabels).WithUnit("bytes").
								WithDescription("Container memory working set bytes from Kubelet summary (excludes reclaimable cache)"),
						)
					}
				}
			}

			// cAdvisor enrichment: CPU throttle seconds.
			// Neither metrics-server nor Kubelet /stats/summary provides this.
			if tm, ok := throttleMap[podKey]; ok {
				if throttledSec, ok2 := tm[container.Name]; ok2 && throttledSec > 0 {
					cs.CPUThrottled = &throttledSec
					metrics = append(metrics,
						collector.NewMetric("k8s.pod.container.cpu_throttled", throttledSec, collector.MetricTypeCounter).
							WithLabels(cLabels).WithUnit("sec").
							WithDescription("Cumulative CPU throttled time from cAdvisor (container_cpu_cfs_throttled_seconds_total)"),
					)
				}
			}

			containerStates = append(containerStates, cs)
		}

		ownerKind, ownerName := ownerRef(pod)
		var startTime *metav1.Time
		if pod.Status.StartTime != nil {
			startTime = pod.Status.StartTime
		}

		// Pod conditions (PodScheduled, Initialized, ContainersReady, Ready)
		podConditions := make(map[string]bool, len(pod.Status.Conditions))
		for _, cond := range pod.Status.Conditions {
			podConditions[string(cond.Type)] = cond.Status == "True"
		}

		state := PodState{
			Name:         pod.Name,
			Namespace:    pod.Namespace,
			Node:         pod.Spec.NodeName,
			Phase:        phase,
			RestartCount: totalRestarts,
			Labels:       pod.Labels,
			Annotations:  pod.Annotations,
			OwnerKind:    ownerKind,
			OwnerName:    ownerName,
			Containers:   containerStates,
			IP:           pod.Status.PodIP,
			QOSClass:     string(pod.Status.QOSClass),
			Conditions:   podConditions,
			// Describe-level fields
			Tolerations:        extractTolerations(pod.Spec.Tolerations),
			Volumes:            extractVolumes(pod.Spec.Volumes),
			InitContainers:     extractInitContainers(pod),
			ServiceAccountName: pod.Spec.ServiceAccountName,
			Priority:           pod.Spec.Priority,
			PriorityClassName:  pod.Spec.PriorityClassName,
			DNSPolicy:          string(pod.Spec.DNSPolicy),
			HostNetwork:        pod.Spec.HostNetwork,
			NodeSelector:       pod.Spec.NodeSelector,
		}
		if pod.CreationTimestamp.Unix() > 0 {
			state.CreatedAt = pod.CreationTimestamp.UnixMilli()
		}
		if startTime != nil {
			t := startTime.Time
			state.StartTime = &t
		}

		states = append(states, state)
	}

	// Aggregate pod count metrics
	for ns, phases := range podCounts {
		for phase, count := range phases {
			metrics = append(metrics,
				collector.NewMetric("k8s.pod.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithLabel("phase", phase).
					WithDescription("Pod count by namespace and phase"),
			)
		}
	}

	return metrics, states, nil
}

type containerMetrics struct {
	cpuCores    float64
	memoryBytes int64
}

// kubeletContainerData holds per-container data collected from the Kubelet summary.
type kubeletContainerData struct {
	ephemeralBytes   int64 // rootfs.UsedBytes + logs.UsedBytes
	memoryWorkingSet int64 // memory.WorkingSetBytes
}

// fetchEphemeralStorageMap builds a map of namespace/pod → container → kubeletContainerData
// by querying each unique node's Kubelet /stats/summary. This is the only data source
// for ephemeral storage and memory working set — metrics-server does not provide them.
func fetchEphemeralStorageMap(
	ctx context.Context,
	podList *corev1.PodList,
	fetcher KubeletProxyFunc,
	logger *zap.Logger,
) map[string]map[string]kubeletContainerData {
	result := make(map[string]map[string]kubeletContainerData)

	// Collect unique node names from the pod list.
	nodeSet := make(map[string]struct{})
	for i := range podList.Items {
		if n := podList.Items[i].Spec.NodeName; n != "" {
			nodeSet[n] = struct{}{}
		}
	}

	for nodeName := range nodeSet {
		summary, err := fetcher(ctx, nodeName)
		if err != nil {
			logger.Debug("Failed to fetch kubelet stats for ephemeral storage",
				zap.String("node", nodeName), zap.Error(err))
			continue
		}
		for _, pod := range summary.Pods {
			key := pod.PodRef.Namespace + "/" + pod.PodRef.Name
			containers := make(map[string]kubeletContainerData)
			for _, c := range pod.Containers {
				var data kubeletContainerData
				if c.Rootfs != nil && c.Rootfs.UsedBytes != nil {
					data.ephemeralBytes += int64(*c.Rootfs.UsedBytes)
				}
				if c.Logs != nil && c.Logs.UsedBytes != nil {
					data.ephemeralBytes += int64(*c.Logs.UsedBytes)
				}
				if c.Memory != nil && c.Memory.WorkingSetBytes != nil {
					data.memoryWorkingSet = int64(*c.Memory.WorkingSetBytes)
				}
				if data.ephemeralBytes > 0 || data.memoryWorkingSet > 0 {
					containers[c.Name] = data
				}
			}
			if len(containers) > 0 {
				result[key] = containers
			}
		}
	}
	return result
}

func fetchPodMetrics(ctx context.Context, mc metricsv.Interface, logger *zap.Logger) map[string]map[string]containerMetrics {
	result := make(map[string]map[string]containerMetrics)
	pmList, err := mc.MetricsV1beta1().PodMetricses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Debug("Failed to fetch pod metrics from metrics-server", zap.Error(err))
		return result
	}
	for _, pm := range pmList.Items {
		key := pm.Namespace + "/" + pm.Name
		containers := make(map[string]containerMetrics)
		for _, c := range pm.Containers {
			containers[c.Name] = containerMetrics{
				cpuCores:    float64(c.Usage.Cpu().MilliValue()) / 1000.0,
				memoryBytes: c.Usage.Memory().Value(),
			}
		}
		result[key] = containers
	}
	return result
}
