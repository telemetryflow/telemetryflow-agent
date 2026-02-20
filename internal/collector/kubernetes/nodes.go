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
			Name:              node.Name,
			Status:            readyString(ready),
			Roles:             roles,
			Labels:            node.Labels,
			KubeletVersion:    node.Status.NodeInfo.KubeletVersion,
			ContainerRuntime:  node.Status.NodeInfo.ContainerRuntimeVersion,
			OS:                node.Status.NodeInfo.OSImage,
			Architecture:      node.Status.NodeInfo.Architecture,
			CPUCapacity:       cpuCap,
			CPUAllocatable:    cpuAlloc,
			MemoryCapacity:    memCap,
			MemoryAllocatable: memAlloc,
			PodsCapacity:      podsCap,
			PodsCount:         int64(podsCount),
			Conditions:        conditions,
			InternalIP:        internalIP,
			ExternalIP:        externalIP,
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
