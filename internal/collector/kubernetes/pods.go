package kubernetes

import (
	"context"

	"go.uber.org/zap"
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

		metrics = append(metrics,
			collector.NewMetric("k8s.pod.phase", phaseToFloat(pod.Status.Phase), collector.MetricTypeGauge).
				WithLabels(labels).WithLabel("phase", phase).
				WithDescription("Pod phase (1=Running, 2=Succeeded, 3=Pending, 4=Failed, 5=Unknown)"),
			collector.NewMetric("k8s.pod.restart_count", float64(totalRestarts), collector.MetricTypeGauge).
				WithLabels(labels).
				WithDescription("Total container restart count"),
		)

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

			cs := ContainerState{
				Name:          container.Name,
				CPURequest:    cpuReq,
				CPULimit:      cpuLim,
				MemoryRequest: memReq,
				MemoryLimit:   memLim,
			}

			// Find container status
			for _, cst := range pod.Status.ContainerStatuses {
				if cst.Name == container.Name {
					cs.Ready = cst.Ready
					cs.RestartCount = cst.RestartCount
					cs.Status = containerStatus(cst)

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

			containerStates = append(containerStates, cs)
		}

		ownerKind, ownerName := ownerRef(pod)
		var startTime *metav1.Time
		if pod.Status.StartTime != nil {
			startTime = pod.Status.StartTime
		}

		state := PodState{
			Name:         pod.Name,
			Namespace:    pod.Namespace,
			Node:         pod.Spec.NodeName,
			Phase:        phase,
			RestartCount: totalRestarts,
			Labels:       pod.Labels,
			OwnerKind:    ownerKind,
			OwnerName:    ownerName,
			Containers:   containerStates,
			IP:           pod.Status.PodIP,
			QOSClass:     string(pod.Status.QOSClass),
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
