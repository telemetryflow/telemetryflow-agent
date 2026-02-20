package kubernetes

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// KubeletStatsFetcher retrieves the Kubelet /stats/summary for a given node.
type KubeletStatsFetcher func(ctx context.Context, nodeName string) (*KubeletSummary, error)

// collectNetwork fetches per-pod network stats from each node's Kubelet Summary
// API and aggregates them by namespace.
func collectNetwork(
	ctx context.Context,
	fetcher KubeletStatsFetcher,
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

// newKubeletStatsFetcher creates a real KubeletStatsFetcher using the
// Kubernetes API server proxy to reach each node's kubelet /stats/summary.
func newKubeletStatsFetcher(cs kubernetes.Interface) KubeletStatsFetcher {
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
