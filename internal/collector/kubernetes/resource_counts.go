package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectResourceCounts gathers counts of Secrets, ConfigMaps, and Ingresses per namespace.
func collectResourceCounts(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, *ResourceCounts, error) {
	var metrics []collector.Metric
	counts := &ResourceCounts{
		Secrets:    make(map[string]int),
		ConfigMaps: make(map[string]int),
		Ingresses:  make(map[string]int),
	}

	// --- Secrets ---
	secretList, err := cs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		nsCounts := make(map[string]int)
		for i := range secretList.Items {
			s := &secretList.Items[i]
			if !cfg.shouldCollectNamespace(s.Namespace) {
				continue
			}
			nsCounts[s.Namespace]++
		}
		for ns, count := range nsCounts {
			counts.Secrets[ns] = count
			metrics = append(metrics,
				collector.NewMetric("k8s.secret.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithDescription("Secret count per namespace"),
			)
		}
	}

	// --- ConfigMaps ---
	cmList, err := cs.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err == nil {
		nsCounts := make(map[string]int)
		for i := range cmList.Items {
			cm := &cmList.Items[i]
			if !cfg.shouldCollectNamespace(cm.Namespace) {
				continue
			}
			nsCounts[cm.Namespace]++
		}
		for ns, count := range nsCounts {
			counts.ConfigMaps[ns] = count
			metrics = append(metrics,
				collector.NewMetric("k8s.configmap.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithDescription("ConfigMap count per namespace"),
			)
		}
	}

	// --- Ingresses ---
	ingList, err := cs.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err == nil {
		nsCounts := make(map[string]int)
		for i := range ingList.Items {
			ing := &ingList.Items[i]
			if !cfg.shouldCollectNamespace(ing.Namespace) {
				continue
			}
			nsCounts[ing.Namespace]++
		}
		for ns, count := range nsCounts {
			counts.Ingresses[ns] = count
			metrics = append(metrics,
				collector.NewMetric("k8s.ingress.count", float64(count), collector.MetricTypeGauge).
					WithLabel("cluster", cluster).
					WithLabel("namespace", ns).
					WithDescription("Ingress count per namespace"),
			)
		}
	}

	return metrics, counts, nil
}
