package kubernetes

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "kubernetes"

// KubernetesCollector collects Kubernetes resource metrics.
// It implements the collector.Collector interface.
type KubernetesCollector struct {
	cfg    Config
	logger *zap.Logger

	clientset     kubernetes.Interface
	metricsClient metricsv.Interface

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	// Last collected cluster state (for sync to backend)
	lastState *ClusterState

	// kubeletFetcher retrieves /stats/summary from each node's kubelet.
	// nil means network collection is skipped (e.g. in unit tests).
	kubeletFetcher KubeletStatsFetcher
}

// NewKubernetesCollector creates a new Kubernetes collector.
func NewKubernetesCollector(cfg config.KubernetesCollectorConfig, logger *zap.Logger) (*KubernetesCollector, error) {
	conf := NewConfig(cfg)

	cs, err := newClientset(conf.Kubeconfig, conf.Context)
	if err != nil {
		return nil, fmt.Errorf("kubernetes collector: %w", err)
	}

	var mc metricsv.Interface
	if conf.MetricsAPI {
		mc, err = newMetricsClientset(conf.Kubeconfig, conf.Context)
		if err != nil {
			logger.Warn("Failed to create metrics-server client, usage metrics will be unavailable", zap.Error(err))
		}
	}

	// Auto-detect cluster name if not configured
	clusterName := conf.ClusterName
	if clusterName == "" {
		clusterName = detectClusterName()
	}
	conf.ClusterName = clusterName

	// Auto-detect cluster provider if not configured
	if conf.ClusterProvider == "" {
		conf.ClusterProvider = detectClusterProvider()
	}

	return &KubernetesCollector{
		cfg:            conf,
		logger:         logger.Named(collectorName),
		clientset:      cs,
		metricsClient:  mc,
		kubeletFetcher: newKubeletStatsFetcher(cs),
	}, nil
}

// Name returns the collector name.
func (k *KubernetesCollector) Name() string {
	return collectorName
}

// Start begins periodic metric collection. It blocks until ctx is cancelled or Stop is called.
func (k *KubernetesCollector) Start(ctx context.Context) error {
	k.mu.Lock()
	if k.running {
		k.mu.Unlock()
		return fmt.Errorf("kubernetes collector is already running")
	}
	k.running = true
	k.stopChan = make(chan struct{})
	k.mu.Unlock()

	k.logger.Info("Kubernetes collector starting",
		zap.Duration("interval", k.cfg.Interval),
		zap.String("cluster", k.cfg.ClusterName),
		zap.String("provider", k.cfg.ClusterProvider),
	)

	ticker := time.NewTicker(k.cfg.Interval)
	defer ticker.Stop()

	// Collect once immediately at startup
	if _, err := k.Collect(ctx); err != nil {
		k.logger.Warn("Initial collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return k.Stop()
		case <-k.stopChan:
			return nil
		case <-ticker.C:
			if _, err := k.Collect(ctx); err != nil {
				k.logger.Warn("Collection cycle failed", zap.Error(err))
			}
		}
	}
}

// Stop gracefully stops the collector.
func (k *KubernetesCollector) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.running {
		return nil
	}

	k.logger.Info("Kubernetes collector stopping")
	k.running = false
	close(k.stopChan)
	return nil
}

// IsRunning returns whether the collector is running.
func (k *KubernetesCollector) IsRunning() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.running
}

// Collect performs a single collection cycle across all enabled sub-collectors.
func (k *KubernetesCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	start := time.Now()
	k.logger.Debug("Starting Kubernetes collection cycle")

	var allMetrics []collector.Metric
	state := &ClusterState{
		ClusterName:     k.cfg.ClusterName,
		ClusterProvider: k.cfg.ClusterProvider,
		CollectedAt:     start,
	}

	// --- Nodes ---
	if k.cfg.Nodes {
		metrics, nodes, err := collectNodes(ctx, k.clientset, k.metricsClient, k.cfg, k.cfg.ClusterName, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect node metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Nodes = nodes
		}
	}

	// --- Pods ---
	if k.cfg.Pods {
		metrics, pods, err := collectPods(ctx, k.clientset, k.metricsClient, k.cfg, k.cfg.ClusterName, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect pod metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Pods = pods
		}
	}

	// --- Deployments ---
	if k.cfg.Deployments {
		metrics, deps, err := collectDeployments(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect deployment metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Deployments = deps
		}
	}

	// --- Namespaces ---
	if k.cfg.NamespacesCollect {
		metrics, nss, err := collectNamespaces(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect namespace metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Namespaces = nss
		}
	}

	// --- Storage ---
	if k.cfg.Storage {
		metrics, pvs, pvcs, err := collectStorage(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect storage metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.PVs = pvs
			state.PVCs = pvcs
		}
	}

	// --- Workloads ---
	if k.cfg.Workloads {
		metrics, sts, ds, rs, jobs, crons, err := collectWorkloads(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect workload metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.StatefulSets = sts
			state.DaemonSets = ds
			state.ReplicaSets = rs
			state.Jobs = jobs
			state.CronJobs = crons
		}
	}

	// --- Services ---
	if k.cfg.Services {
		metrics, svcs, err := collectServices(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect service metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Services = svcs
		}
	}

	// --- Events ---
	if k.cfg.Events {
		metrics, events, err := collectEvents(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect event metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Events = events
		}
	}

	// --- Resource Counts ---
	if k.cfg.ResourceCounts {
		metrics, counts, err := collectResourceCounts(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect resource count metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.ResourceCounts = counts
		}
	}

	// --- Network (Kubelet Summary API) ---
	if k.cfg.Network {
		// Gather node names from already-collected state, or list them
		var nodeNames []string
		if len(state.Nodes) > 0 {
			for _, n := range state.Nodes {
				nodeNames = append(nodeNames, n.Name)
			}
		} else {
			nodeList, err := k.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err == nil {
				for i := range nodeList.Items {
					nodeNames = append(nodeNames, nodeList.Items[i].Name)
				}
			}
		}

		metrics, netStats, err := collectNetwork(ctx, k.kubeletFetcher, nodeNames, k.cfg, k.cfg.ClusterName, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect network metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.NetworkStats = netStats
		}
	}

	// Store state for backend sync
	k.mu.Lock()
	k.lastState = state
	k.mu.Unlock()

	duration := time.Since(start)
	k.logger.Debug("Kubernetes collection cycle completed",
		zap.Int("metrics", len(allMetrics)),
		zap.Duration("duration", duration),
	)

	return allMetrics, nil
}

// LastClusterState returns the most recent cluster state snapshot for backend sync.
func (k *KubernetesCollector) LastClusterState() *ClusterState {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.lastState
}

// ClusterName returns the detected or configured cluster name.
func (k *KubernetesCollector) ClusterName() string {
	return k.cfg.ClusterName
}

// ClusterProvider returns the detected or configured cluster provider.
func (k *KubernetesCollector) ClusterProvider() string {
	return k.cfg.ClusterProvider
}

// SetKubeletFetcher replaces the kubelet stats fetcher (used in tests).
func (k *KubernetesCollector) SetKubeletFetcher(f KubeletStatsFetcher) {
	k.kubeletFetcher = f
}

// NewKubernetesCollectorForTest creates a KubernetesCollector with injected dependencies
// for unit testing. This bypasses the real Kubernetes client creation.
func NewKubernetesCollectorForTest(
	cfg config.KubernetesCollectorConfig,
	cs kubernetes.Interface,
	mc metricsv.Interface,
	logger *zap.Logger,
) *KubernetesCollector {
	conf := NewConfig(cfg)
	if conf.ClusterName == "" {
		conf.ClusterName = "test-cluster"
	}
	return &KubernetesCollector{
		cfg:           conf,
		logger:        logger.Named(collectorName),
		clientset:     cs,
		metricsClient: mc,
	}
}

// detectClusterName attempts to determine the cluster name from environment.
func detectClusterName() string {
	// Check common environment variables
	if name := os.Getenv("CLUSTER_NAME"); name != "" {
		return name
	}
	if name := os.Getenv("KUBE_CLUSTER_NAME"); name != "" {
		return name
	}
	// EKS
	if name := os.Getenv("EKS_CLUSTER_NAME"); name != "" {
		return name
	}
	// Fallback
	hostname, _ := os.Hostname()
	if hostname != "" {
		return hostname
	}
	return "unknown"
}

// detectClusterProvider attempts to detect the Kubernetes provider from environment
// variables and filesystem heuristics. Returns a value matching K8sProviderEnum
// on the platform backend (eks, gke, aks, ack, cce, k3s, kind, minikube,
// rancher, openshift, okd, microshift, kubesphere, self-managed).
func detectClusterProvider() string {
	// === Managed Cloud Providers ===

	// EKS (Amazon Elastic Kubernetes Service)
	if os.Getenv("AWS_REGION") != "" || os.Getenv("EKS_CLUSTER_NAME") != "" {
		return "eks"
	}
	// GKE (Google Kubernetes Engine)
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("GKE_CLUSTER_NAME") != "" {
		return "gke"
	}
	// AKS (Azure Kubernetes Service)
	if os.Getenv("AKS_CLUSTER_NAME") != "" || os.Getenv("AZURE_SUBSCRIPTION_ID") != "" {
		return "aks"
	}
	// ACK (Alibaba Cloud Kubernetes Service)
	if os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID") != "" || os.Getenv("ACK_CLUSTER_ID") != "" {
		return "ack"
	}
	// CCE (Huawei Cloud Container Engine)
	if os.Getenv("HUAWEICLOUD_SDK_TYPE") != "" || os.Getenv("CCE_CLUSTER_ID") != "" {
		return "cce"
	}

	// === OpenShift Variants (check MicroShift first — it's a subset of OpenShift) ===

	// MicroShift
	if _, err := os.Stat("/var/lib/microshift"); err == nil {
		return "microshift"
	}
	// OpenShift
	if os.Getenv("OPENSHIFT_BUILD_NAMESPACE") != "" || os.Getenv("OPENSHIFT_DEPLOYMENT_NAME") != "" {
		return "openshift"
	}
	if _, err := os.Stat("/etc/openshift"); err == nil {
		return "openshift"
	}
	// OKD (Origin Kubernetes Distribution — community OpenShift)
	if os.Getenv("OKD_CLUSTER") != "" {
		return "okd"
	}
	if _, err := os.Stat("/etc/okd"); err == nil {
		return "okd"
	}

	// === Lightweight / Local Distributions ===

	// k3s (check before Rancher — k3s lives under /var/lib/rancher/k3s)
	if _, err := os.Stat("/var/lib/rancher/k3s"); err == nil {
		return "k3s"
	}
	// Rancher (RKE / RKE2)
	if os.Getenv("CATTLE_CLUSTER_AGENT_PORT") != "" || os.Getenv("CATTLE_SERVER") != "" {
		return "rancher"
	}
	if _, err := os.Stat("/var/lib/rancher/rke2"); err == nil {
		return "rancher"
	}
	// minikube
	if os.Getenv("MINIKUBE_ACTIVE_DOCKERD") != "" || os.Getenv("MINIKUBE_HOME") != "" {
		return "minikube"
	}
	// KIND (Kubernetes IN Docker)
	if os.Getenv("KIND_CLUSTER_NAME") != "" {
		return "kind"
	}

	// === Platform Distributions ===

	// KubeSphere
	if os.Getenv("KUBESPHERE_NAMESPACE") != "" {
		return "kubesphere"
	}

	return "self-managed"
}
