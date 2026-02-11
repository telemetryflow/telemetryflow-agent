package kubernetes

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
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
		cfg:           conf,
		logger:        logger.Named(collectorName),
		clientset:     cs,
		metricsClient: mc,
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

// detectClusterProvider attempts to detect the Kubernetes provider from environment.
func detectClusterProvider() string {
	// EKS
	if os.Getenv("AWS_REGION") != "" || os.Getenv("EKS_CLUSTER_NAME") != "" {
		return "eks"
	}
	// GKE
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("GKE_CLUSTER_NAME") != "" {
		return "gke"
	}
	// AKS
	if os.Getenv("AKS_CLUSTER_NAME") != "" || os.Getenv("AZURE_SUBSCRIPTION_ID") != "" {
		return "aks"
	}
	// k3s
	if _, err := os.Stat("/var/lib/rancher/k3s"); err == nil {
		return "k3s"
	}
	return "self-managed"
}
