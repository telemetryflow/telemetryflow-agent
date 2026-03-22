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
	kubeletFetcher KubeletProxyFunc

	// cadvisorFetcher retrieves /metrics/cadvisor from each node's kubelet
	// via the API server proxy. Used for CPU throttle metrics.
	cadvisorFetcher CAdvisorProxyFunc
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
		cfg:             conf,
		logger:          logger.Named(collectorName),
		clientset:       cs,
		metricsClient:   mc,
		kubeletFetcher:  newKubeletStatsFetcher(cs),
		cadvisorFetcher: newCAdvisorProxyFetcher(cs),
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
		metrics, nodes, err := collectNodes(ctx, k.clientset, k.metricsClient, k.kubeletFetcher, k.cfg, k.cfg.ClusterName, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect node metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Nodes = nodes
		}
	}

	// --- Pods ---
	if k.cfg.Pods {
		metrics, pods, err := collectPods(ctx, k.clientset, k.metricsClient, k.kubeletFetcher, k.cadvisorFetcher, k.cfg, k.cfg.ClusterName, k.logger)
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
		metrics, svcs, eps, err := collectServices(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect service metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.Services = svcs
			state.Endpoints = eps
		}

		// Ingresses (collect alongside services since they share networking context)
		ingMetrics, ings, err := collectIngresses(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect ingress state", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, ingMetrics...)
			state.Ingresses = ings
		}
	}

	// --- Network Policies ---
	{
		npMetrics, nps, err := collectNetworkPolicies(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect network policy state", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, npMetrics...)
			state.NetworkPolicies = nps
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

	// --- HPA ---
	if k.cfg.HPA {
		metrics, hpas, err := collectHPAs(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect HPA metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.HPAs = hpas
		}
	}

	// --- PodDisruptionBudgets ---
	if k.cfg.PDB {
		metrics, pdbs, err := collectPDBs(ctx, k.clientset, k.cfg, k.cfg.ClusterName)
		if err != nil {
			k.logger.Warn("Failed to collect PDB metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, metrics...)
			state.PDBs = pdbs
		}
	}

	// --- Pod Logs ---
	if k.cfg.PodLogs {
		logs, err := collectPodLogs(ctx, k.clientset, k.cfg, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect pod logs", zap.Error(err))
		} else {
			state.PodLogs = logs
		}
	}

	// --- Node Logs ---
	if k.cfg.NodeLogs {
		nodeLogs, err := collectNodeLogs(ctx, k.clientset, k.cfg, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect node logs", zap.Error(err))
		} else {
			state.NodeLogs = nodeLogs
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

		// Volume stats (PVC usage from Kubelet /stats/summary)
		if k.cfg.Storage {
			volMetrics, pvcData, err := collectVolumeStats(ctx, k.kubeletFetcher, nodeNames, k.cfg, k.cfg.ClusterName, k.logger)
			if err != nil {
				k.logger.Warn("Failed to collect volume stats", zap.Error(err))
			} else {
				allMetrics = append(allMetrics, volMetrics...)
				// Map PVC volume usage to PV names for the sync payload
				if len(pvcData) > 0 && len(state.PVs) > 0 {
					state.PVIOStats = buildPVIOStats(state.PVs, pvcData)
				}
			}
		}
	}

	// --- Usage Metrics (metrics-server with Kubelet fallback) ---
	// collectUsageMetricsWithFallback tries the metrics.k8s.io API first and
	// automatically falls back to querying each node's Kubelet /stats/summary
	// endpoint when metrics-server is unavailable.
	if k.cfg.MetricsAPI {
		usageMetrics, err := collectUsageMetricsWithFallback(ctx, k)
		if err != nil {
			k.logger.Warn("Failed to collect usage metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, usageMetrics...)
		}
	}

	// --- Resource Quotas ---
	if k.cfg.ResourceQuotas {
		rqMetrics, err := k.collectResourceQuotas(ctx)
		if err != nil {
			k.logger.Warn("Failed to collect resource quota metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, rqMetrics...)
		}
	}

	// --- Limit Ranges ---
	if k.cfg.LimitRanges {
		lrMetrics, err := k.collectLimitRanges(ctx)
		if err != nil {
			k.logger.Warn("Failed to collect limit range metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, lrMetrics...)
		}
	}

	// --- Pod Conditions ---
	if k.cfg.PodConditions {
		pcMetrics, err := k.collectPodConditions(ctx)
		if err != nil {
			k.logger.Warn("Failed to collect pod condition metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, pcMetrics...)
		}
	}

	// --- Node Taints ---
	if k.cfg.NodeTaints {
		ntMetrics, err := k.collectNodeTaints(ctx)
		if err != nil {
			k.logger.Warn("Failed to collect node taint metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, ntMetrics...)
		}
	}

	// --- Workload Generations ---
	if k.cfg.WorkloadGenerations {
		wgMetrics, err := k.collectWorkloadGenerations(ctx)
		if err != nil {
			k.logger.Warn("Failed to collect workload generation metrics", zap.Error(err))
		} else {
			allMetrics = append(allMetrics, wgMetrics...)
		}
	}

	// --- API Server Metrics ---
	if k.cfg.ApiServerMetrics {
		apiMetrics, err := collectApiServerMetrics(ctx, k.clientset, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect API server metrics", zap.Error(err))
		} else {
			state.ApiServerMetrics = apiMetrics
		}
	}

	// --- CoreDNS Metrics ---
	if k.cfg.CoreDNSMetrics {
		dnsMetrics, err := collectCoreDNSMetrics(ctx, k.clientset, k.cfg.CoreDNSService, k.logger)
		if err != nil {
			k.logger.Warn("Failed to collect CoreDNS metrics", zap.Error(err))
		} else {
			state.CoreDNSMetrics = dnsMetrics
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

// Clientset returns the Kubernetes client interface for external use (e.g., Agent API server).
func (k *KubernetesCollector) Clientset() kubernetes.Interface {
	return k.clientset
}

// SetKubeletFetcher replaces the kubelet stats fetcher (used in tests).
func (k *KubernetesCollector) SetKubeletFetcher(f KubeletProxyFunc) {
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
//
// When running as a DaemonSet the container host filesystem is typically
// bind-mounted at /hostfs (the value of TELEMETRYFLOW_HOST_ROOT, defaulting to
// /hostfs). All path-based heuristics check both the direct path and the
// host-root-prefixed path so detection works correctly inside containers.
func detectClusterProvider() string {
	// hostRoot is the mount point for the host filesystem inside the container.
	// When running as a DaemonSet with hostPath / → /hostfs this lets us read
	// host filesystem paths (e.g. /var/lib/rancher/rke2) that are not directly
	// accessible inside the container.
	hostRoot := os.Getenv("TELEMETRYFLOW_HOST_ROOT")
	if hostRoot == "" {
		hostRoot = "/hostfs"
	}

	// hostStat checks both the direct path and the host-root-prefixed path.
	hostStat := func(path string) bool {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if _, err := os.Stat(hostRoot + path); err == nil {
			return true
		}
		return false
	}

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
	if hostStat("/var/lib/microshift") {
		return "microshift"
	}
	// OpenShift
	if os.Getenv("OPENSHIFT_BUILD_NAMESPACE") != "" || os.Getenv("OPENSHIFT_DEPLOYMENT_NAME") != "" {
		return "openshift"
	}
	if hostStat("/etc/openshift") {
		return "openshift"
	}
	// OKD (Origin Kubernetes Distribution — community OpenShift)
	if os.Getenv("OKD_CLUSTER") != "" {
		return "okd"
	}
	if hostStat("/etc/okd") {
		return "okd"
	}

	// === Lightweight / Local Distributions ===

	// k3s (check before Rancher — k3s lives under /var/lib/rancher/k3s)
	if hostStat("/var/lib/rancher/k3s") {
		return "k3s"
	}
	// Rancher (RKE / RKE2)
	if os.Getenv("CATTLE_CLUSTER_AGENT_PORT") != "" || os.Getenv("CATTLE_SERVER") != "" {
		return "rancher"
	}
	if hostStat("/var/lib/rancher/rke2") {
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
