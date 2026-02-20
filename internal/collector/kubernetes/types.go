package kubernetes

import "time"

// ClusterState is the full cluster snapshot sent to the TFO backend for sync.
type ClusterState struct {
	ClusterName     string                  `json:"cluster_name"`
	ClusterProvider string                  `json:"cluster_provider"`
	CollectedAt     time.Time               `json:"collected_at"`
	Nodes           []NodeState             `json:"nodes,omitempty"`
	Namespaces      []NamespaceState        `json:"namespaces,omitempty"`
	Pods            []PodState              `json:"pods,omitempty"`
	Deployments     []DeploymentState       `json:"deployments,omitempty"`
	StatefulSets    []WorkloadState         `json:"statefulsets,omitempty"`
	DaemonSets      []WorkloadState         `json:"daemonsets,omitempty"`
	ReplicaSets     []WorkloadState         `json:"replicasets,omitempty"`
	Jobs            []WorkloadState         `json:"jobs,omitempty"`
	CronJobs        []WorkloadState         `json:"cronjobs,omitempty"`
	Services        []ServiceState          `json:"services,omitempty"`
	PVs             []PVState               `json:"pvs,omitempty"`
	PVCs            []PVCState              `json:"pvcs,omitempty"`
	Events          []EventState            `json:"events,omitempty"`
	ResourceCounts  *ResourceCounts         `json:"resource_counts,omitempty"`
	NetworkStats    []NamespaceNetworkStats `json:"network_stats,omitempty"`
}

// NodeState represents a single Kubernetes node.
type NodeState struct {
	Name              string            `json:"name"`
	Status            string            `json:"status"` // Ready, NotReady
	Roles             []string          `json:"roles,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	KubeletVersion    string            `json:"kubelet_version,omitempty"`
	ContainerRuntime  string            `json:"container_runtime,omitempty"`
	OS                string            `json:"os,omitempty"`
	Architecture      string            `json:"architecture,omitempty"`
	CPUCapacity       int64             `json:"cpu_capacity"`       // millicores
	CPUAllocatable    int64             `json:"cpu_allocatable"`    // millicores
	MemoryCapacity    int64             `json:"memory_capacity"`    // bytes
	MemoryAllocatable int64             `json:"memory_allocatable"` // bytes
	PodsCapacity      int64             `json:"pods_capacity"`
	PodsCount         int64             `json:"pods_count"`
	Conditions        map[string]bool   `json:"conditions,omitempty"`   // condition → true/false
	CPUUsage          *float64          `json:"cpu_usage,omitempty"`    // cores (from metrics-server)
	MemoryUsage       *int64            `json:"memory_usage,omitempty"` // bytes (from metrics-server)
	InternalIP        string            `json:"internal_ip,omitempty"`
	ExternalIP        string            `json:"external_ip,omitempty"`
}

// PodState represents a single Kubernetes pod.
type PodState struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	Node         string            `json:"node,omitempty"`
	Phase        string            `json:"phase"` // Running, Pending, Succeeded, Failed, Unknown
	RestartCount int32             `json:"restart_count"`
	StartTime    *time.Time        `json:"start_time,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	OwnerKind    string            `json:"owner_kind,omitempty"`
	OwnerName    string            `json:"owner_name,omitempty"`
	Containers   []ContainerState  `json:"containers,omitempty"`
	IP           string            `json:"ip,omitempty"`
	QOSClass     string            `json:"qos_class,omitempty"`
}

// ContainerState represents a container within a pod.
type ContainerState struct {
	Name          string   `json:"name"`
	Image         string   `json:"image,omitempty"`
	Ready         bool     `json:"ready"`
	RestartCount  int32    `json:"restart_count"`
	Status        string   `json:"status"`                   // running, waiting, terminated
	CPURequest    int64    `json:"cpu_request,omitempty"`    // millicores
	CPULimit      int64    `json:"cpu_limit,omitempty"`      // millicores
	MemoryRequest int64    `json:"memory_request,omitempty"` // bytes
	MemoryLimit   int64    `json:"memory_limit,omitempty"`   // bytes
	CPUUsage      *float64 `json:"cpu_usage,omitempty"`      // cores (metrics-server)
	MemoryUsage   *int64   `json:"memory_usage,omitempty"`   // bytes (metrics-server)
}

// DeploymentStrategy represents the deployment strategy configuration.
type DeploymentStrategy struct {
	Type           string `json:"type"`                      // RollingUpdate, Recreate
	MaxUnavailable string `json:"max_unavailable,omitempty"` // e.g. "25%"
	MaxSurge       string `json:"max_surge,omitempty"`       // e.g. "25%"
}

// DeploymentContainer is a summary of a container spec within a deployment.
type DeploymentContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// DeploymentState represents a Kubernetes deployment.
type DeploymentState struct {
	Name                string                `json:"name"`
	Namespace           string                `json:"namespace"`
	Replicas            int32                 `json:"replicas"`
	ReadyReplicas       int32                 `json:"ready_replicas"`
	AvailableReplicas   int32                 `json:"available_replicas"`
	UnavailableReplicas int32                 `json:"unavailable_replicas"`
	UpdatedReplicas     int32                 `json:"updated_replicas"`
	Labels              map[string]string     `json:"labels,omitempty"`
	Conditions          map[string]bool       `json:"conditions,omitempty"`
	Strategy            *DeploymentStrategy   `json:"strategy,omitempty"`
	Containers          []DeploymentContainer `json:"containers,omitempty"`
	Selector            map[string]string     `json:"selector,omitempty"`
	Generation          int64                 `json:"generation,omitempty"`
	ObservedGeneration  int64                 `json:"observed_generation,omitempty"`
}

// ResourceQuotaUsage represents a single resource's used/hard values.
type ResourceQuotaUsage struct {
	Used string `json:"used"`
	Hard string `json:"hard"`
}

// NamespaceResourceQuota represents the aggregate resource quota for a namespace.
type NamespaceResourceQuota struct {
	CPU    *ResourceQuotaUsage `json:"cpu,omitempty"`
	Memory *ResourceQuotaUsage `json:"memory,omitempty"`
	Pods   *ResourceQuotaUsage `json:"pods,omitempty"`
}

// NamespaceState represents a Kubernetes namespace.
type NamespaceState struct {
	Name          string                  `json:"name"`
	Phase         string                  `json:"phase"` // Active, Terminating
	Labels        map[string]string       `json:"labels,omitempty"`
	ResourceQuota *NamespaceResourceQuota `json:"resource_quota,omitempty"`
}

// WorkloadState is a generic workload (StatefulSet, DaemonSet, ReplicaSet, Job, CronJob).
type WorkloadState struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// Replica counts (semantics vary by kind)
	Desired   int32 `json:"desired"`
	Current   int32 `json:"current"`
	Ready     int32 `json:"ready"`
	Succeeded int32 `json:"succeeded,omitempty"`
	Failed    int32 `json:"failed,omitempty"`
	Active    int32 `json:"active,omitempty"` // CronJob
}

// ServiceState represents a Kubernetes service.
type ServiceState struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	Type          string `json:"type"` // ClusterIP, NodePort, LoadBalancer, ExternalName
	ClusterIP     string `json:"cluster_ip,omitempty"`
	EndpointCount int    `json:"endpoint_count"`
}

// PVClaimRef identifies the PVC bound to a PV.
type PVClaimRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// PVState represents a PersistentVolume.
type PVState struct {
	Name          string      `json:"name"`
	StorageClass  string      `json:"storage_class,omitempty"`
	Capacity      int64       `json:"capacity"` // bytes
	Phase         string      `json:"phase"`    // Available, Bound, Released, Failed
	AccessModes   []string    `json:"access_modes,omitempty"`
	ReclaimPolicy string      `json:"reclaim_policy,omitempty"`
	VolumeMode    string      `json:"volume_mode,omitempty"`
	ClaimRef      *PVClaimRef `json:"claim_ref,omitempty"`
}

// PVCResources represents the resource requests/limits of a PVC.
type PVCResources struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// PVCState represents a PersistentVolumeClaim.
type PVCState struct {
	Name         string        `json:"name"`
	Namespace    string        `json:"namespace"`
	StorageClass string        `json:"storage_class,omitempty"`
	Capacity     int64         `json:"capacity"` // bytes
	Phase        string        `json:"phase"`    // Pending, Bound, Lost
	AccessModes  []string      `json:"access_modes,omitempty"`
	VolumeName   string        `json:"volume_name,omitempty"`
	VolumeMode   string        `json:"volume_mode,omitempty"`
	Resources    *PVCResources `json:"resources,omitempty"`
}

// EventState represents a Kubernetes event.
type EventState struct {
	Type           string `json:"type"` // Normal, Warning
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	Source         string `json:"source"`        // component that generated it
	InvolvedKind   string `json:"involved_kind"` // Node, Pod, Deployment, etc.
	InvolvedName   string `json:"involved_name"`
	Namespace      string `json:"namespace,omitempty"`
	Count          int32  `json:"count"`
	FirstTimestamp int64  `json:"first_timestamp"` // Unix millis
	LastTimestamp  int64  `json:"last_timestamp"`  // Unix millis
}

// ResourceCounts holds per-namespace resource counts for the overview dashboard.
type ResourceCounts struct {
	Secrets    map[string]int `json:"secrets,omitempty"`
	ConfigMaps map[string]int `json:"configmaps,omitempty"`
	Ingresses  map[string]int `json:"ingresses,omitempty"`
}

// NamespaceNetworkStats holds aggregated network statistics per namespace.
type NamespaceNetworkStats struct {
	Namespace string `json:"namespace"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
}

// KubeletSummary is the response from the Kubelet /stats/summary API.
type KubeletSummary struct {
	Node KubeletNodeStats  `json:"node"`
	Pods []KubeletPodStats `json:"pods"`
}

// KubeletNodeStats holds node-level stats from the Kubelet summary.
type KubeletNodeStats struct {
	NodeName string               `json:"nodeName"`
	Network  *KubeletNetworkStats `json:"network,omitempty"`
}

// KubeletPodStats holds per-pod stats from the Kubelet summary.
type KubeletPodStats struct {
	PodRef  KubeletPodRef        `json:"podRef"`
	Network *KubeletNetworkStats `json:"network,omitempty"`
}

// KubeletPodRef identifies a pod in the Kubelet summary response.
type KubeletPodRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// KubeletNetworkStats holds network interface statistics.
type KubeletNetworkStats struct {
	Interfaces []KubeletInterfaceStats `json:"interfaces,omitempty"`
}

// KubeletInterfaceStats holds per-interface network counters.
type KubeletInterfaceStats struct {
	Name     string  `json:"name"`
	RxBytes  *uint64 `json:"rxBytes,omitempty"`
	TxBytes  *uint64 `json:"txBytes,omitempty"`
	RxErrors *uint64 `json:"rxErrors,omitempty"`
	TxErrors *uint64 `json:"txErrors,omitempty"`
}
