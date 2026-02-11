package kubernetes

import "time"

// ClusterState is the full cluster snapshot sent to the TFO backend for sync.
type ClusterState struct {
	ClusterName     string            `json:"cluster_name"`
	ClusterProvider string            `json:"cluster_provider"`
	CollectedAt     time.Time         `json:"collected_at"`
	Nodes           []NodeState       `json:"nodes,omitempty"`
	Namespaces      []NamespaceState  `json:"namespaces,omitempty"`
	Pods            []PodState        `json:"pods,omitempty"`
	Deployments     []DeploymentState `json:"deployments,omitempty"`
	StatefulSets    []WorkloadState   `json:"statefulsets,omitempty"`
	DaemonSets      []WorkloadState   `json:"daemonsets,omitempty"`
	ReplicaSets     []WorkloadState   `json:"replicasets,omitempty"`
	Jobs            []WorkloadState   `json:"jobs,omitempty"`
	CronJobs        []WorkloadState   `json:"cronjobs,omitempty"`
	Services        []ServiceState    `json:"services,omitempty"`
	PVs             []PVState         `json:"pvs,omitempty"`
	PVCs            []PVCState        `json:"pvcs,omitempty"`
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

// DeploymentState represents a Kubernetes deployment.
type DeploymentState struct {
	Name                string            `json:"name"`
	Namespace           string            `json:"namespace"`
	Replicas            int32             `json:"replicas"`
	ReadyReplicas       int32             `json:"ready_replicas"`
	AvailableReplicas   int32             `json:"available_replicas"`
	UnavailableReplicas int32             `json:"unavailable_replicas"`
	Labels              map[string]string `json:"labels,omitempty"`
	Conditions          map[string]bool   `json:"conditions,omitempty"`
}

// NamespaceState represents a Kubernetes namespace.
type NamespaceState struct {
	Name   string            `json:"name"`
	Phase  string            `json:"phase"` // Active, Terminating
	Labels map[string]string `json:"labels,omitempty"`
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

// PVState represents a PersistentVolume.
type PVState struct {
	Name         string `json:"name"`
	StorageClass string `json:"storage_class,omitempty"`
	Capacity     int64  `json:"capacity"` // bytes
	Phase        string `json:"phase"`    // Available, Bound, Released, Failed
}

// PVCState represents a PersistentVolumeClaim.
type PVCState struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	StorageClass string `json:"storage_class,omitempty"`
	Capacity     int64  `json:"capacity"` // bytes
	Phase        string `json:"phase"`    // Pending, Bound, Lost
}
