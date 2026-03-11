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
	HPAs            []HPAState              `json:"hpas,omitempty"`
	PDBs            []PDBState              `json:"pdbs,omitempty"`
	PodLogs         []PodLogEntry           `json:"pod_logs,omitempty"`
}

// TaintState represents a single Kubernetes node taint.
type TaintState struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}

// NodeState represents a single Kubernetes node.
type NodeState struct {
	Name                        string            `json:"name"`
	Status                      string            `json:"status"` // Ready, NotReady
	Roles                       []string          `json:"roles,omitempty"`
	Labels                      map[string]string `json:"labels,omitempty"`
	KubeletVersion              string            `json:"kubelet_version,omitempty"`
	ContainerRuntime            string            `json:"container_runtime,omitempty"`
	OS                          string            `json:"os,omitempty"`
	Architecture                string            `json:"architecture,omitempty"`
	CPUCapacity                 int64             `json:"cpu_capacity"`                  // millicores
	CPUAllocatable              int64             `json:"cpu_allocatable"`               // millicores
	MemoryCapacity              int64             `json:"memory_capacity"`               // bytes
	MemoryAllocatable           int64             `json:"memory_allocatable"`            // bytes
	EphemeralStorageCapacity    int64             `json:"ephemeral_storage_capacity"`    // bytes
	EphemeralStorageAllocatable int64             `json:"ephemeral_storage_allocatable"` // bytes
	PodsCapacity                int64             `json:"pods_capacity"`
	PodsCount                   int64             `json:"pods_count"`
	Conditions                  map[string]bool   `json:"conditions,omitempty"`               // condition → true/false
	CPUUsage                    *float64          `json:"cpu_usage,omitempty"`                // cores (from metrics-server)
	MemoryUsage                 *int64            `json:"memory_usage,omitempty"`             // bytes (from metrics-server)
	CPUUsageNanoseconds         *uint64           `json:"cpu_usage_ns,omitempty"`             // cumulative CPU nanoseconds (Kubelet summary)
	MemoryWorkingSetBytes       *uint64           `json:"memory_working_set_bytes,omitempty"` // memory pressure indicator (Kubelet summary)
	MemoryPageFaults            *uint64           `json:"memory_page_faults,omitempty"`       // cumulative page faults (Kubelet summary)
	MemoryMajorPageFaults       *uint64           `json:"memory_major_page_faults,omitempty"` // cumulative major page faults (Kubelet summary)
	FSUsedBytes                 *uint64           `json:"fs_used_bytes,omitempty"`            // filesystem used bytes (Kubelet summary)
	FSCapacityBytes             *uint64           `json:"fs_capacity_bytes,omitempty"`        // filesystem capacity bytes (Kubelet summary)
	ImageFSUsedBytes            *uint64           `json:"image_fs_used_bytes,omitempty"`      // container image layer disk usage (Kubelet summary)
	ImageFSCapacityBytes        *uint64           `json:"image_fs_capacity_bytes,omitempty"`  // container image fs capacity (Kubelet summary)
	NetworkRxBytes              *uint64           `json:"network_rx_bytes,omitempty"`         // cumulative network rx bytes (Kubelet summary)
	NetworkTxBytes              *uint64           `json:"network_tx_bytes,omitempty"`         // cumulative network tx bytes (Kubelet summary)
	InternalIP                  string            `json:"internal_ip,omitempty"`
	ExternalIP                  string            `json:"external_ip,omitempty"`
	Taints                      []TaintState      `json:"taints,omitempty"`
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
	Conditions   map[string]bool   `json:"conditions,omitempty"` // PodScheduled, ContainersReady, Initialized, Ready
}

// ContainerState represents a container within a pod.
type ContainerState struct {
	Name                    string   `json:"name"`
	Image                   string   `json:"image,omitempty"`
	Ready                   bool     `json:"ready"`
	RestartCount            int32    `json:"restart_count"`
	Status                  string   `json:"status"`                              // running, waiting, terminated
	CPURequest              int64    `json:"cpu_request,omitempty"`               // millicores
	CPULimit                int64    `json:"cpu_limit,omitempty"`                 // millicores
	MemoryRequest           int64    `json:"memory_request,omitempty"`            // bytes
	MemoryLimit             int64    `json:"memory_limit,omitempty"`              // bytes
	EphemeralStorageRequest int64    `json:"ephemeral_storage_request,omitempty"` // bytes
	EphemeralStorageLimit   int64    `json:"ephemeral_storage_limit,omitempty"`   // bytes
	CPUUsage                *float64 `json:"cpu_usage,omitempty"`                 // cores (metrics-server)
	MemoryUsage             *int64   `json:"memory_usage,omitempty"`              // bytes (metrics-server)
	MemoryWorkingSetBytes   *int64   `json:"memory_working_set_bytes,omitempty"`  // bytes (Kubelet summary — memory pressure indicator)
	EphemeralStorageUsage   *int64   `json:"ephemeral_storage_usage,omitempty"`   // bytes (Kubelet summary: rootfs+logs)
	// Last termination details (kube-state-metrics equivalent)
	LastTerminationReason string `json:"last_termination_reason,omitempty"` // OOMKilled, Error, Completed, etc.
	LastTerminationCode   *int32 `json:"last_termination_code,omitempty"`   // exit code of last terminated instance
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

// HPAState represents a HorizontalPodAutoscaler resource.
type HPAState struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	ScaleTargetKind string            `json:"scale_target_kind"` // Deployment, StatefulSet, etc.
	ScaleTargetName string            `json:"scale_target_name"`
	MinReplicas     int32             `json:"min_replicas"`
	MaxReplicas     int32             `json:"max_replicas"`
	CurrentReplicas int32             `json:"current_replicas"`
	DesiredReplicas int32             `json:"desired_replicas"`
	Conditions      map[string]bool   `json:"conditions,omitempty"` // AbleToScale, ScalingActive, ScalingLimited
	Labels          map[string]string `json:"labels,omitempty"`
}

// PDBState represents a PodDisruptionBudget resource.
type PDBState struct {
	Name               string            `json:"name"`
	Namespace          string            `json:"namespace"`
	CurrentHealthy     int32             `json:"current_healthy"`
	DesiredHealthy     int32             `json:"desired_healthy"`
	ExpectedPods       int32             `json:"expected_pods"`
	DisruptionsAllowed int32             `json:"disruptions_allowed"`
	Labels             map[string]string `json:"labels,omitempty"`
}

// PodLogEntry holds a tail of recent log lines for a single container.
type PodLogEntry struct {
	Namespace     string    `json:"namespace"`
	PodName       string    `json:"pod_name"`
	ContainerName string    `json:"container_name"`
	Lines         []string  `json:"lines,omitempty"`
	CollectedAt   time.Time `json:"collected_at"`
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
	CPU      *KubeletCPUStats     `json:"cpu,omitempty"`
	Memory   *KubeletMemoryStats  `json:"memory,omitempty"`
	Network  *KubeletNetworkStats `json:"network,omitempty"`
	Fs       *KubeletFSStats      `json:"fs,omitempty"`
	Runtime  *KubeletRuntimeStats `json:"runtime,omitempty"`
}

// KubeletRuntimeStats holds container runtime stats (image filesystem) from the Kubelet summary.
type KubeletRuntimeStats struct {
	ImageFs *KubeletFSStats `json:"imageFs,omitempty"`
}

// KubeletCPUStats holds CPU usage stats from the Kubelet summary.
type KubeletCPUStats struct {
	UsageNanoCores       *uint64 `json:"usageNanoCores,omitempty"`       // current CPU usage in nanocores
	UsageCoreNanoSeconds *uint64 `json:"usageCoreNanoSeconds,omitempty"` // cumulative CPU nanoseconds
}

// KubeletMemoryStats holds memory stats from the Kubelet summary.
type KubeletMemoryStats struct {
	UsageBytes      *uint64 `json:"usageBytes,omitempty"`
	WorkingSetBytes *uint64 `json:"workingSetBytes,omitempty"` // memory under active use (excludes reclaimable cache)
	PageFaults      *uint64 `json:"pageFaults,omitempty"`
	MajorPageFaults *uint64 `json:"majorPageFaults,omitempty"`
}

// KubeletPodStats holds per-pod stats from the Kubelet summary.
type KubeletPodStats struct {
	PodRef     KubeletPodRef           `json:"podRef"`
	Network    *KubeletNetworkStats    `json:"network,omitempty"`
	Containers []KubeletContainerStats `json:"containers,omitempty"`
}

// KubeletContainerStats holds per-container stats from the Kubelet summary.
// Ephemeral storage usage = Rootfs.UsedBytes + Logs.UsedBytes.
type KubeletContainerStats struct {
	Name   string              `json:"name"`
	CPU    *KubeletCPUStats    `json:"cpu,omitempty"`
	Memory *KubeletMemoryStats `json:"memory,omitempty"`
	Rootfs *KubeletFSStats     `json:"rootfs,omitempty"`
	Logs   *KubeletFSStats     `json:"logs,omitempty"`
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

// KubeletFSStats holds filesystem statistics from the Kubelet summary API.
type KubeletFSStats struct {
	CapacityBytes  *uint64 `json:"capacityBytes,omitempty"`
	UsedBytes      *uint64 `json:"usedBytes,omitempty"`
	AvailableBytes *uint64 `json:"availableBytes,omitempty"`
}
