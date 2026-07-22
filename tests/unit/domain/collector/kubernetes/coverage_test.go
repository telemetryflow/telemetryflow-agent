// Package kubernetes_test contains additional coverage-focused unit tests for
// the Kubernetes collector, exercising the full Collect pipeline with all
// sub-collectors enabled, the metrics-server + kubelet fallback paths, the
// direct kubelet HTTP fetcher (via httptest), cluster-state build, and error
// paths — all via the fake clientset and httptest, no live cluster.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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
package kubernetes_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func int64Ptr(v int64) *int64 { return &v }

// fullConfig enables every sub-collector so a single Collect exercises them all.
func fullConfig() config.KubernetesCollectorConfig {
	return config.KubernetesCollectorConfig{
		Enabled:             true,
		Interval:            1 * time.Second,
		Nodes:               true,
		Pods:                true,
		Deployments:         true,
		NamespacesCollect:   true,
		Storage:             true,
		Services:            true,
		Workloads:           true,
		Events:              true,
		ResourceCounts:      true,
		HPA:                 true,
		PDB:                 true,
		Network:             true,
		MetricsAPI:          true,
		PodLogs:             true,
		NodeLogs:            false,
		ResourceQuotas:      true,
		LimitRanges:         true,
		PodConditions:       true,
		NodeTaints:          true,
		WorkloadGenerations: true,
		// ApiServerMetrics / CoreDNSMetrics / NodeLogs use the API-server
		// RESTClient proxy, which the fake clientset cannot serve. They are
		// covered separately via a real clientset over httptest (see
		// proxy_test.go).
		ApiServerMetrics:  false,
		CoreDNSMetrics:    false,
		SyncToBackend:     false,
		SyncInterval:      60 * time.Second,
		ClusterName:       "test-cluster",
		ClusterProvider:   "self-managed",
		ExcludeNamespaces: []string{"kube-system"},
	}
}

func u64(v uint64) *uint64 { return &v }

// richClientset returns a fake clientset with a broad set of resources plus the
// describe-level richness (volumes, init containers, probes, tolerations,
// conditions, taints) needed to exercise the extraction helpers.
func richClientset() *fake.Clientset {
	hostPathType := corev1.HostPathDirectory
	probe := &corev1.Probe{
		InitialDelaySeconds: 5,
		PeriodSeconds:       10,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080), Scheme: corev1.URISchemeHTTP},
		},
	}
	tcpProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(9090)}},
	}
	execProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"cat", "/ready"}}},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-a",
			Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: "node-role.kubernetes.io/control-plane", Value: "", Effect: corev1.TaintEffectNoSchedule},
				{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoExecute},
			},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.31.2", Architecture: "amd64", OSImage: "Ubuntu"},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.10"},
				{Type: corev1.NodeHostName, Address: "node-a"},
			},
			Images: []corev1.ContainerImage{
				{Names: []string{"nginx:latest"}, SizeBytes: 1000},
			},
		},
	}

	richPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rich-pod",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rich-rs"}},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			Tolerations: []corev1.Toleration{
				{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu", Effect: corev1.TaintEffectNoExecute, TolerationSeconds: int64Ptr(30)},
			},
			InitContainers: []corev1.Container{
				{
					Name:    "init",
					Image:   "busybox:1.36",
					Command: []string{"sh", "-c", "echo init"},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("20m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
					},
					VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: true, SubPath: "sub"}},
				},
			},
			Containers: []corev1.Container{
				{
					Name:           "main",
					Image:          "nginx:1.27",
					LivenessProbe:  probe,
					ReadinessProbe: tcpProbe,
					StartupProbe:   execProbe,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("1Gi")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("256Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("2Gi")},
					},
					VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/var/data"}},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-data-1"}}},
				{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}}},
				{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "app-secret"}}},
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
				{Name: "hp", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log", Type: &hostPathType}}},
				{Name: "proj", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}}},
				{Name: "csi", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "ebs.csi.aws.com"}}},
			},
		},
		Status: corev1.PodStatus{
			Phase:     corev1.PodRunning,
			QOSClass:  corev1.PodQOSBurstable,
			PodIP:     "10.1.1.1",
			StartTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
				{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
				{Type: corev1.ContainersReady, Status: corev1.ConditionFalse},
				{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init", Ready: true, RestartCount: 0, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}}},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "main", Ready: true, RestartCount: 2,
					State:                corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
					LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137}},
				},
			},
		},
	}
	richPod.CreationTimestamp = metav1.Now()

	pendingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pending-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "c", Image: "img"}}},
		Status: corev1.PodStatus{
			Phase:  corev1.PodPending,
			Reason: "Unschedulable",
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c", Ready: false, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}},
			},
		},
	}

	// A second, NotReady node with no addresses and >50 images to cover
	// nodeReady=false, extractNodeAddresses(empty)->nil, and image truncation.
	manyImages := make([]corev1.ContainerImage, 60)
	for i := range manyImages {
		manyImages[i] = corev1.ContainerImage{Names: []string{"img"}, SizeBytes: int64(i)}
	}
	nodeB := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Images: manyImages,
		},
	}

	// Pods covering the remaining phases and an unknown container state.
	succeededPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "succeeded-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "c", Image: "img"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	failedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "c", Image: "img"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error"}}},
			},
		},
	}
	unknownPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "unknown-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-b", Containers: []corev1.Container{{Name: "c", Image: "img"}}},
		Status: corev1.PodStatus{
			Phase:             corev1.PodUnknown,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "c"}}, // no state -> "unknown"
		},
	}

	// CoreDNS pods in kube-system for discovery coverage.
	corednsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coredns-abc",
			Namespace: "kube-system",
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}

	replicas := int32(2)
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rich-rs", Namespace: "default"},
		Spec:       appsv1.ReplicaSetSpec{Replicas: &replicas},
		Status:     appsv1.ReplicaSetStatus{Replicas: 2, ReadyReplicas: 2, AvailableReplicas: 2},
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "rich-job", Namespace: "default"},
		Status:     batchv1.JobStatus{Active: 1, Succeeded: 1},
	}
	cron := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "rich-cron", Namespace: "default"},
		Spec:       batchv1.CronJobSpec{Schedule: "* * * * *"},
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rich-sts", Namespace: "default", Generation: 4},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
		Status:     appsv1.StatefulSetStatus{Replicas: 2, ReadyReplicas: 2, ObservedGeneration: 4},
	}
	maxUnavail := intstr.FromString("25%")
	maxSurge := intstr.FromInt32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "rich-dep", Namespace: "default", Generation: 2, CreationTimestamp: metav1.Now(), Labels: map[string]string{"app": "rich"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "rich"}},
			Strategy: appsv1.DeploymentStrategy{
				Type:          appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: &maxUnavail, MaxSurge: &maxSurge},
			},
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "nginx"}}}},
		},
		Status: appsv1.DeploymentStatus{
			Replicas: 2, ReadyReplicas: 2, AvailableReplicas: 2, UpdatedReplicas: 2, ObservedGeneration: 2,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue},
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse},
			},
		},
	}

	tcp := corev1.ProtocolTCP
	npPort := intstr.FromInt32(8080)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "default", Labels: map[string]string{"app": "web"}},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "db"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &npPort}},
					From: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
						{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}},
						{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}}},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{{Port: &npPort}},
					To: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "cache"}}},
						{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "b"}}},
						{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}},
					},
				},
			},
		},
	}

	limitRange := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: "lr", Namespace: "default"},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{
				{
					Type:           corev1.LimitTypeContainer,
					Default:        corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
					DefaultRequest: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
					Max:            corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")},
					Min:            corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")},
				},
			},
		},
	}

	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "q", Namespace: "default"},
		Spec:       corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{corev1.ResourcePods: resource.MustParse("10"), corev1.ResourceRequestsCPU: resource.MustParse("4")}},
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{
				corev1.ResourcePods:           resource.MustParse("10"),
				corev1.ResourceRequestsCPU:    resource.MustParse("4"),
				corev1.ResourceRequestsMemory: resource.MustParse("8Gi"),
			},
			Used: corev1.ResourceList{
				corev1.ResourcePods:           resource.MustParse("3"),
				corev1.ResourceRequestsCPU:    resource.MustParse("1"),
				corev1.ResourceRequestsMemory: resource.MustParse("2Gi"),
			},
		},
	}

	fsMode := corev1.PersistentVolumeFilesystem
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-data-1", CreationTimestamp: metav1.Now(), Labels: map[string]string{"tier": "gold"}, Annotations: map[string]string{"note": "x"}},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			StorageClassName:              "standard",
			AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			VolumeMode:                    &fsMode,
			MountOptions:                  []string{"noatime"},
			ClaimRef:                      &corev1.ObjectReference{Name: "pvc-data-1", Namespace: "default"},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-data-1", Namespace: "default", CreationTimestamp: metav1.Now(), Labels: map[string]string{"tier": "gold"}},
		Spec: corev1.PersistentVolumeClaimSpec{
			VolumeName:  "pv-data-1",
			VolumeMode:  &fsMode,
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
				Limits:   corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("20Gi")},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase:    corev1.ClaimBound,
			Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			Conditions: []corev1.PersistentVolumeClaimCondition{
				{Type: corev1.PersistentVolumeClaimResizing, Status: corev1.ConditionTrue, Reason: "Resizing", Message: "growing"},
			},
		},
	}
	// Second PVC without status.Capacity to exercise the requested-capacity fallback.
	pvc2 := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-pending", Namespace: "default"},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("5Gi")}},
		},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "app-svc", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.0.0.5"},
	}
	// LoadBalancer service with ports, external IPs and LB ingress (IP + hostname).
	lbSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "lb-svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Type:        corev1.ServiceTypeLoadBalancer,
			ClusterIP:   "10.0.0.9",
			ExternalIPs: []string{"192.0.2.10"},
			Ports:       []corev1.ServicePort{{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, NodePort: 30080, TargetPort: intstr.FromInt32(8080)}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "203.0.113.5"}, {Hostname: "lb.example.com"}}},
		},
	}
	endpoints := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "app-svc", Namespace: "default"},
		Subsets: []corev1.EndpointSubset{{
			Addresses:         []corev1.EndpointAddress{{IP: "10.1.1.2", NodeName: strPtr2("node-a"), TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "rich-pod"}}},
			NotReadyAddresses: []corev1.EndpointAddress{{IP: "10.1.1.3", NodeName: strPtr2("node-a"), TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "pending-pod"}}},
			Ports:             []corev1.EndpointPort{{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP}},
		}},
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "app-config", Namespace: "default"}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: "default"}, Type: corev1.SecretTypeOpaque}
	event := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "default"},
		Type:           "Warning",
		Reason:         "BackOff",
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "rich-pod"},
		Count:          3,
		LastTimestamp:  metav1.Now(),
	}

	// Node with no Ready condition to cover nodeReady's final return-false path.
	nodeC := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-c"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse}},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1"),
				corev1.ResourceMemory: resource.MustParse("2Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1"),
				corev1.ResourceMemory: resource.MustParse("2Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.12"}},
		},
	}

	pathTypePrefix := networkingv1.PathTypePrefix
	// Ingress using annotation-based class, both named and numbered service
	// ports, TLS, and a LoadBalancer status.
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "app-ingress",
			Namespace:   "default",
			Annotations: map[string]string{"kubernetes.io/ingress.class": "nginx"},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{
						{Path: "/named", PathType: &pathTypePrefix, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "app-svc", Port: networkingv1.ServiceBackendPort{Name: "http"}}}},
						{Path: "/num", PathType: &pathTypePrefix, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "app-svc", Port: networkingv1.ServiceBackendPort{Number: 8080}}}},
					},
				}},
			}},
			TLS: []networkingv1.IngressTLS{{Hosts: []string{"example.com"}, SecretName: "tls-secret"}},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{Ingress: []networkingv1.IngressLoadBalancerIngress{{IP: "203.0.113.7"}, {Hostname: "ing.example.com"}}},
		},
	}

	return fake.NewClientset(
		node, nodeB, nodeC, richPod, pendingPod, succeededPod, failedPod, unknownPod, corednsPod,
		rs, job, cron, sts, dep, np,
		limitRange, quota, pv, pvc, pvc2, ns, svc, lbSvc, endpoints, ingress, cm, sec, event,
	)
}

func strPtr2(s string) *string { return &s }

// fakeKubeletSummary returns a proxy fetcher producing node + pod stats with
// network and volume data for the network/volume/ephemeral paths.
func fakeKubeletFetcher() k8scollector.KubeletProxyFunc {
	return func(_ context.Context, nodeName string) (*k8scollector.KubeletSummary, error) {
		return &k8scollector.KubeletSummary{
			Node: k8scollector.KubeletNodeStats{
				NodeName: nodeName,
				CPU:      &k8scollector.KubeletCPUStats{UsageNanoCores: u64(500000000), UsageCoreNanoSeconds: u64(123456789)},
				Memory:   &k8scollector.KubeletMemoryStats{WorkingSetBytes: u64(1 << 30), PageFaults: u64(10), MajorPageFaults: u64(1)},
				Fs:       &k8scollector.KubeletFSStats{UsedBytes: u64(2000), CapacityBytes: u64(10000)},
				Runtime:  &k8scollector.KubeletRuntimeStats{ImageFs: &k8scollector.KubeletFSStats{UsedBytes: u64(3000), CapacityBytes: u64(20000)}},
				Network: &k8scollector.KubeletNetworkStats{
					Interfaces: []k8scollector.KubeletInterfaceStats{
						{Name: "eth0", RxBytes: u64(1000), TxBytes: u64(2000), RxErrors: u64(1), TxErrors: u64(2)},
					},
				},
			},
			Pods: []k8scollector.KubeletPodStats{
				{
					PodRef: k8scollector.KubeletPodRef{Name: "rich-pod", Namespace: "default"},
					Network: &k8scollector.KubeletNetworkStats{
						Interfaces: []k8scollector.KubeletInterfaceStats{
							{Name: "eth0", RxBytes: u64(3000), TxBytes: u64(4000), RxErrors: u64(2), TxErrors: u64(3)},
						},
					},
					Containers: []k8scollector.KubeletContainerStats{
						{
							Name:   "main",
							Memory: &k8scollector.KubeletMemoryStats{WorkingSetBytes: u64(1000)},
							Rootfs: &k8scollector.KubeletFSStats{UsedBytes: u64(500)},
							Logs:   &k8scollector.KubeletFSStats{UsedBytes: u64(100)},
						},
					},
					Volumes: []k8scollector.KubeletVolumeStats{
						{
							Name:          "data",
							PvcRef:        &k8scollector.KubeletPvcRef{Name: "pvc-data-1", Namespace: "default"},
							UsedBytes:     u64(4096),
							CapacityBytes: u64(10240),
							InodesUsed:    u64(10),
							// AvailableBytes and Inodes intentionally left nil so
							// the merge with rich-pod-2 fills them in buildPVIOStats.
						},
					},
				},
				// Second pod mounting the same PVC with a PvcRef missing the
				// namespace and only partial fields set — exercises the merge
				// path in buildPVIOStats and the namespace-fallback branch.
				{
					PodRef: k8scollector.KubeletPodRef{Name: "rich-pod-2", Namespace: "default"},
					Volumes: []k8scollector.KubeletVolumeStats{
						{Name: "data", PvcRef: &k8scollector.KubeletPvcRef{Name: "pvc-data-1"}, AvailableBytes: u64(6144), Inodes: u64(100), InodesUsed: u64(20)},
					},
				},
				// kube-system pod should be filtered out.
				{PodRef: k8scollector.KubeletPodRef{Name: "kube-dns", Namespace: "kube-system"}, Network: &k8scollector.KubeletNetworkStats{Interfaces: []k8scollector.KubeletInterfaceStats{{Name: "eth0", RxBytes: u64(9)}}}},
			},
		}, nil
	}
}

const cadvisorThrottleText = `# HELP container_cpu_cfs_throttled_seconds_total Throttled seconds.
# TYPE container_cpu_cfs_throttled_seconds_total counter
container_cpu_cfs_throttled_seconds_total{namespace="default",pod="rich-pod",container="main"} 12.5
container_cpu_cfs_throttled_seconds_total{namespace="default",pod="rich-pod",container="POD"} 0.1
container_cpu_cfs_throttled_seconds_total{namespace="",pod="",container=""} 0.2
`

func fakeCAdvisorFetcher() k8scollector.CAdvisorProxyFunc {
	return func(_ context.Context, _ string) ([]byte, error) {
		return []byte(cadvisorThrottleText), nil
	}
}

func TestCollectAllSubCollectors(t *testing.T) {
	logger := zap.NewNop()
	cs := richClientset()
	mc := realMetricsClientOverHTTP(t)
	cfg := fullConfig()

	coll := k8scollector.NewKubernetesCollectorForTest(cfg, cs, mc, logger)
	coll.SetKubeletFetcher(fakeKubeletFetcher())
	coll.SetCAdvisorFetcher(fakeCAdvisorFetcher())

	ctx := context.Background()

	// First cycle populates lastState.
	metrics, err := coll.Collect(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, metrics)

	// Second cycle exercises the collectors that read lastState
	// (node taints, pod conditions, workload generations).
	metrics, err = coll.Collect(ctx)
	require.NoError(t, err)

	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
	}

	// Usage metrics from metrics-server.
	assert.True(t, names["k8s.node.cpu.usage"], "expected node cpu usage from metrics-server")
	assert.True(t, names["k8s.pod.container.cpu_usage"], "expected container cpu usage")
	// Network aggregation from kubelet summary.
	assert.True(t, names["k8s.namespace.network.receive_bytes"])
	// Volume stats from kubelet summary.
	assert.True(t, names["k8s.volume.used_bytes"])
	// Resource quota + limit range.
	assert.True(t, names["k8s.resourcequota.hard"])
	assert.True(t, names["k8s.limitrange.default"])
	// Node taints + pod conditions (from lastState on 2nd cycle).
	assert.True(t, names["k8s.node.taint"])
	assert.True(t, names["k8s.pod.condition"])
	// Workload generations.
	assert.True(t, names["k8s.deployment.metadata_generation"])
	assert.True(t, names["k8s.statefulset.metadata_generation"])

	state := coll.LastClusterState()
	require.NotNil(t, state)
	assert.NotEmpty(t, state.NetworkStats)
	assert.NotEmpty(t, state.NetworkPolicies)
	assert.NotEmpty(t, state.PVIOStats)

	// Accessor coverage.
	assert.Equal(t, "test-cluster", coll.ClusterName())
	assert.Equal(t, "self-managed", coll.ClusterProvider())
	assert.NotNil(t, coll.Clientset())
}

func TestConvertKubeletSummary(t *testing.T) {
	summary := &k8scollector.KubeletDirectSummary{
		Node: k8scollector.NodeStats{
			NodeName: "node-a",
			CPU:      &k8scollector.CPUStats{UsageNanoCores: u64(2000000000)},
			Memory:   &k8scollector.MemStats{WorkingSetBytes: u64(2 << 30)},
		},
		Pods: []k8scollector.PodStats{
			{
				PodRef: k8scollector.PodReference{Name: "p", Namespace: "default"},
				Containers: []k8scollector.ContainerStats{
					{Name: "c", CPU: &k8scollector.CPUStats{UsageNanoCores: u64(1000000000)}, Memory: &k8scollector.MemStats{WorkingSetBytes: u64(1024)}},
				},
			},
		},
	}
	metrics := k8scollector.ConvertKubeletSummaryExported(summary, "test-cluster", "node-a")
	require.NotEmpty(t, metrics)

	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
	}
	assert.True(t, names["k8s.node.cpu.usage"])
	assert.True(t, names["k8s.node.memory.usage"])
	assert.True(t, names["k8s.pod.container.cpu_usage"])
	assert.True(t, names["k8s.pod.container.memory_usage"])
}

func TestParseCPUThrottleMetrics(t *testing.T) {
	out := k8scollector.ParseCPUThrottleMetricsExported([]byte(cadvisorThrottleText), zap.NewNop())
	require.Contains(t, out, "default/rich-pod/main")
	assert.Equal(t, 12.5, out["default/rich-pod/main"])
	// POD infra container and empty identifiers are skipped.
	assert.NotContains(t, out, "default/rich-pod/POD")

	// Malformed input returns an empty map without panicking.
	empty := k8scollector.ParseCPUThrottleMetricsExported([]byte("not-prometheus\x00"), zap.NewNop())
	assert.Empty(t, empty)
}

func TestReadLines(t *testing.T) {
	in := "line1\n\n  \nline2\nline3\nline4\n"
	lines := k8scollector.ReadLinesExported(strings.NewReader(in), 2)
	assert.Equal(t, []string{"line1", "line2"}, lines)

	all := k8scollector.ReadLinesExported(strings.NewReader(in), 100)
	assert.Equal(t, []string{"line1", "line2", "line3", "line4"}, all)
}

func TestCollectCoreDNSMetricsNoPods(t *testing.T) {
	// Empty clientset -> no CoreDNS pods discovered -> error.
	empty := fake.NewClientset()
	_, err := k8scollector.CollectCoreDNSMetricsExported(context.Background(), empty, "", zap.NewNop())
	require.Error(t, err)
}

// erroringFetcher returns a kubelet proxy fetcher that always errors.
func erroringFetcher() k8scollector.KubeletProxyFunc {
	return func(_ context.Context, _ string) (*k8scollector.KubeletSummary, error) {
		return nil, assertErr
	}
}

var assertErr = &listError{"boom"}

type listError struct{ msg string }

func (e *listError) Error() string { return e.msg }

// TestCollectListErrorsAreHandled injects list failures on every resource so the
// per-collector error/warn branches in Collect are exercised. Collect must still
// succeed (errors are logged, not propagated).
func TestCollectListErrorsAreHandled(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, assertErr
	})

	cfg := fullConfig()
	coll := k8scollector.NewKubernetesCollectorForTest(cfg, cs, nil, zap.NewNop())
	coll.SetKubeletFetcher(erroringFetcher())
	coll.SetCAdvisorFetcher(func(_ context.Context, _ string) ([]byte, error) { return nil, assertErr })

	_, err := coll.Collect(context.Background())
	require.NoError(t, err)
}

func TestParseQuantityStringHelpers(t *testing.T) {
	assert.InDelta(t, 0.5, k8scollector.ParseQuantityStringExported("500m"), 1e-9)
	assert.Equal(t, float64(0), k8scollector.ParseQuantityStringExported("not-a-qty"))
	assert.Equal(t, float64(1024), k8scollector.ParseQuantityStringBytesExported("1Ki"))
	assert.Equal(t, float64(0), k8scollector.ParseQuantityStringBytesExported("bad"))
	assert.Equal(t, float64(7), k8scollector.ParseQuantityStringValueExported("7"))
	assert.Equal(t, float64(0), k8scollector.ParseQuantityStringValueExported("bad"))
}

func TestExtractProbe(t *testing.T) {
	assert.Nil(t, k8scollector.ExtractProbeExported(nil))

	grpc := &corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 5000}}}
	ps := k8scollector.ExtractProbeExported(grpc)
	require.NotNil(t, ps)
	assert.Equal(t, "grpc", ps.Type)

	// Probe with no handler set -> Type stays empty.
	empty := k8scollector.ExtractProbeExported(&corev1.Probe{})
	require.NotNil(t, empty)
	assert.Equal(t, "", empty.Type)
}

// TestCollectWithErroringFetchers exercises the per-node fetch error branches in
// pod ephemeral-storage, CPU-throttle, network, and volume-stats collection when
// the pod list itself succeeds but the kubelet/cAdvisor fetchers fail.
func TestCollectWithErroringFetchers(t *testing.T) {
	coll := k8scollector.NewKubernetesCollectorForTest(fullConfig(), richClientset(), nil, zap.NewNop())
	coll.SetKubeletFetcher(erroringFetcher())
	coll.SetCAdvisorFetcher(func(_ context.Context, _ string) ([]byte, error) { return nil, assertErr })

	_, err := coll.Collect(context.Background())
	require.NoError(t, err)
}
