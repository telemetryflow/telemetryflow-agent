// Package mocks provides test helpers for Kubernetes testing.
package mocks

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// NewFakeClientset creates a fake Kubernetes clientset with sample resources.
func NewFakeClientset() *fake.Clientset {
	return fake.NewSimpleClientset(
		fakeNode("worker-1", true, "4", "8Gi"),
		fakeNode("worker-2", true, "8", "16Gi"),
		fakeNode("worker-3", false, "4", "8Gi"),
		fakePod("default", "app-abc123", "worker-1", corev1.PodRunning, "100m", "128Mi"),
		fakePod("default", "app-def456", "worker-2", corev1.PodRunning, "200m", "256Mi"),
		fakePod("monitoring", "prometheus-0", "worker-1", corev1.PodRunning, "500m", "512Mi"),
		fakePod("kube-system", "kube-dns-xxx", "worker-1", corev1.PodRunning, "50m", "64Mi"),
		fakeDeployment("default", "app", 3, 3, 3, 0),
		fakeDeployment("monitoring", "prometheus", 1, 1, 1, 0),
		fakeNamespace("default", corev1.NamespaceActive),
		fakeNamespace("monitoring", corev1.NamespaceActive),
		fakeNamespace("kube-system", corev1.NamespaceActive),
		fakeService("default", "app-svc", corev1.ServiceTypeClusterIP),
		fakePV("pv-data-1", "10Gi", "standard", corev1.VolumeBound),
		fakePVC("default", "pvc-data-1", "10Gi", "standard", corev1.ClaimBound),
		fakeStatefulSet("default", "redis", 3, 3, 3),
		fakeDaemonSet("monitoring", "node-exporter", 3, 3, 3),
	)
}

// NewEmptyClientset returns an empty fake clientset (no resources).
func NewEmptyClientset() *fake.Clientset {
	return fake.NewSimpleClientset()
}

func fakeNode(name string, ready bool, cpu, memory string) *corev1.Node {
	condStatus := corev1.ConditionFalse
	if ready {
		condStatus = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/hostname":         name,
				"node-role.kubernetes.io/worker": "",
			},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: condStatus},
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(memory),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(memory),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			NodeInfo: corev1.NodeSystemInfo{
				KubeletVersion:          "v1.31.2",
				ContainerRuntimeVersion: "containerd://1.7.0",
				OSImage:                 "Ubuntu 22.04 LTS",
				Architecture:            "amd64",
			},
		},
	}
}

func fakePod(namespace, name, node string, phase corev1.PodPhase, cpuReq, memReq string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app": name,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: node,
			Containers: []corev1.Container{
				{
					Name:  "main",
					Image: "app:latest",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse(cpuReq),
							corev1.ResourceMemory: resource.MustParse(memReq),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse(cpuReq),
							corev1.ResourceMemory: resource.MustParse(memReq),
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: phase,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "main",
					Ready:        phase == corev1.PodRunning,
					RestartCount: 0,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{},
					},
				},
			},
		},
	}
}

func fakeDeployment(namespace, name string, replicas, ready, available, unavailable int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:            replicas,
			ReadyReplicas:       ready,
			AvailableReplicas:   available,
			UnavailableReplicas: unavailable,
		},
	}
}

func fakeNamespace(name string, phase corev1.NamespacePhase) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NamespaceStatus{Phase: phase},
	}
}

func fakeService(namespace, name string, svcType corev1.ServiceType) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:      svcType,
			ClusterIP: "10.0.0.1",
		},
	}
}

func fakePV(name, capacity, storageClass string, phase corev1.PersistentVolumePhase) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: storageClass,
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse(capacity),
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: phase},
	}
}

func fakePVC(namespace, name, capacity, storageClass string, phase corev1.PersistentVolumeClaimPhase) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: &storageClass,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(capacity),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: phase,
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse(capacity),
			},
		},
	}
}

func fakeStatefulSet(namespace, name string, replicas, current, ready int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
		Status: appsv1.StatefulSetStatus{
			Replicas:        replicas,
			CurrentReplicas: current,
			ReadyReplicas:   ready,
		},
	}
}

func fakeDaemonSet(namespace, name string, desired, current, ready int32) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: desired,
			CurrentNumberScheduled: current,
			NumberReady:            ready,
		},
	}
}
