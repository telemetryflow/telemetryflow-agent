// Package mocks provides test doubles — mock API client, mock collector,
// mock exporter, mock Kubernetes client, and mock logger — for use in unit
// and integration tests across the TelemetryFlow Agent.
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
package mocks

import (
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// NewFakeClientset creates a fake Kubernetes clientset with sample resources.
func NewFakeClientset() *fake.Clientset {
	return fake.NewClientset(
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
		// Events
		fakeEvent("default", "app-scheduled", "Normal", "Scheduled", "Pod", "app-abc123"),
		fakeEvent("default", "app-warning", "Warning", "FailedScheduling", "Pod", "app-def456"),
		fakeEvent("monitoring", "prometheus-started", "Normal", "Started", "Pod", "prometheus-0"),
		// Secrets
		fakeSecret("default", "app-secret"),
		fakeSecret("default", "tls-secret"),
		fakeSecret("monitoring", "prometheus-secret"),
		// ConfigMaps
		fakeConfigMap("default", "app-config"),
		fakeConfigMap("monitoring", "prometheus-config"),
		// Endpoints
		fakeEndpoints("default", "app-svc", []string{"10.0.1.1", "10.0.1.2"}, []string{"10.0.1.3"}, 8080),
		// Ingresses
		fakeIngress("default", "app-ingress"),
		// ResourceQuotas
		fakeResourceQuota("default", "default-quota"),
		// HorizontalPodAutoscalers
		fakeHPA("default", "app-hpa", "Deployment", "app", 2, 5, 3, 3),
		// PodDisruptionBudgets
		fakePDB("default", "app-pdb", 3, 3, 1, 3),
	)
}

// NewEmptyClientset returns an empty fake clientset (no resources).
func NewEmptyClientset() *fake.Clientset {
	return fake.NewClientset()
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
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "203.0.113.1"},
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
					Image: name + ":latest",
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
			Name:       name,
			Namespace:  namespace,
			Generation: 3,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.String, StrVal: "25%"},
					MaxSurge:       &intstr.IntOrString{Type: intstr.String, StrVal: "25%"},
				},
			},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "main", Image: name + ":latest"},
					},
				},
			},
		},
		Status: appsv1.DeploymentStatus{
			Replicas:            replicas,
			ReadyReplicas:       ready,
			AvailableReplicas:   available,
			UnavailableReplicas: unavailable,
			UpdatedReplicas:     replicas,
			ObservedGeneration:  3,
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
	fsMode := corev1.PersistentVolumeFilesystem
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: storageClass,
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse(capacity),
			},
			AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			VolumeMode:                    &fsMode,
			ClaimRef: &corev1.ObjectReference{
				Name:      "pvc-data-1",
				Namespace: "default",
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: phase},
	}
}

func fakePVC(namespace, name, capacity, storageClass string, phase corev1.PersistentVolumeClaimPhase) *corev1.PersistentVolumeClaim {
	fsMode := corev1.PersistentVolumeFilesystem
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: &storageClass,
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeName:       "pv-data-1",
			VolumeMode:       &fsMode,
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

func fakeEvent(namespace, name, evType, reason, kind, involvedName string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type:   evType,
		Reason: reason,
		InvolvedObject: corev1.ObjectReference{
			Kind: kind,
			Name: involvedName,
		},
		Source:         corev1.EventSource{Component: "kubelet"},
		Count:          1,
		Message:        reason + " event for " + involvedName,
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
	}
}

func fakeSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
	}
}

func fakeConfigMap(namespace, name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string]string{"key": "value"},
	}
}

func fakeEndpoints(namespace, name string, readyIPs, notReadyIPs []string, port int32) *corev1.Endpoints {
	var addresses []corev1.EndpointAddress
	for _, ip := range readyIPs {
		addresses = append(addresses, corev1.EndpointAddress{
			IP:       ip,
			NodeName: strPtr("worker-1"),
			TargetRef: &corev1.ObjectReference{
				Kind: "Pod",
				Name: "app-abc123",
			},
		})
	}
	var notReady []corev1.EndpointAddress
	for _, ip := range notReadyIPs {
		notReady = append(notReady, corev1.EndpointAddress{
			IP: ip,
		})
	}
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses:         addresses,
				NotReadyAddresses: notReady,
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: port, Protocol: corev1.ProtocolTCP},
				},
			},
		},
	}
}

func strPtr(s string) *string { return &s }

func fakeIngress(namespace, name string) *networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix
	ingressClass := "nginx"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": "web"},
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/rewrite-target": "/",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClass,
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "app-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
							},
						},
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"example.com"},
					SecretName: "tls-secret",
				},
			},
		},
	}
}

func fakeResourceQuota(namespace, name string) *corev1.ResourceQuota {
	return &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceRequestsCPU:    resource.MustParse("4"),
				corev1.ResourceRequestsMemory: resource.MustParse("8Gi"),
				corev1.ResourcePods:           resource.MustParse("20"),
			},
		},
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{
				corev1.ResourceRequestsCPU:    resource.MustParse("4"),
				corev1.ResourceRequestsMemory: resource.MustParse("8Gi"),
				corev1.ResourcePods:           resource.MustParse("20"),
			},
			Used: corev1.ResourceList{
				corev1.ResourceRequestsCPU:    resource.MustParse("1"),
				corev1.ResourceRequestsMemory: resource.MustParse("2Gi"),
				corev1.ResourcePods:           resource.MustParse("5"),
			},
		},
	}
}

func fakeHPA(namespace, name, targetKind, targetName string, minR, maxR, currentR, desiredR int32) *autoscalingv2.HorizontalPodAutoscaler {
	return &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				Kind: targetKind,
				Name: targetName,
			},
			MinReplicas: &minR,
			MaxReplicas: maxR,
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			CurrentReplicas: currentR,
			DesiredReplicas: desiredR,
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{Type: autoscalingv2.AbleToScale, Status: "True"},
				{Type: autoscalingv2.ScalingActive, Status: "True"},
				{Type: autoscalingv2.ScalingLimited, Status: "False"},
			},
		},
	}
}

func fakePDB(namespace, name string, currentHealthy, desiredHealthy, disruptionsAllowed, expectedPods int32) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			CurrentHealthy:     currentHealthy,
			DesiredHealthy:     desiredHealthy,
			DisruptionsAllowed: disruptionsAllowed,
			ExpectedPods:       expectedPods,
		},
	}
}
