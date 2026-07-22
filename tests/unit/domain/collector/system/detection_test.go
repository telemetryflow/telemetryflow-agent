// Package system_test contains unit tests for the corresponding collector module.
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

package system_test

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

// TestDetectK8sProviderEnv exercises every environment-variable-driven branch
// of detectK8sProvider. t.Setenv isolates each case and restores state.
func TestDetectK8sProviderEnv(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantK8s  bool
		wantProv string
	}{
		{"eks", map[string]string{"AWS_REGION": "us-east-1"}, true, "eks"},
		{"eks_cluster", map[string]string{"EKS_CLUSTER_NAME": "c"}, true, "eks"},
		{"gke", map[string]string{"GOOGLE_CLOUD_PROJECT": "p"}, true, "gke"},
		{"gke_cluster", map[string]string{"GKE_CLUSTER_NAME": "c"}, true, "gke"},
		{"aks", map[string]string{"AKS_CLUSTER_NAME": "c"}, true, "aks"},
		{"aks_sub", map[string]string{"AZURE_SUBSCRIPTION_ID": "s"}, true, "aks"},
		{"ack", map[string]string{"ALIBABA_CLOUD_ACCESS_KEY_ID": "k"}, true, "ack"},
		{"ack_cluster", map[string]string{"ACK_CLUSTER_ID": "c"}, true, "ack"},
		{"cce", map[string]string{"HUAWEICLOUD_SDK_TYPE": "t"}, true, "cce"},
		{"cce_cluster", map[string]string{"CCE_CLUSTER_ID": "c"}, true, "cce"},
		{"openshift", map[string]string{"OPENSHIFT_BUILD_NAMESPACE": "n"}, true, "openshift"},
		{"openshift_dep", map[string]string{"OPENSHIFT_DEPLOYMENT_NAME": "d"}, true, "openshift"},
		{"okd", map[string]string{"OKD_CLUSTER": "c"}, true, "okd"},
		{"rancher_agent", map[string]string{"CATTLE_CLUSTER_AGENT_PORT": "5"}, true, "rancher"},
		{"rancher_server", map[string]string{"CATTLE_SERVER": "s"}, true, "rancher"},
		{"minikube", map[string]string{"MINIKUBE_ACTIVE_DOCKERD": "d"}, true, "minikube"},
		{"minikube_home", map[string]string{"MINIKUBE_HOME": "/h"}, true, "minikube"},
		{"kind", map[string]string{"KIND_CLUSTER_NAME": "c"}, true, "kind"},
		{"kubesphere", map[string]string{"KUBESPHERE_NAMESPACE": "n"}, true, "kubesphere"},
		{"self_managed", map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, true, "self-managed"},
	}

	// Ensure a clean environment for higher-priority vars so lower-priority
	// branches are actually reached.
	clearVars := []string{
		"AWS_REGION", "EKS_CLUSTER_NAME", "GOOGLE_CLOUD_PROJECT", "GKE_CLUSTER_NAME",
		"AKS_CLUSTER_NAME", "AZURE_SUBSCRIPTION_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID",
		"ACK_CLUSTER_ID", "HUAWEICLOUD_SDK_TYPE", "CCE_CLUSTER_ID",
		"OPENSHIFT_BUILD_NAMESPACE", "OPENSHIFT_DEPLOYMENT_NAME", "OKD_CLUSTER",
		"CATTLE_CLUSTER_AGENT_PORT", "CATTLE_SERVER", "MINIKUBE_ACTIVE_DOCKERD",
		"MINIKUBE_HOME", "KIND_CLUSTER_NAME", "KUBESPHERE_NAMESPACE",
		"KUBERNETES_SERVICE_HOST", "TELEMETRYFLOW_HOST_ROOT",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range clearVars {
				t.Setenv(v, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			gotK8s, gotProv := system.DetectK8sProviderExported()
			if gotK8s != tc.wantK8s || gotProv != tc.wantProv {
				t.Errorf("DetectK8sProvider = (%v, %q), want (%v, %q)",
					gotK8s, gotProv, tc.wantK8s, tc.wantProv)
			}
		})
	}
}

// TestDetectK8sProviderNone verifies the negative path with all env vars cleared.
func TestDetectK8sProviderNone(t *testing.T) {
	clearVars := []string{
		"AWS_REGION", "EKS_CLUSTER_NAME", "GOOGLE_CLOUD_PROJECT", "GKE_CLUSTER_NAME",
		"AKS_CLUSTER_NAME", "AZURE_SUBSCRIPTION_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID",
		"ACK_CLUSTER_ID", "HUAWEICLOUD_SDK_TYPE", "CCE_CLUSTER_ID",
		"OPENSHIFT_BUILD_NAMESPACE", "OPENSHIFT_DEPLOYMENT_NAME", "OKD_CLUSTER",
		"CATTLE_CLUSTER_AGENT_PORT", "CATTLE_SERVER", "MINIKUBE_ACTIVE_DOCKERD",
		"MINIKUBE_HOME", "KIND_CLUSTER_NAME", "KUBESPHERE_NAMESPACE",
		"KUBERNETES_SERVICE_HOST", "TELEMETRYFLOW_HOST_ROOT",
	}
	for _, v := range clearVars {
		t.Setenv(v, "")
	}
	if k8s, prov := system.DetectK8sProviderExported(); k8s || prov != "" {
		t.Errorf("expected (false, \"\"), got (%v, %q)", k8s, prov)
	}
}

// TestContainerDetection covers detectContainer, getContainerID and
// detectContainerRuntime. Results depend on the host, so we assert only that
// the functions run and return consistent types.
func TestContainerDetection(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	_ = system.DetectContainerExported()
	_ = system.GetContainerIDExported()
	_ = system.DetectContainerRuntimeExported()

	// Force the Kubernetes env branch of both detectors.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if !system.DetectContainerExported() {
		t.Error("expected container detection true with KUBERNETES_SERVICE_HOST set")
	}
	if rt := system.DetectContainerRuntimeExported(); rt != "kubernetes" && rt != "docker" && rt != "containerd" && rt != "cri-o" {
		// On a plain host with the env var set, runtime resolves to kubernetes.
		if rt != "kubernetes" {
			t.Errorf("unexpected runtime %q", rt)
		}
	}
}

// TestDetectVirtualization exercises detectVirtualization on the host.
func TestDetectVirtualization(t *testing.T) {
	isVM, typ := system.DetectVirtualizationExported()
	if !isVM && typ != "" {
		t.Errorf("inconsistent result: isVM=%v type=%q", isVM, typ)
	}
}

// TestContainerNameAndImage covers the env-var-driven metadata helpers.
func TestContainerNameAndImage(t *testing.T) {
	envs := []string{
		"CONTAINER_NAME", "COMPOSE_PROJECT_NAME", "COMPOSE_SERVICE", "POD_NAME",
		"DOCKER_CONTAINER_NAME", "CONTAINER_IMAGE", "POD_IMAGE", "DOCKER_IMAGE",
	}
	for _, e := range envs {
		t.Setenv(e, "")
	}

	if got := system.GetContainerNameExported(); got != "" {
		t.Errorf("expected empty name, got %q", got)
	}

	t.Setenv("CONTAINER_NAME", "my-container")
	if got := system.GetContainerNameExported(); got != "my-container" {
		t.Errorf("CONTAINER_NAME: got %q", got)
	}
	t.Setenv("CONTAINER_NAME", "")
	t.Setenv("COMPOSE_PROJECT_NAME", "proj")
	t.Setenv("COMPOSE_SERVICE", "svc")
	if got := system.GetContainerNameExported(); got != "proj_svc" {
		t.Errorf("compose: got %q", got)
	}
	t.Setenv("COMPOSE_PROJECT_NAME", "")
	t.Setenv("COMPOSE_SERVICE", "")
	t.Setenv("POD_NAME", "pod-1")
	if got := system.GetContainerNameExported(); got != "pod-1" {
		t.Errorf("POD_NAME: got %q", got)
	}
	t.Setenv("POD_NAME", "")
	t.Setenv("DOCKER_CONTAINER_NAME", "dname")
	if got := system.GetContainerNameExported(); got != "dname" {
		t.Errorf("DOCKER_CONTAINER_NAME: got %q", got)
	}

	// Image helper.
	if got := system.GetContainerImageExported(); got != "" {
		t.Errorf("expected empty image, got %q", got)
	}
	t.Setenv("CONTAINER_IMAGE", "img:1")
	if got := system.GetContainerImageExported(); got != "img:1" {
		t.Errorf("CONTAINER_IMAGE: got %q", got)
	}
	t.Setenv("CONTAINER_IMAGE", "")
	t.Setenv("POD_IMAGE", "img:2")
	if got := system.GetContainerImageExported(); got != "img:2" {
		t.Errorf("POD_IMAGE: got %q", got)
	}
	t.Setenv("POD_IMAGE", "")
	t.Setenv("DOCKER_IMAGE", "img:3")
	if got := system.GetContainerImageExported(); got != "img:3" {
		t.Errorf("DOCKER_IMAGE: got %q", got)
	}
}
