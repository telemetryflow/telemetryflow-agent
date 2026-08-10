// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
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
package kubernetes

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	gatewayv "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

// newClientset creates a Kubernetes clientset from config.
// It tries in-cluster config first, then falls back to kubeconfig.
func newClientset(kubeconfig, context string) (kubernetes.Interface, error) {
	cfg, err := buildRESTConfig(kubeconfig, context)
	if err != nil {
		return nil, fmt.Errorf("build REST config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %w", err)
	}
	return cs, nil
}

// newMetricsClientset creates a metrics-server clientset.
func newMetricsClientset(kubeconfig, context string) (metricsv.Interface, error) {
	cfg, err := buildRESTConfig(kubeconfig, context)
	if err != nil {
		return nil, fmt.Errorf("build REST config: %w", err)
	}
	mc, err := metricsv.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create metrics clientset: %w", err)
	}
	return mc, nil
}

// newGatewayClientset creates a Gateway API (gateway.networking.k8s.io)
// versioned clientset from the same REST config as the core clientset.
// The Gateway API CRDs are optional; callers must graceful-degrade when the
// group/version is absent from the target cluster.
func newGatewayClientset(kubeconfig, context string) (gatewayv.Interface, error) {
	cfg, err := buildRESTConfig(kubeconfig, context)
	if err != nil {
		return nil, fmt.Errorf("build REST config: %w", err)
	}
	gc, err := gatewayv.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create gateway-api clientset: %w", err)
	}
	return gc, nil
}

// buildRESTConfig returns a *rest.Config using in-cluster or kubeconfig.
func buildRESTConfig(kubeconfig, context string) (*rest.Config, error) {
	// 1. Explicit kubeconfig path
	if kubeconfig != "" {
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{CurrentContext: context},
		).ClientConfig()
	}

	// 2. KUBECONFIG env var
	if envPath := os.Getenv("KUBECONFIG"); envPath != "" {
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: envPath},
			&clientcmd.ConfigOverrides{CurrentContext: context},
		).ClientConfig()
	}

	// 3. In-cluster config (ServiceAccount token)
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}

	// 4. Default kubeconfig (~/.kube/config)
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: context},
	).ClientConfig()
}
