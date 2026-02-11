package kubernetes

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
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
