// Package kubernetes exports internal functions for testing.
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
	"context"
	"io"
	"net/http"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ParseQuantityStringExported exposes parseQuantityString for testing.
func ParseQuantityStringExported(s string) float64 { return parseQuantityString(s) }

// ParseQuantityStringBytesExported exposes parseQuantityStringBytes for testing.
func ParseQuantityStringBytesExported(s string) float64 { return parseQuantityStringBytes(s) }

// ParseQuantityStringValueExported exposes parseQuantityStringValue for testing.
func ParseQuantityStringValueExported(s string) float64 { return parseQuantityStringValue(s) }

// ExtractProbeExported exposes extractProbe for testing.
func ExtractProbeExported(probe *corev1.Probe) *ProbeState { return extractProbe(probe) }

// ParseApiServerMetricsExported exposes parseApiServerMetrics for testing.
func ParseApiServerMetricsExported(body string, logger *zap.Logger) *ApiServerMetrics {
	return parseApiServerMetrics(body, logger)
}

// ParseCoreDNSMetricsExported exposes parseCoreDNSMetrics for testing.
func ParseCoreDNSMetricsExported(body string, podCount int, logger *zap.Logger) *CoreDNSMetrics {
	return parseCoreDNSMetrics(body, podCount, logger)
}

// ParsePromLineExported exposes parsePromLine for testing.
func ParsePromLineExported(line string) (map[string]string, float64) {
	return parsePromLine(line)
}

// ConvertKubeletSummaryExported exposes convertKubeletSummary for testing.
func ConvertKubeletSummaryExported(summary *KubeletDirectSummary, cluster, nodeName string) []collector.Metric {
	return convertKubeletSummary(summary, cluster, nodeName)
}

// ParseCPUThrottleMetricsExported exposes parseCPUThrottleMetrics for testing.
// The returned map is keyed by "namespace/pod/container" for easy assertions.
func ParseCPUThrottleMetricsExported(data []byte, logger *zap.Logger) map[string]float64 {
	out := make(map[string]float64)
	for k, v := range parseCPUThrottleMetrics(data, logger) {
		out[k.namespace+"/"+k.pod+"/"+k.container] = v
	}
	return out
}

// ReadLinesExported exposes readLines for testing.
func ReadLinesExported(r io.Reader, maxLines int64) []string {
	return readLines(r, maxLines)
}

// BuildRESTConfigExported exposes buildRESTConfig for testing.
func BuildRESTConfigExported(kubeconfig, kubeContext string) error {
	_, err := buildRESTConfig(kubeconfig, kubeContext)
	return err
}

// NewClientsetExported exposes newClientset for testing.
func NewClientsetExported(kubeconfig, kubeContext string) error {
	_, err := newClientset(kubeconfig, kubeContext)
	return err
}

// NewMetricsClientsetExported exposes newMetricsClientset for testing.
func NewMetricsClientsetExported(kubeconfig, kubeContext string) error {
	_, err := newMetricsClientset(kubeconfig, kubeContext)
	return err
}

// DetectClusterNameExported exposes detectClusterName for testing.
func DetectClusterNameExported() string { return detectClusterName() }

// DetectClusterProviderExported exposes detectClusterProvider for testing.
func DetectClusterProviderExported() string { return detectClusterProvider() }

// CollectApiServerMetricsExported exposes collectApiServerMetrics for testing.
func CollectApiServerMetricsExported(ctx context.Context, cs kubernetes.Interface, logger *zap.Logger) (*ApiServerMetrics, error) {
	return collectApiServerMetrics(ctx, cs, logger)
}

// CollectCoreDNSMetricsExported exposes collectCoreDNSMetrics for testing.
func CollectCoreDNSMetricsExported(ctx context.Context, cs kubernetes.Interface, service string, logger *zap.Logger) (*CoreDNSMetrics, error) {
	return collectCoreDNSMetrics(ctx, cs, service, logger)
}

// CollectNodeLogsExported exposes collectNodeLogs for testing.
func CollectNodeLogsExported(ctx context.Context, cs kubernetes.Interface, cfg config.KubernetesCollectorConfig, logger *zap.Logger) ([]NodeLogEntry, error) {
	return collectNodeLogs(ctx, cs, NewConfig(cfg), logger)
}

// SetCAdvisorFetcher replaces the cAdvisor proxy fetcher (used in tests).
func (k *KubernetesCollector) SetCAdvisorFetcher(f CAdvisorProxyFunc) {
	k.cadvisorFetcher = f
}

// NewKubeletHTTPFetcherForTest builds a KubeletHTTPFetcher pointed at a test
// server: it injects a custom HTTP client, port, and token/CA file paths so the
// production FetchNodeStats path can be exercised against httptest.
func NewKubeletHTTPFetcherForTest(client *http.Client, port int, tokenPath, caPath string) *KubeletHTTPFetcher {
	return &KubeletHTTPFetcher{
		client:    client,
		port:      port,
		tokenPath: tokenPath,
		caPath:    caPath,
	}
}
