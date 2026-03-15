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

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// collectCoreDNSMetrics scrapes CoreDNS /metrics endpoint and returns aggregated
// CoreDNSMetrics for the sync payload.
func collectCoreDNSMetrics(
	ctx context.Context,
	cs kubernetes.Interface,
	coreDNSService string,
	logger *zap.Logger,
) (*CoreDNSMetrics, error) {
	if coreDNSService == "" {
		coreDNSService = "coredns.kube-system.svc.cluster.local:9153"
	}

	// Try scraping via the Kubernetes API proxy first (works from outside the cluster too).
	// GET /api/v1/namespaces/kube-system/services/kube-dns:metrics/proxy/metrics
	body, err := scrapeCoreDNSViaProxy(ctx, cs)
	if err != nil {
		logger.Debug("CoreDNS proxy scrape failed, trying direct HTTP", zap.Error(err))
		// Fall back to direct HTTP scrape (works from inside the cluster)
		body, err = scrapeCoreDNSDirectly(ctx, coreDNSService)
		if err != nil {
			return nil, fmt.Errorf("failed to scrape CoreDNS metrics: %w", err)
		}
	}

	// Count CoreDNS pods
	podCount := countCoreDNSPods(ctx, cs, logger)

	return parseCoreDNSMetrics(body, podCount, logger), nil
}

// scrapeCoreDNSViaProxy uses the Kubernetes API server proxy to reach CoreDNS metrics.
func scrapeCoreDNSViaProxy(ctx context.Context, cs kubernetes.Interface) (string, error) {
	result := cs.CoreV1().RESTClient().Get().
		Namespace("kube-system").
		Resource("services").
		Name("kube-dns:metrics").
		SubResource("proxy", "metrics").
		SetHeader("Accept", "text/plain").
		Do(ctx)

	raw, err := result.Raw()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// scrapeCoreDNSDirectly fetches CoreDNS /metrics via direct HTTP.
func scrapeCoreDNSDirectly(ctx context.Context, service string) (string, error) {
	url := fmt.Sprintf("http://%s/metrics", service)
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("CoreDNS metrics returned status %d", resp.StatusCode)
	}

	buf := make([]byte, 0, 512*1024)
	for {
		tmp := make([]byte, 32*1024)
		n, readErr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	return string(buf), nil
}

// countCoreDNSPods counts the number of running CoreDNS pods in kube-system.
func countCoreDNSPods(ctx context.Context, cs kubernetes.Interface, logger *zap.Logger) int {
	pods, err := cs.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=kube-dns",
	})
	if err != nil {
		logger.Debug("Failed to count CoreDNS pods", zap.Error(err))
		return 0
	}
	count := 0
	for _, p := range pods.Items {
		if p.Status.Phase == "Running" {
			count++
		}
	}
	return count
}

// parseCoreDNSMetrics parses Prometheus text exposition format from CoreDNS
// and extracts the metrics that the TFO backend expects.
func parseCoreDNSMetrics(body string, podCount int, logger *zap.Logger) *CoreDNSMetrics {
	metrics := &CoreDNSMetrics{
		HealthStatus:    1, // If we can scrape, it's healthy
		PodCount:        podCount,
		RequestsByRcode: make(map[string]float64),
	}

	var totalRequests float64
	var totalErrors float64
	var cacheHits float64
	var cacheMisses float64
	var durationSumMs float64
	var durationCount float64
	var upstreamRequests float64
	var cpuSeconds float64
	var memBytes float64

	reader := strings.NewReader(body)
	buf := make([]byte, 0, 1024*1024)
	scanner := newLineScanner(reader, buf)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		switch {
		// coredns_dns_requests_total{server="dns://:53",zone=".",proto="udp",family="1",type="A"} 1234
		case strings.HasPrefix(line, "coredns_dns_requests_total{"):
			_, value := parsePromLine(line)
			totalRequests += value

		// coredns_dns_responses_total{server="dns://:53",zone=".",rcode="NOERROR",plugin="."} 1200
		case strings.HasPrefix(line, "coredns_dns_responses_total{"):
			labels, value := parsePromLine(line)
			rcode := labels["rcode"]
			if rcode != "" {
				metrics.RequestsByRcode[rcode] += value
			}
			// Count SERVFAIL and REFUSED as errors
			if rcode == "SERVFAIL" || rcode == "REFUSED" {
				totalErrors += value
			}

		// coredns_dns_request_duration_seconds_sum{...} 12.345
		case strings.HasPrefix(line, "coredns_dns_request_duration_seconds_sum{"):
			_, value := parsePromLine(line)
			durationSumMs += value * 1000

		// coredns_dns_request_duration_seconds_count{...} 12345
		case strings.HasPrefix(line, "coredns_dns_request_duration_seconds_count{"):
			_, value := parsePromLine(line)
			durationCount += value

		// coredns_cache_hits_total{server="dns://:53",type="success"} 500
		case strings.HasPrefix(line, "coredns_cache_hits_total{"):
			_, value := parsePromLine(line)
			cacheHits += value

		// coredns_cache_misses_total{server="dns://:53"} 100
		case strings.HasPrefix(line, "coredns_cache_misses_total{"):
			_, value := parsePromLine(line)
			cacheMisses += value

		// coredns_forward_requests_total{to="10.96.0.10:53"} 234
		case strings.HasPrefix(line, "coredns_forward_requests_total{"):
			_, value := parsePromLine(line)
			upstreamRequests += value

		// process_cpu_seconds_total 123.456
		case strings.HasPrefix(line, "process_cpu_seconds_total"):
			_, value := parsePromLine(line)
			cpuSeconds = value

		// process_resident_memory_bytes 123456789
		case strings.HasPrefix(line, "process_resident_memory_bytes"):
			_, value := parsePromLine(line)
			memBytes = value
		}
	}

	// Compute derived metrics
	metrics.RequestsPerSec = totalRequests // snapshot count — rate computed backend-side

	if cacheHits+cacheMisses > 0 {
		metrics.CacheHitRatePercent = math.Round((cacheHits/(cacheHits+cacheMisses))*10000) / 100
	}

	if durationCount > 0 {
		metrics.AvgDurationMs = math.Round((durationSumMs/durationCount)*100) / 100
	}

	if totalRequests > 0 {
		metrics.ErrorRate = math.Round((totalErrors/totalRequests)*10000) / 100
	}

	metrics.UpstreamRequestsPerSec = upstreamRequests
	metrics.CPUUsage = cpuSeconds
	metrics.MemoryUsage = memBytes

	logger.Debug("Parsed CoreDNS metrics",
		zap.Float64("totalRequests", totalRequests),
		zap.Float64("cacheHitRate", metrics.CacheHitRatePercent),
		zap.Float64("avgDurationMs", metrics.AvgDurationMs),
		zap.Int("podCount", podCount),
		zap.Int("rcodes", len(metrics.RequestsByRcode)),
	)

	return metrics
}
