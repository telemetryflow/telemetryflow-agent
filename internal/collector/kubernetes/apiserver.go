// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
	"fmt"
	"io"
	"math"
	"strings"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

// collectApiServerMetrics scrapes the kube-apiserver /metrics endpoint via the
// Kubernetes API proxy and returns aggregated ApiServerMetrics for the sync payload.
func collectApiServerMetrics(
	ctx context.Context,
	cs kubernetes.Interface,
	logger *zap.Logger,
) (*ApiServerMetrics, error) {
	// Use the Kubernetes API proxy to reach the apiserver's own metrics.
	// GET /api/v1/nodes/<master>/proxy/metrics won't work for apiserver;
	// instead, the metrics are served at /metrics on the apiserver itself,
	// accessible via the RESTClient.
	result := cs.CoreV1().RESTClient().Get().
		AbsPath("/metrics").
		SetHeader("Accept", "text/plain").
		Do(ctx)

	raw, err := result.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to scrape apiserver /metrics: %w", err)
	}

	return parseApiServerMetrics(string(raw), logger), nil
}

// parseApiServerMetrics parses Prometheus text exposition format from kube-apiserver
// and extracts the metrics that the TFO backend expects.
func parseApiServerMetrics(body string, logger *zap.Logger) *ApiServerMetrics {
	metrics := &ApiServerMetrics{
		HealthStatus:   1, // If we can scrape, it's healthy
		RequestsByCode: make(map[string]float64),
		RequestsByVerb: make(map[string]float64),
	}

	// Aggregation accumulators
	var totalRequests float64
	var totalErrors float64
	var latencySumMs float64
	var latencyCount float64
	instanceCPU := make(map[string]float64)
	instanceMem := make(map[string]float64)
	instanceWQ := make(map[string]float64)

	reader := strings.NewReader(body)
	buf := make([]byte, 0, 1024*1024)
	scanner := newLineScanner(reader, buf)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		switch {
		// apiserver_request_total{code="200",verb="GET",...} 12345
		case strings.HasPrefix(line, "apiserver_request_total{"):
			labels, value := parsePromLine(line)
			if value == 0 {
				continue
			}
			code := labels["code"]
			verb := labels["verb"]

			if code != "" {
				metrics.RequestsByCode[code] += value
			}
			if verb != "" {
				metrics.RequestsByVerb[verb] += value
			}
			totalRequests += value

			// Count 5xx as errors
			if len(code) > 0 && code[0] == '5' {
				totalErrors += value
			}

		// apiserver_request_duration_seconds_sum{verb="GET",...} 123.456
		case strings.HasPrefix(line, "apiserver_request_duration_seconds_sum{"):
			_, value := parsePromLine(line)
			latencySumMs += value * 1000 // seconds → milliseconds

		// apiserver_request_duration_seconds_count{verb="GET",...} 12345
		case strings.HasPrefix(line, "apiserver_request_duration_seconds_count{"):
			_, value := parsePromLine(line)
			latencyCount += value

		// process_cpu_seconds_total 123.456
		case strings.HasPrefix(line, "process_cpu_seconds_total"):
			labels, value := parsePromLine(line)
			instance := labels["instance"]
			if instance == "" {
				instance = "apiserver"
			}
			instanceCPU[instance] = value

		// process_resident_memory_bytes 123456789
		case strings.HasPrefix(line, "process_resident_memory_bytes"):
			labels, value := parsePromLine(line)
			instance := labels["instance"]
			if instance == "" {
				instance = "apiserver"
			}
			instanceMem[instance] = value

		// workqueue_depth{name="..."} 5
		case strings.HasPrefix(line, "workqueue_depth{"):
			labels, value := parsePromLine(line)
			instance := labels["instance"]
			if instance == "" {
				instance = "apiserver"
			}
			instanceWQ[instance] += value
		}
	}

	// Build per-instance metrics (merge all instance keys)
	allInstances := make(map[string]bool)
	for k := range instanceCPU {
		allInstances[k] = true
	}
	for k := range instanceMem {
		allInstances[k] = true
	}
	// If no instance-level data, create a single "apiserver" entry
	if len(allInstances) == 0 {
		allInstances["apiserver"] = true
	}

	var avgLatencyMs float64
	if latencyCount > 0 {
		avgLatencyMs = latencySumMs / latencyCount
	}

	var errorRate float64
	if totalRequests > 0 {
		errorRate = (totalErrors / totalRequests) * 100
	}

	for inst := range allInstances {
		metrics.Instances = append(metrics.Instances, ApiServerInstanceMetrics{
			Instance:       inst,
			RequestsPerSec: totalRequests, // snapshot count — rate computed backend-side
			AvgLatencyMs:   math.Round(avgLatencyMs*100) / 100,
			ErrorRate:      math.Round(errorRate*100) / 100,
			CPUUsage:       instanceCPU[inst],
			MemoryUsage:    instanceMem[inst],
			WorkQueueDepth: instanceWQ[inst],
		})
	}

	logger.Debug("Parsed API server metrics",
		zap.Int("requestsByCode", len(metrics.RequestsByCode)),
		zap.Int("requestsByVerb", len(metrics.RequestsByVerb)),
		zap.Int("instances", len(metrics.Instances)),
		zap.Float64("totalRequests", totalRequests),
	)

	return metrics
}

// lineScanner wraps a strings.Reader for line-by-line scanning.
type lineScanner struct {
	reader *strings.Reader
	buf    []byte
	text   string
}

func newLineScanner(r *strings.Reader, buf []byte) *lineScanner {
	return &lineScanner{reader: r, buf: buf[:0]}
}

func (s *lineScanner) Scan() bool {
	s.buf = s.buf[:0]
	for {
		b, err := s.reader.ReadByte()
		if err == io.EOF {
			if len(s.buf) > 0 {
				s.text = string(s.buf)
				return true
			}
			return false
		}
		if err != nil {
			return false
		}
		if b == '\n' {
			s.text = string(s.buf)
			return true
		}
		s.buf = append(s.buf, b)
	}
}

func (s *lineScanner) Text() string {
	return s.text
}

// parsePromLine extracts label key-value pairs and the float value from a
// Prometheus text line like: metric_name{key="val",key2="val2"} 123.45
func parsePromLine(line string) (map[string]string, float64) {
	labels := make(map[string]string)

	// Find the labels section between { and }
	braceOpen := strings.IndexByte(line, '{')
	braceClose := strings.LastIndexByte(line, '}')

	var valuePart string
	if braceOpen >= 0 && braceClose > braceOpen {
		labelStr := line[braceOpen+1 : braceClose]
		valuePart = strings.TrimSpace(line[braceClose+1:])

		// Parse label pairs: key="value",key2="value2"
		for labelStr != "" {
			eqIdx := strings.IndexByte(labelStr, '=')
			if eqIdx < 0 {
				break
			}
			key := labelStr[:eqIdx]
			labelStr = labelStr[eqIdx+1:]

			if len(labelStr) == 0 || labelStr[0] != '"' {
				break
			}
			labelStr = labelStr[1:] // skip opening quote
			closeQuote := strings.IndexByte(labelStr, '"')
			if closeQuote < 0 {
				break
			}
			val := labelStr[:closeQuote]
			labels[key] = val
			labelStr = labelStr[closeQuote+1:]
			if len(labelStr) > 0 && labelStr[0] == ',' {
				labelStr = labelStr[1:]
			}
		}
	} else {
		// No labels — metric_name value
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			valuePart = parts[len(parts)-1]
		}
	}

	var value float64
	if valuePart != "" {
		_, _ = fmt.Sscanf(valuePart, "%f", &value)
	}

	return labels, value
}
