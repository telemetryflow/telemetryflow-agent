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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

const (
	defaultKubeletPort = 10250
	defaultTokenPath   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAPath      = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// KubeletStatsFetcher abstracts the Kubelet /stats/summary HTTP call.
// The interface allows test injection of a mock fetcher.
type KubeletStatsFetcher interface {
	FetchNodeStats(ctx context.Context, nodeIP string) (*KubeletDirectSummary, error)
}

// KubeletHTTPFetcher is the production implementation that connects directly
// to the Kubelet HTTPS endpoint using a ServiceAccount token and cluster CA.
type KubeletHTTPFetcher struct {
	client    *http.Client
	port      int
	tokenPath string
	caPath    string
}

// NewKubeletHTTPFetcher creates a KubeletHTTPFetcher configured with the
// cluster ServiceAccount CA. If insecureSkipVerify is true, TLS verification
// is skipped (useful for development or clusters with self-signed certs).
func NewKubeletHTTPFetcher(insecureSkipVerify bool) (*KubeletHTTPFetcher, error) {
	f := &KubeletHTTPFetcher{
		port:      defaultKubeletPort,
		tokenPath: defaultTokenPath,
		caPath:    defaultCAPath,
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // controlled by config
	}

	if !insecureSkipVerify {
		caData, err := os.ReadFile(f.caPath)
		if err != nil {
			return nil, fmt.Errorf("kubelet fetcher: read CA cert %s: %w", f.caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("kubelet fetcher: failed to parse CA cert from %s", f.caPath)
		}
		tlsCfg.RootCAs = pool
	}

	f.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
	return f, nil
}

// FetchNodeStats calls the Kubelet /stats/summary endpoint on the given nodeIP
// and returns the parsed summary. It authenticates using the ServiceAccount
// bearer token read from tokenPath.
func (f *KubeletHTTPFetcher) FetchNodeStats(ctx context.Context, nodeIP string) (*KubeletDirectSummary, error) {
	token, err := os.ReadFile(f.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("kubelet fetcher: read token %s: %w", f.tokenPath, err)
	}

	url := fmt.Sprintf("https://%s:%d/stats/summary", nodeIP, f.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kubelet fetcher: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubelet fetcher: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubelet fetcher: unexpected status %d from %s", resp.StatusCode, url)
	}

	var summary KubeletDirectSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return nil, fmt.Errorf("kubelet fetcher: decode response: %w", err)
	}
	return &summary, nil
}

// KubeletDirectSummary is a minimal struct matching the /stats/summary JSON
// response used by the direct-access fallback path.
type KubeletDirectSummary struct {
	Node NodeStats  `json:"node"`
	Pods []PodStats `json:"pods"`
}

// NodeStats holds node-level CPU and memory stats from the Kubelet summary.
type NodeStats struct {
	NodeName string    `json:"nodeName"`
	CPU      *CPUStats `json:"cpu"`
	Memory   *MemStats `json:"memory"`
}

// PodStats holds per-pod container stats from the Kubelet summary.
type PodStats struct {
	PodRef     PodReference     `json:"podRef"`
	Containers []ContainerStats `json:"containers"`
}

// PodReference identifies a pod by name and namespace.
type PodReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ContainerStats holds per-container CPU and memory stats.
type ContainerStats struct {
	Name   string    `json:"name"`
	CPU    *CPUStats `json:"cpu"`
	Memory *MemStats `json:"memory"`
}

// CPUStats holds CPU usage in nanocores.
type CPUStats struct {
	UsageNanoCores *uint64 `json:"usageNanoCores"`
}

// MemStats holds memory working set in bytes.
type MemStats struct {
	WorkingSetBytes *uint64 `json:"workingSetBytes"`
}
