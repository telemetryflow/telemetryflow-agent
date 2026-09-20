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
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// podNetworkCounter tracks the previous cumulative rx+tx byte total and the
// timestamp at which it was recorded. It is used to compute a per-second rate
// between consecutive kubelet summary scrapes.
type podNetworkCounter struct {
	totalBytes uint64
	ts         time.Time
}

// collectPodDiskNetwork fetches per-pod ephemeral-storage and network I/O
// metrics from the kubelet /stats/summary endpoint and emits three metric names:
//
//   - k8s.pod.ephemeral_storage.used     (gauge, bytes)  — sum of container rootfs+logs
//   - k8s.pod.ephemeral_storage.capacity (gauge, bytes)  — node-level fs capacity (best available proxy)
//   - k8s.pod.network.io                 (gauge, bytes/s) — rx+tx rate, delta between scrapes
//
// counters is mutated in place: previous byte totals and timestamps are updated
// on every successful scrape so the next call can compute the rate.
// On the first scrape for a pod the network.io metric is suppressed (no delta yet).
func collectPodDiskNetwork(
	ctx context.Context,
	fetcher KubeletProxyFunc,
	nodeNames []string,
	cluster string,
	cfg Config,
	logger *zap.Logger,
	counters map[string]*podNetworkCounter,
	now time.Time,
) []collector.Metric {
	if fetcher == nil {
		return nil
	}

	var metrics []collector.Metric

	for _, nodeName := range nodeNames {
		summary, err := fetcher(ctx, nodeName)
		if err != nil {
			logger.Warn("pod_disk_network: failed to fetch kubelet stats",
				zap.String("node", nodeName), zap.Error(err))
			continue
		}

		// Node-level filesystem capacity — used as the capacity proxy for pods on
		// this node. The kubelet summary does not expose per-pod ephemeral storage
		// capacity; node fs.capacityBytes is the only available upper bound.
		var nodeCapacityBytes *uint64
		if summary.Node.Fs != nil && summary.Node.Fs.CapacityBytes != nil {
			nodeCapacityBytes = summary.Node.Fs.CapacityBytes
		}

		for _, pod := range summary.Pods {
			ns := pod.PodRef.Namespace
			if !cfg.shouldCollectNamespace(ns) {
				continue
			}

			podLabels := map[string]string{
				"cluster":   cluster,
				"namespace": ns,
				"pod":       pod.PodRef.Name,
			}

			// ── Ephemeral storage used ────────────────────────────────────────
			// Sum rootfs.usedBytes + logs.usedBytes across all containers in the
			// pod. This mirrors the kubelet's own ephemeral-storage eviction
			// accounting and is the value the metrics server would surface as
			// pod-level ephemeral storage usage.
			var totalEphemeralUsed uint64
			for _, c := range pod.Containers {
				if c.Rootfs != nil && c.Rootfs.UsedBytes != nil {
					totalEphemeralUsed += *c.Rootfs.UsedBytes
				}
				if c.Logs != nil && c.Logs.UsedBytes != nil {
					totalEphemeralUsed += *c.Logs.UsedBytes
				}
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.pod.ephemeral_storage.used", float64(totalEphemeralUsed), collector.MetricTypeGauge).
					WithLabels(podLabels).WithUnit("By").
					WithDescription("Pod ephemeral storage used bytes (sum of container rootfs + logs from kubelet /stats/summary)"),
			)

			// ── Ephemeral storage capacity ────────────────────────────────────
			// No per-pod capacity is surfaced by the kubelet summary. The node
			// filesystem capacity is the best available proxy; it is emitted
			// with an explicit note so consumers can interpret it correctly.
			if nodeCapacityBytes != nil {
				metrics = append(metrics,
					collector.NewMetric("k8s.pod.ephemeral_storage.capacity", float64(*nodeCapacityBytes), collector.MetricTypeGauge).
						WithLabels(podLabels).WithUnit("By").
						WithDescription("Pod ephemeral storage capacity (node fs.capacityBytes proxy — per-pod capacity unavailable in kubelet summary)"),
				)
			}

			// ── Network I/O rate ──────────────────────────────────────────────
			// Sum cumulative rx+tx bytes across all network interfaces. Compare
			// with the previous scrape to derive a bytes/sec rate. On the very
			// first observation for a pod, record the baseline and skip emission
			// to avoid a bogus spike from a large initial counter value.
			if pod.Network == nil {
				continue
			}
			var totalRx, totalTx uint64
			for _, iface := range pod.Network.Interfaces {
				if iface.RxBytes != nil {
					totalRx += *iface.RxBytes
				}
				if iface.TxBytes != nil {
					totalTx += *iface.TxBytes
				}
			}
			currentTotal := totalRx + totalTx
			podKey := ns + "/" + pod.PodRef.Name

			if prev, ok := counters[podKey]; ok {
				elapsed := now.Sub(prev.ts).Seconds()
				if elapsed > 0 && currentTotal >= prev.totalBytes {
					delta := currentTotal - prev.totalBytes
					rate := float64(delta) / elapsed
					metrics = append(metrics,
						collector.NewMetric("k8s.pod.network.io", rate, collector.MetricTypeGauge).
							WithLabels(podLabels).WithUnit("By/s").
							WithDescription("Pod network throughput bytes/sec (rx+tx rate, delta between kubelet summary scrapes)"),
					)
				}
			}
			// Update (or create) the baseline for the next scrape.
			counters[podKey] = &podNetworkCounter{totalBytes: currentTotal, ts: now}
		}
	}

	return metrics
}
