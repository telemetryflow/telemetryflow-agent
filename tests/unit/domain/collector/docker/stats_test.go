// Package docker_test contains unit tests for the corresponding collector module.
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

package docker_test

import (
	"testing"

	containertypes "github.com/moby/moby/api/types/container"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/docker"
)

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func newTestStatsResponse() containertypes.StatsResponse {
	return containertypes.StatsResponse{
		CPUStats: containertypes.CPUStats{
			CPUUsage: containertypes.CPUUsage{
				TotalUsage:        2000000000,
				PercpuUsage:       []uint64{500000000, 500000000, 500000000, 500000000},
				UsageInUsermode:   1500000000,
				UsageInKernelmode: 500000000,
			},
			SystemUsage: 10000000000,
			OnlineCPUs:  4,
			ThrottlingData: containertypes.ThrottlingData{
				ThrottledPeriods: 10,
				ThrottledTime:    50000000,
			},
		},
		PreCPUStats: containertypes.CPUStats{
			CPUUsage: containertypes.CPUUsage{
				TotalUsage: 1000000000,
			},
			SystemUsage: 8000000000,
		},
		MemoryStats: containertypes.MemoryStats{
			Usage:    536870912,
			MaxUsage: 600000000,
			Limit:    1073741824,
			Stats: map[string]uint64{
				"inactive_file": 100000000,
				"rss":           300000000,
				"cache":         136870912,
			},
		},
		Networks: map[string]containertypes.NetworkStats{
			"eth0": {
				RxBytes:   1000000,
				TxBytes:   2000000,
				RxPackets: 10000,
				TxPackets: 20000,
				RxErrors:  5,
				TxErrors:  3,
				RxDropped: 1,
				TxDropped: 2,
			},
		},
		BlkioStats: containertypes.BlkioStats{
			IoServiceBytesRecursive: []containertypes.BlkioStatEntry{
				{Op: "read", Value: 500000},
				{Op: "write", Value: 300000},
				{Op: "read", Value: 200000},
			},
			IoServicedRecursive: []containertypes.BlkioStatEntry{
				{Op: "read", Value: 100},
				{Op: "write", Value: 50},
			},
		},
		PidsStats: containertypes.PidsStats{Current: 42},
	}
}

func TestCollectCPUMetrics(t *testing.T) {
	stats := newTestStatsResponse()
	labels := map[string]string{"container_name": "web"}
	metrics := docker.CollectCPUMetricsExported(&stats, labels)

	cpuPct := findMetric(metrics, "container.cpu.usage_percent")
	if cpuPct == nil {
		t.Fatal("missing cpu.usage_percent")
	}
	if cpuPct.Value != 200.0 {
		t.Errorf("cpu.usage_percent = %f, want 200.0", cpuPct.Value)
	}

	total := findMetric(metrics, "container.cpu.usage_total")
	if total == nil || total.Value != 2000000000 {
		t.Error("usage_total wrong")
	}
	online := findMetric(metrics, "container.cpu.online_cpus")
	if online == nil || online.Value != 4 {
		t.Error("online_cpus wrong")
	}
	throttled := findMetric(metrics, "container.cpu.throttled_periods")
	if throttled == nil || throttled.Value != 10 {
		t.Error("throttled_periods wrong")
	}
}

func TestCollectMemoryMetrics(t *testing.T) {
	stats := newTestStatsResponse()
	labels := map[string]string{"container_name": "web"}
	metrics := docker.CollectMemoryMetricsExported(&stats, labels)

	usage := findMetric(metrics, "container.memory.usage")
	if usage == nil || usage.Value != 536870912 {
		t.Error("usage wrong")
	}

	workingSet := findMetric(metrics, "container.memory.working_set")
	if workingSet == nil {
		t.Fatal("missing working_set")
	}
	if workingSet.Value != 436870912 {
		t.Errorf("working_set = %f, want 436870912", workingSet.Value)
	}

	usagePct := findMetric(metrics, "container.memory.usage_percent")
	if usagePct == nil {
		t.Fatal("missing usage_percent")
	}
	expected := 436870912.0 / 1073741824.0 * 100.0
	if usagePct.Value < expected-0.1 || usagePct.Value > expected+0.1 {
		t.Errorf("usage_percent = %f, want ~%f", usagePct.Value, expected)
	}

	rss := findMetric(metrics, "container.memory.rss")
	if rss == nil || rss.Value != 300000000 {
		t.Error("rss wrong")
	}
	cache := findMetric(metrics, "container.memory.cache")
	if cache == nil || cache.Value != 136870912 {
		t.Error("cache wrong")
	}
}

func TestCollectNetworkMetrics(t *testing.T) {
	stats := newTestStatsResponse()
	labels := map[string]string{"container_name": "web"}
	metrics := docker.CollectNetworkMetricsExported(&stats, labels)

	if len(metrics) != 8 {
		t.Fatalf("expected 8 metrics, got %d", len(metrics))
	}
	rxBytes := findMetric(metrics, "container.network.rx_bytes")
	if rxBytes == nil || rxBytes.Value != 1000000 {
		t.Error("rx_bytes wrong")
	}
	iface := findMetric(metrics, "container.network.rx_bytes")
	if iface == nil || iface.Labels["interface"] != "eth0" {
		t.Error("interface label wrong")
	}
}

func TestCollectDiskIOMetrics(t *testing.T) {
	stats := newTestStatsResponse()
	labels := map[string]string{"container_name": "web"}
	metrics := docker.CollectDiskIOMetricsExported(&stats, labels)

	readBytes := findMetric(metrics, "container.diskio.read_bytes")
	if readBytes == nil {
		t.Fatal("missing read_bytes")
	}
	if readBytes.Value != 700000 {
		t.Errorf("read_bytes = %f, want 700000", readBytes.Value)
	}
	writeBytes := findMetric(metrics, "container.diskio.write_bytes")
	if writeBytes == nil || writeBytes.Value != 300000 {
		t.Error("write_bytes wrong")
	}
	readOps := findMetric(metrics, "container.diskio.read_ops")
	if readOps == nil || readOps.Value != 100 {
		t.Error("read_ops wrong")
	}
	writeOps := findMetric(metrics, "container.diskio.write_ops")
	if writeOps == nil || writeOps.Value != 50 {
		t.Error("write_ops wrong")
	}
}
